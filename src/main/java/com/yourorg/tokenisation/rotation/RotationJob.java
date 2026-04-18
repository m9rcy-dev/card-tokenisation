package com.yourorg.tokenisation.rotation;

import com.yourorg.tokenisation.audit.AuditEventType;
import com.yourorg.tokenisation.audit.AuditLogger;
import com.yourorg.tokenisation.config.RotationProperties;
import com.yourorg.tokenisation.crypto.InMemoryKeyRing;
import com.yourorg.tokenisation.crypto.TamperDetector;
import com.yourorg.tokenisation.domain.KeyStatus;
import com.yourorg.tokenisation.domain.KeyVersion;
import com.yourorg.tokenisation.repository.KeyVersionRepository;
import com.yourorg.tokenisation.repository.TokenVaultRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Scheduled job that drives the key rotation batch re-encryption pipeline.
 *
 * <p>On each invocation, the job checks for any key version in {@code ROTATING} status.
 * If found, it delegates a batch of tokens to {@link RotationBatchProcessor} for DEK
 * re-wrapping. When all tokens have been migrated, the job performs the cutover:
 * the old key is marked {@code RETIRED} and the new key is confirmed as the active
 * ring entry.
 *
 * <h3>Job lifecycle per rotation cycle</h3>
 * <ol>
 *   <li>Find the oldest {@code ROTATING} key version. If none, return immediately.
 *   <li>Find the current {@code ACTIVE} key version (the rotation target).
 *   <li>Delegate a batch to {@link RotationBatchProcessor#processBatch}.
 *   <li>Count remaining tokens on the old key. If zero, call {@link #completeRotation}.
 * </ol>
 *
 * <h3>Cutover ({@code completeRotation})</h3>
 * <ol>
 *   <li>Verify the count is truly zero (guard against race with tokenisation).
 *   <li>Verify integrity of the old key via {@link TamperDetector#assertIntegrity}.
 *   <li>Mark the old key {@code RETIRED} in the database (with updated checksum).
 *   <li>Call {@link InMemoryKeyRing#retire} — the old key stays in the ring for
 *       any detokenisation requests that arrive before the batch count reaches zero.
 *   <li>Write {@code KEY_ROTATION_COMPLETED} audit event.
 * </ol>
 *
 * <p>The scheduler is disabled in the test profile ({@code cron: "-"}) — rotation
 * tests trigger the job logic directly by calling {@code processRotationBatch()}.
 */
@Component
@Slf4j
public class RotationJob {

    private final RotationBatchProcessor batchProcessor;
    private final KeyVersionRepository keyVersionRepository;
    private final TokenVaultRepository tokenVaultRepository;
    private final TamperDetector tamperDetector;
    private final InMemoryKeyRing keyRing;
    private final AuditLogger auditLogger;
    private final RotationProperties rotationProperties;

    /**
     * Constructs the rotation job with all required collaborators.
     *
     * @param batchProcessor       the per-batch re-encryption processor; must not be null
     * @param keyVersionRepository the key version repository; must not be null
     * @param tokenVaultRepository the token vault repository for count queries; must not be null
     * @param tamperDetector       HMAC integrity verifier for cutover check; must not be null
     * @param keyRing              in-memory key ring for ring retirement; must not be null
     * @param auditLogger          audit event writer; must not be null
     * @param rotationProperties   rotation configuration (batch size, cron); must not be null
     */
    public RotationJob(RotationBatchProcessor batchProcessor,
                       KeyVersionRepository keyVersionRepository,
                       TokenVaultRepository tokenVaultRepository,
                       TamperDetector tamperDetector,
                       InMemoryKeyRing keyRing,
                       AuditLogger auditLogger,
                       RotationProperties rotationProperties) {
        this.batchProcessor = batchProcessor;
        this.keyVersionRepository = keyVersionRepository;
        this.tokenVaultRepository = tokenVaultRepository;
        this.tamperDetector = tamperDetector;
        this.keyRing = keyRing;
        this.auditLogger = auditLogger;
        this.rotationProperties = rotationProperties;
    }

    /**
     * Processes one batch of token re-encryption as part of the active rotation cycle.
     *
     * <p>Invoked on the schedule configured by {@code rotation.batch.cron}.
     * The method is a no-op if no key version is currently in {@code ROTATING} status.
     *
     * <p>Spring's {@code @Scheduled} guarantees single-threaded invocation (one thread
     * per trigger), preventing concurrent batch runs on the same JVM. Multi-node
     * deployments using a shared database should add a distributed lock (e.g. via
     * ShedLock) to prevent concurrent processing across nodes.
     */
    @Scheduled(cron = "${rotation.batch.cron}")
    public void processRotationBatch() {
        // Find oldest key version needing migration: ROTATING (scheduled) or COMPROMISED (emergency)
        Optional<KeyVersion> rotatingOpt = keyVersionRepository.findOldestPendingMigration();
        if (rotatingOpt.isEmpty()) {
            log.debug("No ROTATING or COMPROMISED key version found — rotation batch skipped");
            return;
        }

        KeyVersion rotatingKey = rotatingOpt.get();
        UUID oldKeyVersionId = rotatingKey.getId();

        Optional<KeyVersion> activeOpt = keyVersionRepository.findActive();
        if (activeOpt.isEmpty()) {
            log.error("No ACTIVE key version found during rotation batch — cannot determine target key");
            return;
        }

        UUID newKeyVersionId = activeOpt.get().getId();

        if (oldKeyVersionId.equals(newKeyVersionId)) {
            log.error("ROTATING and ACTIVE key versions are the same [{}] — rotation state is inconsistent",
                    oldKeyVersionId);
            return;
        }

        log.info("Rotation batch: re-encrypting tokens from old key [{}] → new key [{}]",
                oldKeyVersionId, newKeyVersionId);

        int batchSize = rotationProperties.getBatch().getSize();
        RotationBatchProcessor.BatchResult result =
                batchProcessor.processBatch(oldKeyVersionId, newKeyVersionId, batchSize);

        log.info("Rotation batch result: processed={}, failed={}, fetched={}",
                result.processedCount(), result.failedCount(), result.totalFetched());

        // Check if all tokens have been migrated (only if the batch was a full page — if partial,
        // it's very likely the remaining count is zero, but always do the authoritative count check)
        long remaining = tokenVaultRepository.countActiveByKeyVersionId(oldKeyVersionId);
        if (remaining == 0) {
            log.info("All tokens migrated from key [{}] — initiating cutover", oldKeyVersionId);
            completeRotation(rotatingKey);
        } else {
            log.info("Rotation in progress: {} token(s) remaining on old key [{}]", remaining, oldKeyVersionId);
        }
    }

    /**
     * Completes the rotation cycle by retiring the old key.
     *
     * <p>This method performs a final zero-count guard before transitioning the key
     * to {@code RETIRED}, protecting against a race where a token is re-tokenised
     * onto the old key after the batch counted zero (extremely unlikely but possible
     * on a ROTATING key that is also still ACTIVE temporarily).
     *
     * @param rotatingKey the key version to retire; must be in {@code ROTATING} status
     */
    @Transactional
    public void completeRotation(KeyVersion rotatingKey) {
        UUID oldKeyVersionId = rotatingKey.getId();

        // Double-check: verify count is truly zero before retirement (prevents premature cutover)
        long remainingDoubleCheck = tokenVaultRepository.countActiveByKeyVersionId(oldKeyVersionId);
        if (remainingDoubleCheck > 0) {
            log.warn("Premature cutover prevented: {} token(s) still on key [{}] — continuing batch",
                    remainingDoubleCheck, oldKeyVersionId);
            return;
        }

        // Verify integrity of the rotating key before retiring it.
        // A failed integrity check means the key record was tampered with — halt rotation
        // and alert rather than silently retiring a potentially compromised key.
        try {
            tamperDetector.assertIntegrity(rotatingKey);
        } catch (Exception integrityException) {
            log.error("CRITICAL: Integrity check failed on retiring key [{}] — rotation halted. " +
                    "Investigate key tampering before retrying: {}", oldKeyVersionId, integrityException.getMessage());
            auditLogger.logKeyEvent(
                    AuditEventType.TAMPER_ALERT,
                    oldKeyVersionId,
                    "FAILURE",
                    "Integrity check failed on retiring key during rotation: " + integrityException.getMessage(),
                    null);
            return;
        }

        // Transition to RETIRED in DB
        rotatingKey.markRetired(Instant.now(), "pending");
        keyVersionRepository.save(rotatingKey);
        rotatingKey.initializeChecksum(tamperDetector.computeChecksum(rotatingKey));
        keyVersionRepository.save(rotatingKey);

        // Mark retired in ring (key stays available for any in-flight detokenisation requests)
        keyRing.retire(oldKeyVersionId.toString());

        auditLogger.logKeyEvent(
                AuditEventType.KEY_ROTATION_COMPLETED,
                oldKeyVersionId,
                "SUCCESS",
                null,
                null);

        log.info("Key rotation complete: key [{}] retired successfully", oldKeyVersionId);
    }
}
