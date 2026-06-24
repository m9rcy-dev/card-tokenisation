package com.yourorg.tokenisation.rotation;

import com.yourorg.tokenisation.audit.AuditEventType;
import com.yourorg.tokenisation.audit.AuditLogger;
import com.yourorg.tokenisation.config.RotationProperties;
import com.yourorg.tokenisation.crypto.InMemoryDekKeyRing;
import com.yourorg.tokenisation.domain.KeyVersion;
import com.yourorg.tokenisation.repository.KeyVersionRepository;
import com.yourorg.tokenisation.repository.TokenVaultRepository;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Scheduled job that drives the DEK rotation batch re-encryption pipeline.
 *
 * <p>On each invocation, the job checks for any DEK version in {@code ROTATING} or
 * {@code COMPROMISED} status. If found, it delegates a batch to {@link RotationBatchProcessor}.
 * When all tokens have been migrated, the old key is retired.
 */
@Component
@Slf4j
public class RotationJob {

    private final RotationBatchProcessor batchProcessor;
    private final KeyVersionRepository keyVersionRepository;
    private final TokenVaultRepository tokenVaultRepository;
    private final InMemoryDekKeyRing dekRing;
    private final AuditLogger auditLogger;
    private final RotationProperties rotationProperties;

    public RotationJob(RotationBatchProcessor batchProcessor,
                       KeyVersionRepository keyVersionRepository,
                       TokenVaultRepository tokenVaultRepository,
                       InMemoryDekKeyRing dekRing,
                       AuditLogger auditLogger,
                       RotationProperties rotationProperties) {
        this.batchProcessor = batchProcessor;
        this.keyVersionRepository = keyVersionRepository;
        this.tokenVaultRepository = tokenVaultRepository;
        this.dekRing = dekRing;
        this.auditLogger = auditLogger;
        this.rotationProperties = rotationProperties;
    }

    @Scheduled(cron = "${rotation.batch.cron}")
    @SchedulerLock(name = "kek-rotation-batch", lockAtMostFor = "PT10M")
    public void processRotationBatch() {
        Optional<KeyVersion> rotatingOpt = keyVersionRepository.findOldestPendingMigration();
        if (rotatingOpt.isEmpty()) {
            log.debug("No ROTATING or COMPROMISED DEK version found — rotation batch skipped");
            return;
        }

        KeyVersion rotatingKey = rotatingOpt.get();
        UUID oldKeyVersionId = rotatingKey.getId();

        Optional<KeyVersion> activeOpt = keyVersionRepository.findActiveDek();
        if (activeOpt.isEmpty()) {
            log.error("No ACTIVE DEK version found during rotation batch — cannot determine target key");
            return;
        }

        UUID newKeyVersionId = activeOpt.get().getId();

        if (oldKeyVersionId.equals(newKeyVersionId)) {
            log.error("ROTATING and ACTIVE DEK versions are the same [{}] — rotation state is inconsistent",
                    oldKeyVersionId);
            return;
        }

        log.info("Rotation drain starting: re-encrypting tokens from old DEK [{}] → new DEK [{}]",
                oldKeyVersionId, newKeyVersionId);

        int batchSize = rotationProperties.getBatch().getSize();
        drainRotationBatches(oldKeyVersionId, newKeyVersionId, batchSize);

        long remaining = tokenVaultRepository.countActiveByKeyVersionId(oldKeyVersionId);
        if (remaining == 0) {
            log.info("All tokens migrated from DEK [{}] — initiating cutover", oldKeyVersionId);
            completeRotation(rotatingKey);
        } else {
            log.info("Rotation in progress: {} token(s) remaining on old DEK [{}]", remaining, oldKeyVersionId);
        }
    }

    private void drainRotationBatches(UUID oldKeyVersionId, UUID newKeyVersionId, int batchSize) {
        int maxBatches = rotationProperties.getBatch().getMaxBatchesPerRun();
        int batchNum = 0;

        while (true) {
            if (Thread.currentThread().isInterrupted()) {
                log.warn("Rotation drain interrupted after {} batch(es) on DEK [{}] — " +
                        "will resume on next cron tick", batchNum, oldKeyVersionId);
                return;
            }

            RotationBatchProcessor.BatchResult result =
                    batchProcessor.processBatch(oldKeyVersionId, newKeyVersionId, batchSize);
            batchNum++;

            if (batchNum % 10 == 0 || result.totalFetched() == 0) {
                log.info("Rotation drain batch {}: processed={}, failed={}, fetched={}",
                        batchNum, result.processedCount(), result.failedCount(), result.totalFetched());
            }

            if (result.totalFetched() == 0) {
                log.info("Rotation drain complete after {} batch(es) — no records remain on DEK [{}]",
                        batchNum, oldKeyVersionId);
                break;
            }

            if (maxBatches > 0 && batchNum >= maxBatches) {
                log.info("Rotation drain paused after {} batch(es) (maxBatchesPerRun={}) — " +
                        "will resume on next cron tick", batchNum, maxBatches);
                break;
            }
        }
    }

    @Transactional
    public void completeRotation(KeyVersion rotatingKey) {
        UUID oldKeyVersionId = rotatingKey.getId();

        long remainingDoubleCheck = tokenVaultRepository.countActiveByKeyVersionId(oldKeyVersionId);
        if (remainingDoubleCheck > 0) {
            log.warn("Premature cutover prevented: {} token(s) still on DEK [{}] — continuing batch",
                    remainingDoubleCheck, oldKeyVersionId);
            return;
        }

        rotatingKey.markRetired(Instant.now());
        keyVersionRepository.save(rotatingKey);

        dekRing.retire(oldKeyVersionId.toString());

        auditLogger.logKeyEvent(
                AuditEventType.KEY_ROTATION_COMPLETED,
                oldKeyVersionId,
                "SUCCESS",
                null,
                null);

        log.info("DEK rotation complete: key [{}] retired successfully", oldKeyVersionId);
    }
}
