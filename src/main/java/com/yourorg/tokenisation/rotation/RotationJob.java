package com.yourorg.tokenisation.rotation;

import com.yourorg.tokenisation.audit.AuditEventType;
import com.yourorg.tokenisation.audit.AuditLogger;
import com.yourorg.tokenisation.config.RotationProperties;
import com.yourorg.tokenisation.crypto.AesGcmCipher;
import com.yourorg.tokenisation.crypto.InMemoryKekKeyRing;
import com.yourorg.tokenisation.crypto.KeyMaterial;
import com.yourorg.tokenisation.domain.KeyVersion;
import com.yourorg.tokenisation.repository.KeyVersionRepository;
import com.yourorg.tokenisation.repository.TokenVaultRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Scheduled job that drives the KEK rotation batch re-encryption pipeline.
 *
 * <p>On each invocation, the job checks for any KEK version in {@code ROTATING} or
 * {@code COMPROMISED} status. If found, it delegates a batch to {@link RotationBatchProcessor}.
 * When all tokens have been migrated, the old key is retired.
 */
@Component
@Slf4j
public class RotationJob {

    private final RotationBatchProcessor batchProcessor;
    private final KeyVersionRepository keyVersionRepository;
    private final TokenVaultRepository tokenVaultRepository;
    private final InMemoryKekKeyRing keyRing;
    private final AesGcmCipher cipher;
    private final AuditLogger auditLogger;
    private final RotationProperties rotationProperties;

    public RotationJob(RotationBatchProcessor batchProcessor,
                       KeyVersionRepository keyVersionRepository,
                       TokenVaultRepository tokenVaultRepository,
                       InMemoryKekKeyRing keyRing,
                       AesGcmCipher cipher,
                       AuditLogger auditLogger,
                       RotationProperties rotationProperties) {
        this.batchProcessor = batchProcessor;
        this.keyVersionRepository = keyVersionRepository;
        this.tokenVaultRepository = tokenVaultRepository;
        this.keyRing = keyRing;
        this.cipher = cipher;
        this.auditLogger = auditLogger;
        this.rotationProperties = rotationProperties;
    }

    @Scheduled(cron = "${rotation.batch.cron}")
    public void processRotationBatch() {
        Optional<KeyVersion> rotatingOpt = keyVersionRepository.findOldestPendingMigration();
        if (rotatingOpt.isEmpty()) {
            log.debug("No ROTATING or COMPROMISED key version found — rotation batch skipped");
            return;
        }

        KeyVersion rotatingKey = rotatingOpt.get();
        UUID oldKeyVersionId = rotatingKey.getId();

        Optional<KeyVersion> activeOpt = keyVersionRepository.findActiveKek();
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

        log.info("Rotation drain starting: re-encrypting tokens from old key [{}] → new key [{}]",
                oldKeyVersionId, newKeyVersionId);

        int batchSize = rotationProperties.getBatch().getSize();
        drainRotationBatches(oldKeyVersionId, newKeyVersionId, batchSize);

        long remaining = tokenVaultRepository.countActiveByKeyVersionId(oldKeyVersionId);
        if (remaining == 0) {
            log.info("All tokens migrated from key [{}] — initiating cutover", oldKeyVersionId);
            completeRotation(rotatingKey, activeOpt.get());
        } else {
            log.info("Rotation in progress: {} token(s) remaining on old key [{}]", remaining, oldKeyVersionId);
        }
    }

    private void drainRotationBatches(UUID oldKeyVersionId, UUID newKeyVersionId, int batchSize) {
        int maxBatches = rotationProperties.getBatch().getMaxBatchesPerRun();
        int batchNum = 0;

        while (true) {
            if (Thread.currentThread().isInterrupted()) {
                log.warn("Rotation drain interrupted after {} batch(es) on key [{}] — " +
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
                log.info("Rotation drain complete after {} batch(es) — no records remain on key [{}]",
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
    public void completeRotation(KeyVersion rotatingKey, KeyVersion newKek) {
        UUID oldKeyVersionId = rotatingKey.getId();

        long remainingDoubleCheck = tokenVaultRepository.countActiveByKeyVersionId(oldKeyVersionId);
        if (remainingDoubleCheck > 0) {
            log.warn("Premature cutover prevented: {} token(s) still on key [{}] — continuing batch",
                    remainingDoubleCheck, oldKeyVersionId);
            return;
        }

        // Re-wrap any HMAC secrets still encrypted under the retiring KEK so they remain
        // loadable at next startup (the RETIRED KEK is not loaded into the ring).
        rewrapHmacSecrets(oldKeyVersionId, newKek);

        rotatingKey.markRetired(Instant.now());
        keyVersionRepository.save(rotatingKey);

        keyRing.retire(oldKeyVersionId.toString());

        auditLogger.logKeyEvent(
                AuditEventType.KEY_ROTATION_COMPLETED,
                oldKeyVersionId,
                "SUCCESS",
                null,
                null);

        log.info("Key rotation complete: key [{}] retired successfully", oldKeyVersionId);
    }

    /**
     * Re-encrypts the {@code encrypted_secret} of any HMAC key versions that were wrapped
     * under the retiring KEK, binding them to the new KEK instead.
     *
     * <p>Both KEKs are already in the in-memory ring (old one is still ROTATING at this point,
     * not yet RETIRED). This is a purely in-memory operation — no KMS call is made.
     * The HMAC table is tiny (single-digit rows), so this runs synchronously.
     */
    private void rewrapHmacSecrets(UUID oldKekVersionId, KeyVersion newKek) {
        List<KeyVersion> hmacRows = keyVersionRepository.findHmacByEncryptingKekId(oldKekVersionId);
        if (hmacRows.isEmpty()) {
            return;
        }
        log.info("Re-wrapping {} HMAC secret(s) from KEK [{}] → [{}]",
                hmacRows.size(), oldKekVersionId, newKek.getId());

        KeyMaterial oldKekMaterial = keyRing.getByVersion(oldKekVersionId.toString());
        KeyMaterial newKekMaterial = keyRing.getByVersion(newKek.getId().toString());

        byte[] oldKek = oldKekMaterial.copyKek();
        byte[] newKek2 = newKekMaterial.copyKek();
        try {
            for (KeyVersion hmac : hmacRows) {
                byte[] secret = null;
                try {
                    secret = cipher.decryptBytes(hmac.getEncryptedSecret(), oldKek);
                    byte[] rewrapped = cipher.encryptBytes(secret, newKek2);
                    hmac.rewrapSecret(rewrapped, newKek.getId());
                    keyVersionRepository.save(hmac);
                    log.debug("HMAC key [{}] re-wrapped under new KEK [{}]", hmac.getId(), newKek.getId());
                } finally {
                    if (secret != null) Arrays.fill(secret, (byte) 0);
                }
            }
        } finally {
            Arrays.fill(oldKek,  (byte) 0);
            Arrays.fill(newKek2, (byte) 0);
        }
    }
}
