package com.yourorg.tokenisation.rotation;

import com.yourorg.tokenisation.config.RotationProperties;
import com.yourorg.tokenisation.crypto.InMemoryHmacKeyRing;
import com.yourorg.tokenisation.repository.TokenVaultRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.UUID;

/**
 * Scheduled job that drives the HMAC rotation batch re-hashing pipeline.
 *
 * <p>On each invocation the job checks whether a HMAC key version is in ROTATING status
 * (via {@link InMemoryHmacKeyRing#findRotatingVersionId}).  If one is found it delegates
 * successive batches to {@link PanHashBatchProcessor} until all vault records have been
 * re-hashed.  When re-hashing is complete it calls
 * {@link HmacRotationService#completeRotation} to retire the old version.
 *
 * <p>The cron expression is controlled by {@code rotation.hmac-batch.cron} (default
 * {@code "0 0 2 * * *"} — 02:00 UTC daily).  Set it to {@code "-"} in test profiles to
 * disable automatic scheduling.
 */
@Component
@Slf4j
public class HmacRotationJob {

    private final PanHashBatchProcessor batchProcessor;
    private final HmacRotationService hmacRotationService;
    private final InMemoryHmacKeyRing hmacKeyRing;
    private final TokenVaultRepository tokenVaultRepository;
    private final RotationProperties rotationProperties;

    public HmacRotationJob(PanHashBatchProcessor batchProcessor,
                            HmacRotationService hmacRotationService,
                            InMemoryHmacKeyRing hmacKeyRing,
                            TokenVaultRepository tokenVaultRepository,
                            RotationProperties rotationProperties) {
        this.batchProcessor = batchProcessor;
        this.hmacRotationService = hmacRotationService;
        this.hmacKeyRing = hmacKeyRing;
        this.tokenVaultRepository = tokenVaultRepository;
        this.rotationProperties = rotationProperties;
    }

    /**
     * Drives one iteration of the HMAC re-hashing batch.
     *
     * <p>If no HMAC version is in ROTATING status, the job exits immediately.
     * Otherwise it drains batches until either all records are processed or the
     * {@code maxBatchesPerRun} cap is reached.
     */
    @Scheduled(cron = "${rotation.hmac-batch.cron}")
    public void processHmacRotationBatch() {
        Optional<String> rotatingOpt = hmacKeyRing.findRotatingVersionId();
        if (rotatingOpt.isEmpty()) {
            log.debug("No ROTATING HMAC version found — HMAC rotation batch skipped");
            return;
        }

        String rotatingVersionId = rotatingOpt.get();
        UUID rotatingId = UUID.fromString(rotatingVersionId);

        String newVersionId = hmacKeyRing.getActiveVersionId();
        UUID newId = UUID.fromString(newVersionId);

        if (rotatingVersionId.equals(newVersionId)) {
            log.error("ROTATING and ACTIVE HMAC versions are the same [{}] — inconsistent ring state",
                    rotatingVersionId);
            return;
        }

        log.info("HMAC rotation drain starting: HMAC [{}] → [{}]", rotatingVersionId, newVersionId);

        int batchSize = rotationProperties.getHmacBatch().getSize();
        drainBatches(rotatingId, newId, batchSize);

        long remaining = tokenVaultRepository.countActiveByHmacVersionId(rotatingId);
        if (remaining == 0) {
            log.info("All vault records re-hashed — completing HMAC rotation [{}]", rotatingVersionId);
            hmacRotationService.completeRotation(rotatingId);
        } else {
            log.info("HMAC rotation in progress: {} record(s) remaining on HMAC version [{}]",
                    remaining, rotatingVersionId);
        }
    }

    private void drainBatches(UUID rotatingId, UUID newId, int batchSize) {
        int maxBatches = rotationProperties.getHmacBatch().getMaxBatchesPerRun();
        int batchNum = 0;

        while (true) {
            if (Thread.currentThread().isInterrupted()) {
                log.warn("HMAC rotation drain interrupted after {} batch(es) on HMAC [{}]",
                        batchNum, rotatingId);
                return;
            }

            RotationBatchProcessor.BatchResult result =
                    batchProcessor.processBatch(rotatingId, newId, batchSize);
            batchNum++;

            if (batchNum % 10 == 0 || result.totalFetched() == 0) {
                log.info("HMAC drain batch {}: processed={}, failed={}, fetched={}",
                        batchNum, result.processedCount(), result.failedCount(), result.totalFetched());
            }

            if (result.totalFetched() == 0) {
                log.info("HMAC drain complete after {} batch(es)", batchNum);
                break;
            }

            if (maxBatches > 0 && batchNum >= maxBatches) {
                log.info("HMAC drain paused after {} batch(es) (maxBatchesPerRun={}) — resuming on next cron tick",
                        batchNum, maxBatches);
                break;
            }
        }
    }
}
