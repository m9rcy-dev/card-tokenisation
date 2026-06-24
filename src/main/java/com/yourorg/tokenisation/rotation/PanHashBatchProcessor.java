package com.yourorg.tokenisation.rotation;

import com.yourorg.tokenisation.audit.AuditEventType;
import com.yourorg.tokenisation.audit.AuditLogger;
import com.yourorg.tokenisation.config.RotationProperties;
import com.yourorg.tokenisation.crypto.AesGcmCipher;
import com.yourorg.tokenisation.crypto.InMemoryDekKeyRing;
import com.yourorg.tokenisation.crypto.KeyMaterial;
import com.yourorg.tokenisation.crypto.PanHasher;
import com.yourorg.tokenisation.domain.KeyStatus;
import com.yourorg.tokenisation.domain.TokenVault;
import com.yourorg.tokenisation.repository.TokenVaultRepository;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.data.domain.PageRequest;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Processes a batch of vault records during HMAC key rotation, re-hashing each PAN
 * under the new HMAC key version.
 *
 * <h3>Per-record flow</h3>
 * <ol>
 *   <li>Load the DEK for the record's key version from {@link InMemoryDekKeyRing}.
 *   <li>If that DEK is {@code COMPROMISED}, skip the record (emit
 *       {@link AuditEventType#RE_HASH_SKIPPED_COMPROMISED_KEY}); it will be processed
 *       after the DEK rotation batch re-encrypts its PAN.
 *   <li>Decrypt the PAN using {@link AesGcmCipher#decrypt}.
 *   <li>Compute a new HMAC-SHA256 via {@link PanHasher#hashWithVersion} using the new version.
 *   <li>Update {@code token_vault.pan_hash} and {@code hmac_key_version_id} and save.
 *   <li>Emit a {@link AuditEventType#PAN_HASH_RECOMPUTED} audit event.
 *   <li>Zero all key material and PAN bytes in {@code finally} blocks.
 * </ol>
 *
 * <p>Records are processed in parallel using a virtual-thread pool whose size is
 * controlled by {@link RotationProperties.HmacBatch#getParallelism()} (default 4).
 * Each record runs in its own {@code REQUIRES_NEW} transaction via the Spring AOP proxy
 * ({@code self}), so a failure on one record does not abort the batch.
 *
 * <p>An {@link ObjectOptimisticLockingFailureException} means a concurrent update —
 * the record is skipped and will reappear in the next batch.
 */
@Component
@Slf4j
public class PanHashBatchProcessor {

    private final TokenVaultRepository tokenVaultRepository;
    private final InMemoryDekKeyRing dekRing;
    private final AesGcmCipher cipher;
    private final PanHasher panHasher;
    private final AuditLogger auditLogger;
    private final ExecutorService rehashExecutor;

    /**
     * Self-reference through the Spring proxy so that {@link #rehashSingleVault} is called
     * via the proxy and benefits from {@code @Transactional(REQUIRES_NEW)}.
     *
     * <p>{@code @Lazy} breaks the circular dependency from self-injection at construction time.
     */
    @Autowired
    @Lazy
    PanHashBatchProcessor self;

    public PanHashBatchProcessor(TokenVaultRepository tokenVaultRepository,
                                  InMemoryDekKeyRing dekRing,
                                  AesGcmCipher cipher,
                                  PanHasher panHasher,
                                  AuditLogger auditLogger,
                                  RotationProperties rotationProperties) {
        this.tokenVaultRepository = tokenVaultRepository;
        this.dekRing = dekRing;
        this.cipher = cipher;
        this.panHasher = panHasher;
        this.auditLogger = auditLogger;
        this.rehashExecutor = Executors.newFixedThreadPool(
                rotationProperties.getHmacBatch().getParallelism(),
                Thread.ofVirtual().name("hmac-rehash-", 0).factory());
    }

    @PreDestroy
    void shutdownExecutor() {
        rehashExecutor.shutdown();
        log.info("HMAC rehash executor shutdown initiated");
    }

    /**
     * Processes one batch of vault records still hashed under the rotating HMAC version.
     *
     * @param rotatingHmacVersionId UUID of the ROTATING HMAC key version
     * @param newHmacVersionId      UUID of the new ACTIVE HMAC key version
     * @param batchSize             maximum records to fetch
     * @return summary of processed, failed, and fetched counts
     */
    public RotationBatchProcessor.BatchResult processBatch(UUID rotatingHmacVersionId,
                                                           UUID newHmacVersionId,
                                                           int batchSize) {
        List<TokenVault> batch = tokenVaultRepository.findActiveByHmacVersionId(
                rotatingHmacVersionId, PageRequest.of(0, batchSize));

        if (batch.isEmpty()) {
            log.debug("No vault records remain on HMAC version [{}]", rotatingHmacVersionId);
            return RotationBatchProcessor.BatchResult.empty();
        }

        log.info("Re-hashing batch of {} record(s): HMAC [{}] → [{}]",
                batch.size(), rotatingHmacVersionId, newHmacVersionId);

        AtomicInteger processed = new AtomicInteger();
        AtomicInteger failed = new AtomicInteger();

        List<CompletableFuture<Void>> futures = batch.stream()
                .map(vault -> CompletableFuture.runAsync(() -> {
                    try {
                        self.rehashSingleVault(vault, newHmacVersionId);
                        processed.incrementAndGet();
                    } catch (Exception e) {
                        failed.incrementAndGet();
                        log.error("HMAC re-hash failed for token [{}]: {}",
                                vault.getTokenId(), e.getMessage(), e);
                        auditLogger.logFailure(
                                AuditEventType.RE_ENCRYPTION_FAILURE,
                                vault.getTokenId(), null, null,
                                "HMAC re-hash failed: " + e.getClass().getSimpleName()
                                        + " — " + e.getMessage(),
                                null);
                    }
                }, rehashExecutor))
                .toList();

        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();

        log.info("HMAC batch complete: {} processed, {} failed (HMAC [{}])",
                processed.get(), failed.get(), rotatingHmacVersionId);
        return new RotationBatchProcessor.BatchResult(processed.get(), failed.get(), batch.size());
    }

    /**
     * Re-hashes the PAN for a single vault record in its own transaction.
     *
     * <p>Runs in {@code REQUIRES_NEW} so that a failure on one record does not roll back
     * any other record's update within the same batch call.
     *
     * <p>All plaintext key and PAN material is zeroed in {@code finally} blocks regardless
     * of whether the operation succeeds or fails.
     *
     * @param vault            the vault record whose pan_hash needs updating
     * @param newHmacVersionId the UUID of the new ACTIVE HMAC version
     * @throws ObjectOptimisticLockingFailureException if a concurrent update raced this record
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void rehashSingleVault(TokenVault vault, UUID newHmacVersionId) {
        String dekVersionId = vault.getKeyVersion().getId().toString();
        KeyMaterial dekMaterial = dekRing.getByVersion(dekVersionId);

        // Skip records whose DEK is compromised — they can be re-hashed after DEK rotation completes
        if (dekMaterial.status() == KeyStatus.COMPROMISED) {
            log.warn("Skipping HMAC re-hash for token [{}]: DEK version [{}] is COMPROMISED",
                    vault.getTokenId(), dekVersionId);
            auditLogger.logSuccess(
                    AuditEventType.RE_HASH_SKIPPED_COMPROMISED_KEY,
                    vault.getTokenId(), null, null, null);
            return;
        }

        byte[] dek = dekMaterial.copyDek();
        byte[] panBytes = null;
        try {
            panBytes = cipher.decrypt(
                    vault.getEncryptedPan(), vault.getIv(), vault.getAuthTag(), dek);

            String pan = new String(panBytes, StandardCharsets.UTF_8);
            String newHash = panHasher.hashWithVersion(pan, newHmacVersionId.toString());

            vault.updatePanHash(newHash, newHmacVersionId);
            tokenVaultRepository.save(vault);

            auditLogger.logSuccess(
                    AuditEventType.PAN_HASH_RECOMPUTED,
                    vault.getTokenId(), null, null, null);

            log.debug("Re-hashed token [{}] → HMAC version [{}]", vault.getTokenId(), newHmacVersionId);
        } finally {
            Arrays.fill(dek, (byte) 0);
            if (panBytes != null) Arrays.fill(panBytes, (byte) 0);
        }
    }
}
