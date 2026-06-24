package com.yourorg.tokenisation.rotation;

import com.yourorg.tokenisation.audit.AuditEventType;
import com.yourorg.tokenisation.audit.AuditLogger;
import com.yourorg.tokenisation.config.RotationProperties;
import com.yourorg.tokenisation.crypto.AesGcmCipher;
import com.yourorg.tokenisation.crypto.EncryptResult;
import com.yourorg.tokenisation.crypto.InMemoryDekKeyRing;
import com.yourorg.tokenisation.crypto.KeyMaterial;
import com.yourorg.tokenisation.domain.KeyVersion;
import com.yourorg.tokenisation.domain.TokenVault;
import com.yourorg.tokenisation.repository.KeyVersionRepository;
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

import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Processes a single batch of token vault records during DEK rotation re-encryption.
 *
 * <p>In the 2-layer architecture (KMS → DEK → PAN), rotation requires decrypting each
 * PAN under the old DEK and re-encrypting it under the new DEK. The PAN is briefly in
 * memory during this operation and zeroed in a {@code finally} block immediately after.
 *
 * <h3>Per-record flow</h3>
 * <ol>
 *   <li>Retrieve both DEKs from {@link InMemoryDekKeyRing} (loaded at startup — no KMS call).
 *   <li>Decrypt PAN using old DEK via {@link AesGcmCipher#decrypt} (in-memory AES-GCM).
 *   <li>Re-encrypt PAN using new DEK via {@link AesGcmCipher#encrypt} with a fresh IV.
 *   <li>Zero plaintext PAN bytes in a {@code finally} block regardless of outcome.
 *   <li>Call {@link TokenVault#reencryptPan} to update the record.
 *   <li>Save the record. The {@code @Version} field provides optimistic locking.
 *   <li>Write a {@code TOKEN_REENCRYPTED} success audit event.
 * </ol>
 *
 * <h3>Parallelism</h3>
 * Records within a batch are processed concurrently using a fixed virtual-thread pool.
 * Each record's {@link #reencryptSingleToken} runs in its own {@code REQUIRES_NEW}
 * transaction via the Spring AOP proxy ({@link #self}).
 */
@Component
@Slf4j
public class RotationBatchProcessor {

    private final TokenVaultRepository tokenVaultRepository;
    private final KeyVersionRepository keyVersionRepository;
    private final AesGcmCipher cipher;
    private final InMemoryDekKeyRing dekRing;
    private final AuditLogger auditLogger;
    private final ExecutorService rewrapExecutor;

    @Autowired
    @Lazy
    RotationBatchProcessor self;

    public RotationBatchProcessor(TokenVaultRepository tokenVaultRepository,
                                   KeyVersionRepository keyVersionRepository,
                                   AesGcmCipher cipher,
                                   InMemoryDekKeyRing dekRing,
                                   AuditLogger auditLogger,
                                   RotationProperties rotationProperties) {
        this.tokenVaultRepository = tokenVaultRepository;
        this.keyVersionRepository = keyVersionRepository;
        this.cipher = cipher;
        this.dekRing = dekRing;
        this.auditLogger = auditLogger;
        this.rewrapExecutor = Executors.newFixedThreadPool(
                rotationProperties.getBatch().getParallelism(),
                Thread.ofVirtual().name("rotation-rewrap-", 0).factory());
    }

    @PreDestroy
    void shutdownExecutor() {
        rewrapExecutor.shutdown();
        log.info("Rotation rewrap executor shutdown initiated");
    }

    /**
     * Processes one batch of token vault records still encrypted under the old DEK version.
     */
    public BatchResult processBatch(UUID oldKeyVersionId, UUID newKeyVersionId, int batchSize) {
        KeyVersion newKeyVersion = keyVersionRepository.findById(newKeyVersionId)
                .orElseThrow(() -> new IllegalStateException(
                        "New key version not found in DB: " + newKeyVersionId));

        List<TokenVault> batch = tokenVaultRepository.findActiveByKeyVersionId(
                oldKeyVersionId, PageRequest.of(0, batchSize));

        if (batch.isEmpty()) {
            log.debug("No tokens remain on old DEK version [{}]", oldKeyVersionId);
            return BatchResult.empty();
        }

        log.info("Re-encrypting batch of {} token(s) from DEK version [{}] → [{}] (parallelism={})",
                batch.size(), oldKeyVersionId, newKeyVersionId, rewrapExecutor.toString());

        AtomicInteger processed = new AtomicInteger();
        AtomicInteger failed    = new AtomicInteger();

        List<CompletableFuture<Void>> futures = batch.stream()
                .map(vault -> CompletableFuture.runAsync(() -> {
                    try {
                        self.reencryptSingleToken(vault, oldKeyVersionId, newKeyVersionId, newKeyVersion);
                        processed.incrementAndGet();
                    } catch (Exception tokenException) {
                        failed.incrementAndGet();
                        log.error("Re-encryption failed for token [{}]: {}",
                                vault.getTokenId(), tokenException.getMessage(), tokenException);
                        auditLogger.logFailure(
                                AuditEventType.RE_ENCRYPTION_FAILURE,
                                vault.getTokenId(),
                                null,
                                null,
                                "Re-encryption failed: " + tokenException.getClass().getSimpleName()
                                        + " — " + tokenException.getMessage(),
                                null);
                    }
                }, rewrapExecutor))
                .toList();

        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();

        log.info("Batch complete: {} processed, {} failed (old DEK [{}])",
                processed.get(), failed.get(), oldKeyVersionId);
        return new BatchResult(processed.get(), failed.get(), batch.size());
    }

    /**
     * Re-encrypts the PAN for a single token vault record in its own transaction.
     *
     * <p>Runs in {@code REQUIRES_NEW} so that a failure on one token does not
     * roll back any other token's update within the same batch call.
     *
     * <p>Both DEKs are retrieved from the in-memory ring. The PAN is decrypted with the
     * old DEK, immediately re-encrypted with the new DEK using a fresh IV, and the
     * plaintext PAN bytes are zeroed in a {@code finally} block.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void reencryptSingleToken(TokenVault vault,
                                     UUID oldKeyVersionId,
                                     UUID newKeyVersionId,
                                     KeyVersion newKeyVersion) {
        KeyMaterial oldKeyMaterial = dekRing.getByVersion(oldKeyVersionId.toString());
        KeyMaterial newKeyMaterial = dekRing.getByVersion(newKeyVersionId.toString());

        byte[] oldDek = oldKeyMaterial.copyDek();
        byte[] newDek = newKeyMaterial.copyDek();
        byte[] panBytes = null;
        try {
            panBytes = cipher.decrypt(vault.getEncryptedPan(), vault.getIv(), vault.getAuthTag(), oldDek);
            EncryptResult result = cipher.encrypt(panBytes, newDek);
            vault.reencryptPan(result.ciphertext(), result.iv(), result.authTag(), newKeyVersion);
            tokenVaultRepository.save(vault);

            auditLogger.logSuccess(
                    AuditEventType.TOKEN_REENCRYPTED,
                    vault.getTokenId(),
                    null,
                    null,
                    null);

            log.debug("Re-encrypted token [{}]: PAN migrated from DEK [{}] → [{}]",
                    vault.getTokenId(), oldKeyVersionId, newKeyVersionId);
        } finally {
            Arrays.fill(oldDek, (byte) 0);
            Arrays.fill(newDek, (byte) 0);
            if (panBytes != null) Arrays.fill(panBytes, (byte) 0);
        }
    }

    /**
     * Result summary for one batch invocation.
     */
    public record BatchResult(int processedCount, int failedCount, int totalFetched) {

        public static BatchResult empty() {
            return new BatchResult(0, 0, 0);
        }

        public boolean isPartialPage(int batchSize) {
            return totalFetched < batchSize;
        }
    }
}
