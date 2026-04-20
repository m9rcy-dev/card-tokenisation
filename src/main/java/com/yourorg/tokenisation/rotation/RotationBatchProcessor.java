package com.yourorg.tokenisation.rotation;

import com.yourorg.tokenisation.audit.AuditEventType;
import com.yourorg.tokenisation.audit.AuditLogger;
import com.yourorg.tokenisation.config.RotationProperties;
import com.yourorg.tokenisation.crypto.AesGcmCipher;
import com.yourorg.tokenisation.crypto.InMemoryKeyRing;
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
 * Processes a single batch of token vault records during key rotation re-encryption.
 *
 * <p>During key rotation, each token vault record holds its PAN ciphertext encrypted with
 * a DEK, and the DEK wrapped under the old KEK ({@code encryptedDek}). Re-encryption
 * updates {@code encryptedDek} to wrap the same DEK under the new KEK — the PAN
 * ciphertext itself is not touched.
 *
 * <h3>Per-record flow</h3>
 * <ol>
 *   <li>Retrieve both KEKs from {@link InMemoryKeyRing} (already loaded at startup — no KMS call).
 *   <li>Unwrap the DEK using the old KEK via {@link AesGcmCipher#unwrapDek} (in-memory AES-GCM).
 *   <li>Rewrap the DEK using the new KEK via {@link AesGcmCipher#wrapDek} (in-memory AES-GCM).
 *   <li>Zero all plaintext key material ({@code oldKek}, {@code newKek}, {@code plaintextDek})
 *       in {@code finally} blocks regardless of outcome.
 *   <li>Call {@link TokenVault#reencryptDek} to update the record's encrypted DEK and
 *       key version reference.
 *   <li>Save the record. The {@code @Version} field ({@code recordVersion}) provides
 *       optimistic locking — a concurrent update causes
 *       {@link ObjectOptimisticLockingFailureException}, which is logged and the record
 *       is skipped (it will appear again in the next batch).
 *   <li>Write a {@code TOKEN_REENCRYPTED} success audit event.
 * </ol>
 *
 * <h3>Parallelism</h3>
 * Records within a batch are processed concurrently using a fixed virtual-thread pool
 * ({@code rotation-rewrap-N}). The pool size is controlled by
 * {@link RotationProperties.Batch#getParallelism()} (default 8). Each record's
 * {@link #reencryptSingleToken} runs in its own {@code REQUIRES_NEW} transaction via the
 * Spring AOP proxy ({@link #self}), so failures on one record do not affect others.
 * The pool is shut down cleanly on application shutdown via {@link #shutdownExecutor()}.
 *
 * <h3>Why no KMS call during rotation</h3>
 * {@code encryptedDek} stored in {@code token_vault} is an AES-256-GCM blob produced by
 * {@link AesGcmCipher#wrapDek} using the in-memory KEK — it is NOT a KMS ciphertext.
 * Both the old and new KEKs are already in {@link InMemoryKeyRing} (loaded from KMS once
 * at startup). Re-wrapping is therefore a purely in-memory operation: unwrap with old KEK,
 * rewrap with new KEK. This keeps KMS calls to 1–2 per startup regardless of vault size.
 *
 * <h3>Error handling</h3>
 * Each record runs in its own {@code REQUIRES_NEW} transaction. A failure on one record
 * does not abort the batch — the error is logged and a {@code RE_ENCRYPTION_FAILURE}
 * audit event is written. The record will be included in the next batch invocation.
 */
@Component
@Slf4j
public class RotationBatchProcessor {

    private final TokenVaultRepository tokenVaultRepository;
    private final KeyVersionRepository keyVersionRepository;
    private final AesGcmCipher cipher;
    private final InMemoryKeyRing keyRing;
    private final AuditLogger auditLogger;
    private final ExecutorService rewrapExecutor;

    /**
     * Self-reference through the Spring proxy to ensure {@link #reencryptSingleToken}
     * is called via the proxy rather than directly on {@code this}. Without this,
     * Spring AOP cannot intercept the method and apply the
     * {@link Transactional @Transactional(REQUIRES_NEW)} annotation.
     *
     * <p>{@code @Lazy} breaks the circular dependency that would otherwise arise because
     * the bean needs to inject itself during construction.
     *
     * <p>Package-private visibility allows unit tests to set {@code self = processor}
     * directly (no proxy needed when transactions are not under test).
     */
    @Autowired
    @Lazy
    RotationBatchProcessor self;

    /**
     * Constructs the batch processor with all required collaborators.
     *
     * @param tokenVaultRepository the vault repository for batch reads and updates; must not be null
     * @param keyVersionRepository the key version repository for new key lookups; must not be null
     * @param cipher               AES-256-GCM cipher for in-memory DEK unwrap and rewrap; must not be null
     * @param keyRing              in-memory key ring holding both old and new KEK bytes; must not be null
     * @param auditLogger          audit event writer; must not be null
     * @param rotationProperties   rotation configuration (parallelism, batch sizes); must not be null
     */
    public RotationBatchProcessor(TokenVaultRepository tokenVaultRepository,
                                   KeyVersionRepository keyVersionRepository,
                                   AesGcmCipher cipher,
                                   InMemoryKeyRing keyRing,
                                   AuditLogger auditLogger,
                                   RotationProperties rotationProperties) {
        this.tokenVaultRepository = tokenVaultRepository;
        this.keyVersionRepository = keyVersionRepository;
        this.cipher = cipher;
        this.keyRing = keyRing;
        this.auditLogger = auditLogger;
        this.rewrapExecutor = Executors.newFixedThreadPool(
                rotationProperties.getBatch().getParallelism(),
                Thread.ofVirtual().name("rotation-rewrap-", 0).factory());
    }

    /**
     * Shuts down the rewrap thread pool on application shutdown.
     *
     * <p>Called automatically by Spring via {@code @PreDestroy}. Any in-flight rewrap
     * tasks that were running when shutdown is triggered will complete normally (the pool
     * is not interrupted); tasks that had not yet started are discarded.
     */
    @PreDestroy
    void shutdownExecutor() {
        rewrapExecutor.shutdown();
        log.info("Rotation rewrap executor shutdown initiated");
    }

    /**
     * Processes one batch of token vault records that are still encrypted under the old key version.
     *
     * <p>Records are fetched with {@link PageRequest#of(int, int) PageRequest.of(0, batchSize)}.
     * Each record is submitted to the parallel rewrap executor as a {@link CompletableFuture}.
     * All futures are awaited before returning the {@link BatchResult}. Failures on individual
     * records are caught, logged, and counted — they do not abort the batch.
     *
     * @param oldKeyVersionId the UUID of the old key version (currently {@code ROTATING})
     * @param newKeyVersionId the UUID of the new key version (currently {@code ACTIVE})
     * @param batchSize       maximum number of records to process in this invocation
     * @return a {@link BatchResult} with processed and failed counts
     */
    public BatchResult processBatch(UUID oldKeyVersionId, UUID newKeyVersionId, int batchSize) {
        KeyVersion newKeyVersion = keyVersionRepository.findById(newKeyVersionId)
                .orElseThrow(() -> new IllegalStateException(
                        "New key version not found in DB: " + newKeyVersionId));

        List<TokenVault> batch = tokenVaultRepository.findActiveByKeyVersionId(
                oldKeyVersionId, PageRequest.of(0, batchSize));

        if (batch.isEmpty()) {
            log.debug("No tokens remain on old key version [{}]", oldKeyVersionId);
            return BatchResult.empty();
        }

        log.info("Re-encrypting batch of {} token(s) from key version [{}] → [{}] (parallelism={})",
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
                                null,
                                "Re-encryption failed: " + tokenException.getClass().getSimpleName()
                                        + " — " + tokenException.getMessage(),
                                null);
                    }
                }, rewrapExecutor))
                .toList();

        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();

        log.info("Batch complete: {} processed, {} failed (old key [{}])",
                processed.get(), failed.get(), oldKeyVersionId);
        return new BatchResult(processed.get(), failed.get(), batch.size());
    }

    /**
     * Re-encrypts the DEK for a single token vault record in its own transaction.
     *
     * <p>Runs in {@code REQUIRES_NEW} so that a failure on one token does not
     * roll back any other token's update within the same batch call.
     *
     * <p>Both KEKs are retrieved from the in-memory key ring (loaded from KMS once at
     * startup). The DEK is unwrapped using the old KEK and rewrapped under the new KEK
     * entirely in memory — no KMS call is made during this operation.
     *
     * <p>All plaintext key material ({@code oldKek}, {@code newKek}, {@code plaintextDek})
     * is zeroed in {@code finally} blocks regardless of whether the operation succeeds or fails.
     *
     * <p>An {@link ObjectOptimisticLockingFailureException} means another thread updated
     * this record concurrently. It is treated as a transient failure — the record will
     * reappear in the next batch.
     *
     * @param vault           the token vault record to re-encrypt
     * @param oldKeyVersionId the old key version UUID (must be loaded in the key ring)
     * @param newKeyVersionId the new key version UUID (must be loaded in the key ring)
     * @param newKeyVersion   the new key version entity (for the vault's FK reference)
     * @throws ObjectOptimisticLockingFailureException if the record was concurrently modified
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void reencryptSingleToken(TokenVault vault,
                                     UUID oldKeyVersionId,
                                     UUID newKeyVersionId,
                                     KeyVersion newKeyVersion) {
        KeyMaterial oldKeyMaterial = keyRing.getByVersion(oldKeyVersionId.toString());
        KeyMaterial newKeyMaterial = keyRing.getByVersion(newKeyVersionId.toString());

        byte[] oldKek = oldKeyMaterial.copyKek();
        byte[] newKek = newKeyMaterial.copyKek();
        byte[] plaintextDek = null;
        try {
            // Unwrap DEK using old KEK — in-memory AES-GCM, no KMS call
            plaintextDek = cipher.unwrapDek(vault.getEncryptedDek(), oldKek);

            // Rewrap DEK under new KEK — in-memory AES-GCM, no KMS call
            byte[] newEncryptedDek = cipher.wrapDek(plaintextDek, newKek);
            try {
                vault.reencryptDek(newEncryptedDek, newKeyVersion);
                tokenVaultRepository.save(vault);

                auditLogger.logSuccess(
                        AuditEventType.TOKEN_REENCRYPTED,
                        vault.getTokenId(),
                        null,
                        null,
                        null,
                        null);

                log.debug("Re-encrypted token [{}]: DEK migrated from key [{}] → [{}]",
                        vault.getTokenId(), oldKeyVersionId, newKeyVersionId);
            } finally {
                Arrays.fill(newEncryptedDek, (byte) 0);
            }
        } finally {
            Arrays.fill(oldKek, (byte) 0);
            Arrays.fill(newKek, (byte) 0);
            if (plaintextDek != null) Arrays.fill(plaintextDek, (byte) 0);
        }
    }

    /**
     * Result summary for one batch invocation.
     *
     * @param processedCount number of records successfully re-encrypted
     * @param failedCount    number of records that failed and were skipped
     * @param totalFetched   total records fetched in this batch
     */
    public record BatchResult(int processedCount, int failedCount, int totalFetched) {

        /**
         * Returns a result representing a batch where no records were found.
         *
         * @return a zero-count result
         */
        public static BatchResult empty() {
            return new BatchResult(0, 0, 0);
        }

        /**
         * Returns {@code true} if the batch fetched fewer records than the requested batch size,
         * suggesting the remaining population is small (though not necessarily zero —
         * use {@link TokenVaultRepository#countActiveByKeyVersionId} for an exact check).
         *
         * @param batchSize the requested batch size
         * @return {@code true} if the batch was a partial page
         */
        public boolean isPartialPage(int batchSize) {
            return totalFetched < batchSize;
        }
    }
}
