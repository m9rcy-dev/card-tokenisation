package com.yourorg.tokenisation.rotation;

import com.yourorg.tokenisation.audit.AuditEventType;
import com.yourorg.tokenisation.audit.AuditLogger;
import com.yourorg.tokenisation.config.RotationProperties;
import com.yourorg.tokenisation.crypto.AesGcmCipher;
import com.yourorg.tokenisation.crypto.InMemoryKeyRing;
import com.yourorg.tokenisation.crypto.KeyMaterial;
import com.yourorg.tokenisation.domain.KeyStatus;
import com.yourorg.tokenisation.domain.KeyVersion;
import com.yourorg.tokenisation.domain.TokenType;
import com.yourorg.tokenisation.domain.TokenVault;
import com.yourorg.tokenisation.repository.KeyVersionRepository;
import com.yourorg.tokenisation.repository.TokenVaultRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Pageable;
import org.springframework.orm.ObjectOptimisticLockingFailureException;

import java.lang.reflect.Field;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link RotationBatchProcessor}.
 *
 * <p>Tests verify:
 * <ul>
 *   <li>Happy path: token DEK is re-wrapped and vault is saved
 *   <li>Happy path: TOKEN_REENCRYPTED audit event written per token
 *   <li>Happy path: batch result counts are correct
 *   <li>Empty batch: no cipher calls, zero counts returned
 *   <li>Single record failure: batch continues, RE_ENCRYPTION_FAILURE audit written
 *   <li>Optimistic lock failure: treated as transient failure, batch continues
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class RotationBatchProcessorTest {

    private static final UUID OLD_KEY_ID = UUID.fromString("11111111-0000-0000-0000-000000000001");
    private static final UUID NEW_KEY_ID = UUID.fromString("22222222-0000-0000-0000-000000000002");
    private static final UUID TOKEN_ID_1 = UUID.fromString("33333333-0000-0000-0000-000000000001");
    private static final UUID TOKEN_ID_2 = UUID.fromString("33333333-0000-0000-0000-000000000002");

    // 32-byte (256-bit) KEKs used by KeyMaterial — content is arbitrary for unit tests
    private static final byte[] OLD_KEK = new byte[32];
    private static final byte[] NEW_KEK = new byte[32];

    @Mock private TokenVaultRepository tokenVaultRepository;
    @Mock private KeyVersionRepository keyVersionRepository;
    @Mock private AesGcmCipher cipher;
    @Mock private InMemoryKeyRing keyRing;
    @Mock private AuditLogger auditLogger;

    private RotationBatchProcessor processor;

    @BeforeEach
    void setUp() {
        // parallelism=1 keeps unit tests deterministic (sequential execution, no thread-ordering surprises)
        RotationProperties rotationProperties = new RotationProperties();
        rotationProperties.getBatch().setParallelism(1);

        processor = new RotationBatchProcessor(
                tokenVaultRepository, keyVersionRepository, cipher, keyRing, auditLogger,
                rotationProperties);
        // In unit tests there is no Spring proxy, so set self to the processor itself.
        // Transactions are not under test here — integration tests verify transactional behaviour.
        processor.self = processor;
    }

    // ── Empty batch ───────────────────────────────────────────────────────────

    @Test
    void processBatch_emptyBatch_returnsZeroCounts() {
        KeyVersion newKey = buildKeyVersion(NEW_KEY_ID);
        when(keyVersionRepository.findById(NEW_KEY_ID)).thenReturn(Optional.of(newKey));
        when(tokenVaultRepository.findActiveByKeyVersionId(eq(OLD_KEY_ID), any(Pageable.class)))
                .thenReturn(List.of());

        RotationBatchProcessor.BatchResult result = processor.processBatch(OLD_KEY_ID, NEW_KEY_ID, 10);

        assertThat(result.processedCount()).isZero();
        assertThat(result.failedCount()).isZero();
        assertThat(result.totalFetched()).isZero();
        verify(cipher, never()).unwrapDek(any(), any());
        verify(cipher, never()).wrapDek(any(), any());
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    @Test
    void processBatch_singleToken_rewrapsAndSavesVault() {
        KeyVersion newKey = buildKeyVersion(NEW_KEY_ID);
        TokenVault vault = buildVault(TOKEN_ID_1, OLD_KEY_ID);
        stubKeyRingForBothVersions();
        when(cipher.unwrapDek(any(), any())).thenReturn(new byte[32]);
        when(cipher.wrapDek(any(), any())).thenReturn(new byte[60]);
        when(keyVersionRepository.findById(NEW_KEY_ID)).thenReturn(Optional.of(newKey));
        when(tokenVaultRepository.findActiveByKeyVersionId(eq(OLD_KEY_ID), any(Pageable.class)))
                .thenReturn(List.of(vault));
        when(tokenVaultRepository.save(vault)).thenReturn(vault);

        processor.processBatch(OLD_KEY_ID, NEW_KEY_ID, 10);

        verify(tokenVaultRepository).save(vault);
    }

    @Test
    void processBatch_singleToken_writesTokenReencryptedAuditEvent() {
        KeyVersion newKey = buildKeyVersion(NEW_KEY_ID);
        TokenVault vault = buildVault(TOKEN_ID_1, OLD_KEY_ID);
        stubKeyRingForBothVersions();
        when(cipher.unwrapDek(any(), any())).thenReturn(new byte[32]);
        when(cipher.wrapDek(any(), any())).thenReturn(new byte[60]);
        when(keyVersionRepository.findById(NEW_KEY_ID)).thenReturn(Optional.of(newKey));
        when(tokenVaultRepository.findActiveByKeyVersionId(eq(OLD_KEY_ID), any(Pageable.class)))
                .thenReturn(List.of(vault));
        when(tokenVaultRepository.save(vault)).thenReturn(vault);

        processor.processBatch(OLD_KEY_ID, NEW_KEY_ID, 10);

        ArgumentCaptor<AuditEventType> eventCaptor = ArgumentCaptor.forClass(AuditEventType.class);
        verify(auditLogger).logSuccess(eventCaptor.capture(), any(), any(), any(), any(), any());
        assertThat(eventCaptor.getValue()).isEqualTo(AuditEventType.TOKEN_REENCRYPTED);
    }

    @Test
    void processBatch_twoTokens_batchResultCountsCorrect() {
        KeyVersion newKey = buildKeyVersion(NEW_KEY_ID);
        TokenVault vault1 = buildVault(TOKEN_ID_1, OLD_KEY_ID);
        TokenVault vault2 = buildVault(TOKEN_ID_2, OLD_KEY_ID);
        stubKeyRingForBothVersions();
        when(cipher.unwrapDek(any(), any())).thenReturn(new byte[32]);
        when(cipher.wrapDek(any(), any())).thenReturn(new byte[60]);
        when(keyVersionRepository.findById(NEW_KEY_ID)).thenReturn(Optional.of(newKey));
        when(tokenVaultRepository.findActiveByKeyVersionId(eq(OLD_KEY_ID), any(Pageable.class)))
                .thenReturn(List.of(vault1, vault2));
        when(tokenVaultRepository.save(any(TokenVault.class))).thenAnswer(inv -> inv.getArgument(0));

        RotationBatchProcessor.BatchResult result = processor.processBatch(OLD_KEY_ID, NEW_KEY_ID, 10);

        assertThat(result.processedCount()).isEqualTo(2);
        assertThat(result.failedCount()).isZero();
        assertThat(result.totalFetched()).isEqualTo(2);
    }

    // ── Failure handling ──────────────────────────────────────────────────────

    @Test
    void processBatch_unwrapFailsForOneToken_continuesBatchAndCountsFailure() {
        KeyVersion newKey = buildKeyVersion(NEW_KEY_ID);
        TokenVault vault1 = buildVault(TOKEN_ID_1, OLD_KEY_ID);
        TokenVault vault2 = buildVault(TOKEN_ID_2, OLD_KEY_ID);
        stubKeyRingForBothVersions();
        // First token fails during DEK unwrap, second succeeds (chained stubs)
        when(cipher.unwrapDek(any(), any()))
                .thenThrow(new RuntimeException("AES-GCM auth tag mismatch"))
                .thenReturn(new byte[32]);
        when(cipher.wrapDek(any(), any())).thenReturn(new byte[60]);
        when(keyVersionRepository.findById(NEW_KEY_ID)).thenReturn(Optional.of(newKey));
        when(tokenVaultRepository.findActiveByKeyVersionId(eq(OLD_KEY_ID), any(Pageable.class)))
                .thenReturn(List.of(vault1, vault2));
        when(tokenVaultRepository.save(any(TokenVault.class))).thenAnswer(inv -> inv.getArgument(0));

        RotationBatchProcessor.BatchResult result = processor.processBatch(OLD_KEY_ID, NEW_KEY_ID, 10);

        assertThat(result.processedCount()).isEqualTo(1);
        assertThat(result.failedCount()).isEqualTo(1);
    }

    @Test
    void processBatch_rewrapFailsForOneToken_writesReEncryptionFailureAudit() {
        KeyVersion newKey = buildKeyVersion(NEW_KEY_ID);
        TokenVault vault1 = buildVault(TOKEN_ID_1, OLD_KEY_ID);
        stubKeyRingForBothVersions();
        when(cipher.unwrapDek(any(), any()))
                .thenThrow(new RuntimeException("AES-GCM failure"));
        when(keyVersionRepository.findById(NEW_KEY_ID)).thenReturn(Optional.of(newKey));
        when(tokenVaultRepository.findActiveByKeyVersionId(eq(OLD_KEY_ID), any(Pageable.class)))
                .thenReturn(List.of(vault1));

        processor.processBatch(OLD_KEY_ID, NEW_KEY_ID, 10);

        ArgumentCaptor<AuditEventType> eventCaptor = ArgumentCaptor.forClass(AuditEventType.class);
        verify(auditLogger).logFailure(eventCaptor.capture(), any(), any(), any(), any(), any(), any());
        assertThat(eventCaptor.getValue()).isEqualTo(AuditEventType.RE_ENCRYPTION_FAILURE);
    }

    @Test
    void reencryptSingleToken_optimisticLockFailure_propagatesException() {
        // reencryptSingleToken runs in REQUIRES_NEW — the caller (processBatch) catches this
        KeyVersion newKey = buildKeyVersion(NEW_KEY_ID);
        TokenVault vault = buildVault(TOKEN_ID_1, OLD_KEY_ID);
        stubKeyRingForBothVersions();
        when(cipher.unwrapDek(any(), any())).thenReturn(new byte[32]);
        when(cipher.wrapDek(any(), any())).thenReturn(new byte[60]);
        when(tokenVaultRepository.save(vault))
                .thenThrow(new ObjectOptimisticLockingFailureException(TokenVault.class, TOKEN_ID_1));

        // reencryptSingleToken itself propagates the exception — processBatch catches it
        org.junit.jupiter.api.Assertions.assertThrows(
                ObjectOptimisticLockingFailureException.class,
                () -> processor.reencryptSingleToken(vault, OLD_KEY_ID, NEW_KEY_ID, newKey));
    }

    // ── BatchResult ───────────────────────────────────────────────────────────

    @Test
    void batchResult_isPartialPage_trueWhenFetchedLessThanBatchSize() {
        RotationBatchProcessor.BatchResult result = new RotationBatchProcessor.BatchResult(3, 0, 3);
        assertThat(result.isPartialPage(10)).isTrue();
    }

    @Test
    void batchResult_isPartialPage_falseWhenFetchedEqualsBatchSize() {
        RotationBatchProcessor.BatchResult result = new RotationBatchProcessor.BatchResult(10, 0, 10);
        assertThat(result.isPartialPage(10)).isFalse();
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /**
     * Stubs {@link InMemoryKeyRing#getByVersion} to return real {@link KeyMaterial} instances
     * for both the old and new key version IDs.
     *
     * <p>The KEK bytes are all-zero 32-byte arrays — the cipher itself is mocked so the
     * actual key bytes are never used for cryptography in these unit tests.
     */
    private void stubKeyRingForBothVersions() {
        KeyMaterial oldMaterial = new KeyMaterial(OLD_KEY_ID.toString(), OLD_KEK, Instant.now().plusSeconds(3600));
        KeyMaterial newMaterial = new KeyMaterial(NEW_KEY_ID.toString(), NEW_KEK, Instant.now().plusSeconds(3600));
        when(keyRing.getByVersion(OLD_KEY_ID.toString())).thenReturn(oldMaterial);
        when(keyRing.getByVersion(NEW_KEY_ID.toString())).thenReturn(newMaterial);
    }

    private KeyVersion buildKeyVersion(UUID id) {
        KeyVersion kv = KeyVersion.builder()
                .kmsKeyId("local-dev-key")
                .kmsProvider("LOCAL_DEV")
                .keyAlias("test-key")
                .encryptedKekBlob("local-dev-key")
                .status(KeyStatus.ACTIVE)
                .activatedAt(Instant.now().minusSeconds(3600))
                .rotateBy(Instant.now().plusSeconds(86400))
                .createdBy("test")
                .checksum("checksum")
                .build();
        try {
            Field idField = KeyVersion.class.getDeclaredField("id");
            idField.setAccessible(true);
            idField.set(kv, id);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
        return kv;
    }

    private TokenVault buildVault(UUID tokenId, UUID keyVersionId) {
        KeyVersion kv = buildKeyVersion(keyVersionId);
        TokenVault vault = TokenVault.builder()
                .token("tok-" + tokenId)
                .encryptedPan(new byte[]{1, 2, 3})
                .iv(new byte[12])
                .authTag(new byte[16])
                .encryptedDek(new byte[60])
                .keyVersion(kv)
                .panHash("hash")
                .tokenType(TokenType.ONE_TIME)
                .lastFour("1111")
                .cardScheme("VISA")
                .expiryMonth((short) 12)
                .expiryYear((short) 2027)
                .merchantId("MERCHANT_001")
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();
        try {
            Field idField = TokenVault.class.getDeclaredField("tokenId");
            idField.setAccessible(true);
            idField.set(vault, tokenId);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
        return vault;
    }
}
