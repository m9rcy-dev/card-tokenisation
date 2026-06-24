package com.yourorg.tokenisation.rotation;

import com.yourorg.tokenisation.audit.AuditEventType;
import com.yourorg.tokenisation.audit.AuditLogger;
import com.yourorg.tokenisation.config.RotationProperties;
import com.yourorg.tokenisation.crypto.AesGcmCipher;
import com.yourorg.tokenisation.crypto.InMemoryDekKeyRing;
import com.yourorg.tokenisation.crypto.KeyMaterial;
import com.yourorg.tokenisation.crypto.PanHasher;
import com.yourorg.tokenisation.domain.KeyStatus;
import com.yourorg.tokenisation.domain.KeyType;
import com.yourorg.tokenisation.domain.KeyVersion;
import com.yourorg.tokenisation.domain.TokenVault;
import com.yourorg.tokenisation.repository.TokenVaultRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Pageable;

import java.lang.reflect.Field;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link PanHashBatchProcessor}.
 *
 * <p>Verifies:
 * <ul>
 *   <li>Happy path: PAN is decrypted, re-hashed under new version, vault is saved,
 *       PAN_HASH_RECOMPUTED audit event written
 *   <li>Empty batch: no crypto calls, zero counts returned
 *   <li>COMPROMISED DEK: record is skipped with RE_HASH_SKIPPED_COMPROMISED_KEY audit
 *   <li>Single record failure: batch continues, failure logged
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class PanHashBatchProcessorTest {

    private static final UUID ROTATING_HMAC_ID = UUID.fromString("aaaaaaaa-0000-0000-0000-000000000001");
    private static final UUID NEW_HMAC_ID       = UUID.fromString("bbbbbbbb-0000-0000-0000-000000000002");
    private static final UUID DEK_VERSION_ID    = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final UUID TOKEN_ID          = UUID.fromString("cccccccc-0000-0000-0000-000000000001");

    private static final byte[] FAKE_DEK_BYTES  = new byte[32];
    private static final byte[] FAKE_ENCRYPTED  = new byte[]{1, 2, 3};
    private static final byte[] FAKE_IV         = new byte[12];
    private static final byte[] FAKE_AUTH_TAG   = new byte[16];
    private static final byte[] PAN_BYTES       = "4111111111111111".getBytes();
    private static final String NEW_HASH        = "new-hash-value";

    @Mock private TokenVaultRepository tokenVaultRepository;
    @Mock private InMemoryDekKeyRing dekRing;
    @Mock private AesGcmCipher cipher;
    @Mock private PanHasher panHasher;
    @Mock private AuditLogger auditLogger;

    private PanHashBatchProcessor processor;

    @BeforeEach
    void setUp() {
        RotationProperties props = new RotationProperties();
        props.getHmacBatch().setParallelism(1);
        props.getHmacBatch().setSize(10);

        processor = new PanHashBatchProcessor(
                tokenVaultRepository, dekRing, cipher, panHasher, auditLogger, props);
        // No Spring proxy in unit tests — self must point to the instance directly
        processor.self = processor;
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    @Test
    void processBatch_happyPath_rehashesAndSavesVaultRecord() {
        TokenVault vault = buildVault(DEK_VERSION_ID);
        KeyMaterial dekMaterial = new KeyMaterial(DEK_VERSION_ID.toString(), FAKE_DEK_BYTES,
                Instant.now().plusSeconds(3600));

        when(tokenVaultRepository.findActiveByHmacVersionId(
                eq(ROTATING_HMAC_ID), any(Pageable.class)))
                .thenReturn(List.of(vault));
        when(dekRing.getByVersion(DEK_VERSION_ID.toString())).thenReturn(dekMaterial);
        when(cipher.decrypt(any(), any(), any(), any())).thenReturn(PAN_BYTES.clone());
        when(panHasher.hashWithVersion(anyString(), eq(NEW_HMAC_ID.toString()))).thenReturn(NEW_HASH);
        when(tokenVaultRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        RotationBatchProcessor.BatchResult result =
                processor.processBatch(ROTATING_HMAC_ID, NEW_HMAC_ID, 10);

        assertThat(result.processedCount()).isEqualTo(1);
        assertThat(result.failedCount()).isZero();
        assertThat(vault.getPanHash()).isEqualTo(NEW_HASH);
        assertThat(vault.getHmacKeyVersionId()).isEqualTo(NEW_HMAC_ID);
        verify(tokenVaultRepository).save(vault);
        verify(auditLogger).logSuccess(eq(AuditEventType.PAN_HASH_RECOMPUTED),
                eq(vault.getTokenId()), any(), any(), any());
    }

    // ── Empty batch ───────────────────────────────────────────────────────────

    @Test
    void processBatch_emptyBatch_returnsZeroCounts() {
        when(tokenVaultRepository.findActiveByHmacVersionId(
                eq(ROTATING_HMAC_ID), any(Pageable.class)))
                .thenReturn(List.of());

        RotationBatchProcessor.BatchResult result =
                processor.processBatch(ROTATING_HMAC_ID, NEW_HMAC_ID, 10);

        assertThat(result.processedCount()).isZero();
        assertThat(result.failedCount()).isZero();
        assertThat(result.totalFetched()).isZero();
        verify(cipher, never()).decrypt(any(), any(), any(), any());
        verify(tokenVaultRepository, never()).save(any());
    }

    // ── Compromised DEK ───────────────────────────────────────────────────────

    @Test
    void rehashSingleVault_compromisedDek_skipsWithAuditAndNoDbWrite() {
        TokenVault vault = buildVault(DEK_VERSION_ID);
        KeyMaterial compromisedMaterial = new KeyMaterial(
                DEK_VERSION_ID.toString(), FAKE_DEK_BYTES, Instant.now().plusSeconds(3600))
                .asCompromised();

        when(dekRing.getByVersion(DEK_VERSION_ID.toString())).thenReturn(compromisedMaterial);

        processor.rehashSingleVault(vault, NEW_HMAC_ID);

        verify(cipher, never()).decrypt(any(), any(), any(), any());
        verify(tokenVaultRepository, never()).save(any());
        verify(auditLogger).logSuccess(
                eq(AuditEventType.RE_HASH_SKIPPED_COMPROMISED_KEY),
                eq(vault.getTokenId()), any(), any(), any());
    }

    // ── Single record failure ─────────────────────────────────────────────────

    @Test
    void processBatch_oneRecordFails_batchContinuesAndCountsFailure() {
        TokenVault vault = buildVault(DEK_VERSION_ID);
        KeyMaterial dekMaterial = new KeyMaterial(DEK_VERSION_ID.toString(), FAKE_DEK_BYTES,
                Instant.now().plusSeconds(3600));

        when(tokenVaultRepository.findActiveByHmacVersionId(
                eq(ROTATING_HMAC_ID), any(Pageable.class)))
                .thenReturn(List.of(vault));
        when(dekRing.getByVersion(DEK_VERSION_ID.toString())).thenReturn(dekMaterial);
        when(cipher.decrypt(any(), any(), any(), any()))
                .thenThrow(new RuntimeException("decryption failed"));

        RotationBatchProcessor.BatchResult result =
                processor.processBatch(ROTATING_HMAC_ID, NEW_HMAC_ID, 10);

        assertThat(result.processedCount()).isZero();
        assertThat(result.failedCount()).isEqualTo(1);
        verify(tokenVaultRepository, never()).save(any());
        verify(auditLogger).logFailure(eq(AuditEventType.RE_ENCRYPTION_FAILURE),
                any(), any(), any(), anyString(), any());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private TokenVault buildVault(UUID dekVersionId) {
        KeyVersion dekVersion = buildDekVersion(dekVersionId);
        TokenVault vault = TokenVault.builder()
                .token("some-token")
                .encryptedPan(FAKE_ENCRYPTED)
                .iv(FAKE_IV)
                .authTag(FAKE_AUTH_TAG)
                .keyVersion(dekVersion)
                .panHash("old-hash")
                .hmacKeyVersionId(ROTATING_HMAC_ID)
                .lastFour("1111")
                .cardScheme("VISA")
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();
        forceVaultId(vault, TOKEN_ID);
        return vault;
    }

    private static KeyVersion buildDekVersion(UUID id) {
        KeyVersion kv = KeyVersion.builder()
                .keyType(KeyType.DEK)
                .keyAlias("test-dek")
                .kmsKeyId("local-dev")
                .kmsProvider("LOCAL_DEV")
                .encryptedDekBlob(new byte[60])
                .status(KeyStatus.ACTIVE)
                .activatedAt(Instant.now())
                .rotateBy(Instant.now().plusSeconds(3600))
                .createdBy("test")
                .build();
        forceField(kv, "id", id);
        return kv;
    }

    private static void forceVaultId(TokenVault vault, UUID id) {
        forceField(vault, "tokenId", id);
    }

    private static void forceField(Object obj, String fieldName, Object value) {
        try {
            Field f = obj.getClass().getDeclaredField(fieldName);
            f.setAccessible(true);
            f.set(obj, value);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }
}
