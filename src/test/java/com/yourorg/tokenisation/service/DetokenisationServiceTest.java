package com.yourorg.tokenisation.service;

import com.yourorg.tokenisation.api.response.DetokeniseResponse;
import com.yourorg.tokenisation.audit.AuditEventType;
import com.yourorg.tokenisation.audit.AuditLogger;
import com.yourorg.tokenisation.crypto.AesGcmCipher;
import com.yourorg.tokenisation.crypto.EncryptionException;
import com.yourorg.tokenisation.crypto.InMemoryKekKeyRing;
import com.yourorg.tokenisation.crypto.KeyMaterial;
import com.yourorg.tokenisation.crypto.KeyVersionNotFoundException;
import com.yourorg.tokenisation.domain.KeyStatus;
import com.yourorg.tokenisation.domain.KeyVersion;
import com.yourorg.tokenisation.domain.TokenVault;
import com.yourorg.tokenisation.exception.KeyIntegrityException;
import com.yourorg.tokenisation.exception.TokenNotFoundException;
import com.yourorg.tokenisation.repository.TokenVaultRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;

import javax.crypto.AEADBadTagException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link DetokenisationService}.
 *
 * <p>All collaborators are mocked. Tests cover:
 * <ul>
 *   <li>Happy path — correct PAN returned, card metadata present, audit logged
 *   <li>Token not found — {@link TokenNotFoundException}
 *   <li>Expired token — {@link TokenNotFoundException}
 *   <li>Compromised key — {@link KeyIntegrityException} + TAMPER_ALERT audit
 *   <li>Tampered ciphertext (GCM auth failure) — {@link KeyIntegrityException} + TAMPER_ALERT audit
 *   <li>Key version not in ring — {@link KeyVersionNotFoundException}
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class DetokenisationServiceTest {

    private static final String TOKEN_VALUE = "some-opaque-token-uuid";
    private static final String PAN = "4111111111111111";
    private static final byte[] PAN_BYTES = PAN.getBytes(StandardCharsets.UTF_8);
    private static final byte[] DUMMY_KEK = new byte[32];
    private static final UUID KEY_VERSION_UUID = UUID.randomUUID();
    private static final String KEY_VERSION_ID = KEY_VERSION_UUID.toString();

    @Mock private AesGcmCipher cipher;
    @Mock private InMemoryKekKeyRing keyRing;
    @Mock private TokenVaultRepository tokenVaultRepository;
    @Mock private AuditLogger auditLogger;

    private DetokenisationService service;

    @BeforeEach
    void setUp() {
        service = new DetokenisationService(cipher, keyRing, tokenVaultRepository, auditLogger);
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    @Test
    void detokenise_validToken_returnsCorrectPan() {
        TokenVault vault = buildVault(Instant.now().plusSeconds(3600));
        KeyMaterial keyMaterial = buildKeyMaterial(KeyStatus.ACTIVE);
        when(tokenVaultRepository.findActiveByToken(TOKEN_VALUE)).thenReturn(Optional.of(vault));
        when(keyRing.getByVersion(KEY_VERSION_ID)).thenReturn(keyMaterial);
        when(cipher.decrypt(any(), any(), any(), any(), any())).thenReturn(PAN_BYTES.clone());

        DetokeniseResponse response = service.detokenise(TOKEN_VALUE);

        assertThat(response.getPan()).isEqualTo(PAN);
    }

    @Test
    void detokenise_validToken_returnsCardMetadataFromVault() {
        TokenVault vault = buildVault(Instant.now().plusSeconds(3600));
        KeyMaterial keyMaterial = buildKeyMaterial(KeyStatus.ACTIVE);
        when(tokenVaultRepository.findActiveByToken(TOKEN_VALUE)).thenReturn(Optional.of(vault));
        when(keyRing.getByVersion(KEY_VERSION_ID)).thenReturn(keyMaterial);
        when(cipher.decrypt(any(), any(), any(), any(), any())).thenReturn(PAN_BYTES.clone());

        DetokeniseResponse response = service.detokenise(TOKEN_VALUE);

        assertThat(response.getLastFour()).isEqualTo("1111");
        assertThat(response.getCardScheme()).isEqualTo("MC");
        assertThat(response.getExpiryMonth()).isEqualTo(12);
        assertThat(response.getExpiryYear()).isEqualTo(2027);
    }

    @Test
    void detokenise_validToken_writesSuccessAuditRecord() {
        TokenVault vault = buildVault(Instant.now().plusSeconds(3600));
        KeyMaterial keyMaterial = buildKeyMaterial(KeyStatus.ACTIVE);
        when(tokenVaultRepository.findActiveByToken(TOKEN_VALUE)).thenReturn(Optional.of(vault));
        when(keyRing.getByVersion(KEY_VERSION_ID)).thenReturn(keyMaterial);
        when(cipher.decrypt(any(), any(), any(), any(), any())).thenReturn(PAN_BYTES.clone());

        service.detokenise(TOKEN_VALUE);

        ArgumentCaptor<AuditEventType> eventCaptor = ArgumentCaptor.forClass(AuditEventType.class);
        verify(auditLogger).logSuccess(eventCaptor.capture(), any(), any(), any(), any());
        assertThat(eventCaptor.getValue()).isEqualTo(AuditEventType.DETOKENISE);
    }

    @Test
    void detokenise_nullExpiresAt_doesNotThrow() {
        TokenVault vault = buildVault(null);
        KeyMaterial keyMaterial = buildKeyMaterial(KeyStatus.ACTIVE);
        when(tokenVaultRepository.findActiveByToken(TOKEN_VALUE)).thenReturn(Optional.of(vault));
        when(keyRing.getByVersion(KEY_VERSION_ID)).thenReturn(keyMaterial);
        when(cipher.decrypt(any(), any(), any(), any(), any())).thenReturn(PAN_BYTES.clone());

        assertThat(service.detokenise(TOKEN_VALUE).getPan()).isEqualTo(PAN);
    }

    @Test
    void detokenise_rotatingKeyStatus_allowsDecryption() {
        TokenVault vault = buildVault(Instant.now().plusSeconds(3600));
        KeyMaterial rotatingMaterial = buildKeyMaterial(KeyStatus.ROTATING);
        when(tokenVaultRepository.findActiveByToken(TOKEN_VALUE)).thenReturn(Optional.of(vault));
        when(keyRing.getByVersion(KEY_VERSION_ID)).thenReturn(rotatingMaterial);
        when(cipher.decrypt(any(), any(), any(), any(), any())).thenReturn(PAN_BYTES.clone());

        assertThat(service.detokenise(TOKEN_VALUE).getPan()).isEqualTo(PAN);
    }

    // ── Token not found ───────────────────────────────────────────────────────

    @Test
    void detokenise_unknownToken_throwsTokenNotFoundException() {
        when(tokenVaultRepository.findActiveByToken(TOKEN_VALUE)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.detokenise(TOKEN_VALUE))
                .isInstanceOf(TokenNotFoundException.class);
    }

    @Test
    void detokenise_unknownToken_noAuditWritten() {
        when(tokenVaultRepository.findActiveByToken(TOKEN_VALUE)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.detokenise(TOKEN_VALUE))
                .isInstanceOf(TokenNotFoundException.class);

        verify(auditLogger, never()).logSuccess(any(), any(), any(), any(), any());
        verify(auditLogger, never()).logFailure(any(), any(), any(), any(), any(), any());
    }

    // ── Expired token ─────────────────────────────────────────────────────────

    @Test
    void detokenise_expiredToken_throwsTokenNotFoundException() {
        TokenVault vault = buildVault(Instant.now().minusSeconds(60));
        when(tokenVaultRepository.findActiveByToken(TOKEN_VALUE)).thenReturn(Optional.of(vault));

        assertThatThrownBy(() -> service.detokenise(TOKEN_VALUE))
                .isInstanceOf(TokenNotFoundException.class);

        verify(cipher, never()).decrypt(any(), any(), any(), any(), any());
    }

    // ── Compromised key ──────────────────────────────────────────────────────

    @Test
    void detokenise_compromisedKey_throwsKeyIntegrityException() {
        TokenVault vault = buildVault(Instant.now().plusSeconds(3600));
        KeyMaterial compromisedMaterial = buildKeyMaterial(KeyStatus.COMPROMISED);
        when(tokenVaultRepository.findActiveByToken(TOKEN_VALUE)).thenReturn(Optional.of(vault));
        when(keyRing.getByVersion(KEY_VERSION_ID)).thenReturn(compromisedMaterial);

        assertThatThrownBy(() -> service.detokenise(TOKEN_VALUE))
                .isInstanceOf(KeyIntegrityException.class)
                .hasMessageContaining("COMPROMISED");
    }

    @Test
    void detokenise_compromisedKey_writesTamperAlertAudit() {
        TokenVault vault = buildVault(Instant.now().plusSeconds(3600));
        KeyMaterial compromisedMaterial = buildKeyMaterial(KeyStatus.COMPROMISED);
        when(tokenVaultRepository.findActiveByToken(TOKEN_VALUE)).thenReturn(Optional.of(vault));
        when(keyRing.getByVersion(KEY_VERSION_ID)).thenReturn(compromisedMaterial);

        assertThatThrownBy(() -> service.detokenise(TOKEN_VALUE))
                .isInstanceOf(KeyIntegrityException.class);

        ArgumentCaptor<AuditEventType> eventCaptor = ArgumentCaptor.forClass(AuditEventType.class);
        verify(auditLogger).logFailure(eventCaptor.capture(), any(), any(), any(), any(), any());
        assertThat(eventCaptor.getValue()).isEqualTo(AuditEventType.TAMPER_ALERT);
    }

    @Test
    void detokenise_compromisedKey_cipherNeverCalled() {
        TokenVault vault = buildVault(Instant.now().plusSeconds(3600));
        KeyMaterial compromisedMaterial = buildKeyMaterial(KeyStatus.COMPROMISED);
        when(tokenVaultRepository.findActiveByToken(TOKEN_VALUE)).thenReturn(Optional.of(vault));
        when(keyRing.getByVersion(KEY_VERSION_ID)).thenReturn(compromisedMaterial);

        assertThatThrownBy(() -> service.detokenise(TOKEN_VALUE))
                .isInstanceOf(KeyIntegrityException.class);

        verify(cipher, never()).decrypt(any(), any(), any(), any(), any());
    }

    // ── Tampered ciphertext (GCM auth tag failure) ────────────────────────────

    @Test
    void detokenise_tamperedCiphertext_throwsKeyIntegrityException() {
        TokenVault vault = buildVault(Instant.now().plusSeconds(3600));
        KeyMaterial keyMaterial = buildKeyMaterial(KeyStatus.ACTIVE);
        EncryptionException tamperException =
                new EncryptionException("GCM authentication tag verification failed", new AEADBadTagException());
        when(tokenVaultRepository.findActiveByToken(TOKEN_VALUE)).thenReturn(Optional.of(vault));
        when(keyRing.getByVersion(KEY_VERSION_ID)).thenReturn(keyMaterial);
        when(cipher.decrypt(any(), any(), any(), any(), any())).thenThrow(tamperException);

        assertThatThrownBy(() -> service.detokenise(TOKEN_VALUE))
                .isInstanceOf(KeyIntegrityException.class)
                .hasMessageContaining("authentication tag");
    }

    @Test
    void detokenise_tamperedCiphertext_writesTamperAlertAudit() {
        TokenVault vault = buildVault(Instant.now().plusSeconds(3600));
        KeyMaterial keyMaterial = buildKeyMaterial(KeyStatus.ACTIVE);
        EncryptionException tamperException =
                new EncryptionException("GCM authentication tag verification failed", new AEADBadTagException());
        when(tokenVaultRepository.findActiveByToken(TOKEN_VALUE)).thenReturn(Optional.of(vault));
        when(keyRing.getByVersion(KEY_VERSION_ID)).thenReturn(keyMaterial);
        when(cipher.decrypt(any(), any(), any(), any(), any())).thenThrow(tamperException);

        assertThatThrownBy(() -> service.detokenise(TOKEN_VALUE))
                .isInstanceOf(KeyIntegrityException.class);

        ArgumentCaptor<AuditEventType> eventCaptor = ArgumentCaptor.forClass(AuditEventType.class);
        verify(auditLogger).logFailure(eventCaptor.capture(), any(), any(), any(), any(), any());
        assertThat(eventCaptor.getValue()).isEqualTo(AuditEventType.TAMPER_ALERT);
    }

    // ── Key version not in ring ───────────────────────────────────────────────

    @Test
    void detokenise_keyVersionNotInRing_throwsKeyVersionNotFoundException() {
        TokenVault vault = buildVault(Instant.now().plusSeconds(3600));
        when(tokenVaultRepository.findActiveByToken(TOKEN_VALUE)).thenReturn(Optional.of(vault));
        when(keyRing.getByVersion(KEY_VERSION_ID))
                .thenThrow(new KeyVersionNotFoundException(KEY_VERSION_ID));

        assertThatThrownBy(() -> service.detokenise(TOKEN_VALUE))
                .isInstanceOf(KeyVersionNotFoundException.class);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /**
     * Builds a {@link TokenVault} stub with the given expiry.
     * Pass {@code null} for no expiry; pass a past instant to test expiry enforcement.
     */
    private TokenVault buildVault(Instant expiresAt) {
        KeyVersion keyVersion = buildKeyVersion();
        return TokenVault.builder()
                .token(TOKEN_VALUE)
                .encryptedPan(new byte[]{1, 2, 3})
                .iv(new byte[12])
                .authTag(new byte[16])
                .encryptedDek(new byte[60])
                .keyVersion(keyVersion)
                .panHash("hash")
                .lastFour("1111")
                .cardScheme("MC")
                .expiryMonth((short) 12)
                .expiryYear((short) 2027)
                .createdAt(Instant.now())
                .expiresAt(expiresAt)
                .build();
    }

    /**
     * Builds a {@link KeyVersion} stub with the fixed {@link #KEY_VERSION_UUID}.
     */
    private KeyVersion buildKeyVersion() {
        KeyVersion keyVersion = KeyVersion.builder()
                .kmsKeyId("test-key-id")
                .kmsProvider("LOCAL_DEV")
                .keyAlias("test-key")
                .encryptedKekBlob("ignored")
                .status(KeyStatus.ACTIVE)
                .rotateBy(Instant.now().plusSeconds(86400))
                .activatedAt(Instant.now().minusSeconds(3600))
                .createdBy("test")
                .build();
        try {
            Field idField = KeyVersion.class.getDeclaredField("id");
            idField.setAccessible(true);
            idField.set(keyVersion, KEY_VERSION_UUID);
        } catch (ReflectiveOperationException reflectionException) {
            throw new RuntimeException("Failed to set id field on KeyVersion in test", reflectionException);
        }
        return keyVersion;
    }

    /**
     * Builds a {@link KeyMaterial} with the given lifecycle status.
     */
    private KeyMaterial buildKeyMaterial(KeyStatus status) {
        KeyMaterial base = new KeyMaterial(KEY_VERSION_ID, DUMMY_KEK, Instant.now().plusSeconds(86400));
        return switch (status) {
            case ACTIVE, ROTATING -> base;
            case COMPROMISED -> base.asCompromised();
            case RETIRED -> base.asRetired();
        };
    }
}
