package com.yourorg.tokenisation.service;

import com.yourorg.tokenisation.api.request.TokeniseRequest;
import com.yourorg.tokenisation.api.response.TokeniseResponse;
import com.yourorg.tokenisation.audit.AuditEventType;
import com.yourorg.tokenisation.audit.AuditLogger;
import com.yourorg.tokenisation.crypto.AesGcmCipher;
import com.yourorg.tokenisation.crypto.EncryptResult;
import com.yourorg.tokenisation.crypto.InMemoryKeyRing;
import com.yourorg.tokenisation.crypto.KeyMaterial;
import com.yourorg.tokenisation.crypto.PanHasher;
import com.yourorg.tokenisation.domain.KeyStatus;
import com.yourorg.tokenisation.domain.KeyVersion;
import com.yourorg.tokenisation.domain.TokenType;
import com.yourorg.tokenisation.domain.TokenVault;
import com.yourorg.tokenisation.exception.PanValidationException;
import com.yourorg.tokenisation.exception.TokenisationException;
import com.yourorg.tokenisation.repository.KeyVersionRepository;
import com.yourorg.tokenisation.repository.TokenVaultRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link TokenisationService}.
 *
 * <p>All collaborators are mocked. Tests cover the documented
 * {@code tokenise} method behaviours:
 * <ul>
 *   <li>Happy path — new ONE_TIME and RECURRING token creation
 *   <li>De-dup — existing RECURRING token is returned without new vault record
 *   <li>PAN validation — null, blank, non-numeric, Luhn-invalid
 *   <li>Key ring empty — {@link IllegalStateException} from {@link InMemoryKeyRing#getActive()}
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class TokenisationServiceTest {

    private static final String VALID_PAN = "4111111111111111";
    private static final String VALID_PAN_HASH = "test-pan-hash-value";
    private static final String MERCHANT_ID = "MERCHANT_001";
    private static final long TOKEN_TTL_DAYS = 1825L;

    @Mock private AesGcmCipher cipher;
    @Mock private PanHasher panHasher;
    @Mock private InMemoryKeyRing keyRing;
    @Mock private TokenVaultRepository tokenVaultRepository;
    @Mock private KeyVersionRepository keyVersionRepository;
    @Mock private AuditLogger auditLogger;

    private TokenisationService service;

    @BeforeEach
    void setUp() {
        service = new TokenisationService(cipher, panHasher, keyRing,
                tokenVaultRepository, keyVersionRepository, auditLogger, TOKEN_TTL_DAYS);
    }

    // ── Happy path — ONE_TIME ─────────────────────────────────────────────────

    @Test
    void tokenise_oneTimePan_persistsNewVaultRecordAndReturnsToken() {
        TokeniseRequest request = buildRequest(VALID_PAN, TokenType.ONE_TIME);
        KeyMaterial activeKey = buildKeyMaterial();
        KeyVersion activeVersion = buildKeyVersion();
        EncryptResult encryptResult = buildEncryptResult();

        when(panHasher.hash(VALID_PAN)).thenReturn(VALID_PAN_HASH);
        when(keyRing.getActive()).thenReturn(activeKey);
        when(keyVersionRepository.findActiveOrThrow()).thenReturn(activeVersion);
        when(cipher.encrypt(any(), any())).thenReturn(encryptResult);
        when(tokenVaultRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        TokeniseResponse response = service.tokenise(request);

        assertThat(response.getToken()).isNotBlank();
        assertThat(response.getTokenType()).isEqualTo(TokenType.ONE_TIME);
        assertThat(response.getLastFour()).isEqualTo("1111");
        assertThat(response.getCardScheme()).isEqualTo("VISA");
        verify(tokenVaultRepository).save(any(TokenVault.class));
        verify(auditLogger).logSuccess(eq(AuditEventType.TOKENISE), any(), eq(MERCHANT_ID), any(), any(), any());
    }

    // ── Happy path — RECURRING (new token) ──────────────────────────────────

    @Test
    void tokenise_recurringPanWithNoExistingToken_persistsNewVaultRecord() {
        TokeniseRequest request = buildRequest(VALID_PAN, TokenType.RECURRING);
        KeyMaterial activeKey = buildKeyMaterial();
        KeyVersion activeVersion = buildKeyVersion();
        EncryptResult encryptResult = buildEncryptResult();

        when(panHasher.hash(VALID_PAN)).thenReturn(VALID_PAN_HASH);
        when(tokenVaultRepository.findActiveRecurringByPanHashAndMerchant(VALID_PAN_HASH, MERCHANT_ID))
                .thenReturn(Optional.empty());
        when(keyRing.getActive()).thenReturn(activeKey);
        when(keyVersionRepository.findActiveOrThrow()).thenReturn(activeVersion);
        when(cipher.encrypt(any(), any())).thenReturn(encryptResult);
        when(tokenVaultRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        TokeniseResponse response = service.tokenise(request);

        assertThat(response.getTokenType()).isEqualTo(TokenType.RECURRING);
        verify(tokenVaultRepository).save(any(TokenVault.class));
    }

    // ── De-dup — RECURRING ────────────────────────────────────────────────────

    @Test
    void tokenise_recurringPanWithExistingToken_returnsSameTokenWithoutNewVaultRecord() {
        TokeniseRequest request = buildRequest(VALID_PAN, TokenType.RECURRING);
        TokenVault existingVault = buildExistingVault(TokenType.RECURRING);

        when(panHasher.hash(VALID_PAN)).thenReturn(VALID_PAN_HASH);
        when(tokenVaultRepository.findActiveRecurringByPanHashAndMerchant(VALID_PAN_HASH, MERCHANT_ID))
                .thenReturn(Optional.of(existingVault));

        TokeniseResponse response = service.tokenise(request);

        assertThat(response.getToken()).isEqualTo(existingVault.getToken());
        assertThat(response.getTokenType()).isEqualTo(TokenType.RECURRING);
        // No new vault record must be written for de-dup
        verify(tokenVaultRepository, never()).save(any());
        // No new encryption must happen
        verify(cipher, never()).encrypt(any(), any());
        verify(auditLogger).logSuccess(eq(AuditEventType.TOKENISE), eq(existingVault.getTokenId()),
                eq(MERCHANT_ID), any(), any(), any());
    }

    @Test
    void tokenise_recurringPanCalledTwice_returnsSameTokenOnSecondCall() {
        TokeniseRequest request = buildRequest(VALID_PAN, TokenType.RECURRING);
        TokenVault existingVault = buildExistingVault(TokenType.RECURRING);

        when(panHasher.hash(VALID_PAN)).thenReturn(VALID_PAN_HASH);
        when(tokenVaultRepository.findActiveRecurringByPanHashAndMerchant(VALID_PAN_HASH, MERCHANT_ID))
                .thenReturn(Optional.of(existingVault));

        TokeniseResponse first = service.tokenise(request);
        TokeniseResponse second = service.tokenise(request);

        assertThat(first.getToken()).isEqualTo(second.getToken());
    }

    @Test
    void tokenise_oneTimePanCalledTwice_returnsDifferentTokens() {
        TokeniseRequest request = buildRequest(VALID_PAN, TokenType.ONE_TIME);
        KeyMaterial activeKey = buildKeyMaterial();
        KeyVersion activeVersion = buildKeyVersion();
        EncryptResult encryptResult = buildEncryptResult();

        when(panHasher.hash(VALID_PAN)).thenReturn(VALID_PAN_HASH);
        when(keyRing.getActive()).thenReturn(activeKey);
        when(keyVersionRepository.findActiveOrThrow()).thenReturn(activeVersion);
        when(cipher.encrypt(any(), any())).thenReturn(encryptResult);
        when(tokenVaultRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        TokeniseResponse first = service.tokenise(request);
        TokeniseResponse second = service.tokenise(request);

        // ONE_TIME tokens always produce a new UUID — they must differ
        assertThat(first.getToken()).isNotEqualTo(second.getToken());
    }

    // ── PAN validation — null ────────────────────────────────────────────────

    @Test
    void tokenise_nullPan_throwsPanValidationException() {
        TokeniseRequest request = buildRequest(null, TokenType.ONE_TIME);

        assertThatThrownBy(() -> service.tokenise(request))
                .isInstanceOf(PanValidationException.class)
                .hasMessageContaining("null or blank");

        verify(tokenVaultRepository, never()).save(any());
        verify(auditLogger).logFailure(eq(AuditEventType.TOKENISE_FAILURE),
                any(), eq(MERCHANT_ID), any(), any(), anyString(), any());
    }

    @Test
    void tokenise_blankPan_throwsPanValidationException() {
        TokeniseRequest request = buildRequest("   ", TokenType.ONE_TIME);

        assertThatThrownBy(() -> service.tokenise(request))
                .isInstanceOf(PanValidationException.class)
                .hasMessageContaining("null or blank");

        verify(tokenVaultRepository, never()).save(any());
    }

    // ── PAN validation — format ───────────────────────────────────────────────

    @ParameterizedTest
    @ValueSource(strings = {"411111111111", "1234", "abcdefghijklmnop", "4111-1111-1111-1111"})
    void tokenise_invalidPanFormat_throwsPanValidationException(String invalidPan) {
        TokeniseRequest request = buildRequest(invalidPan, TokenType.ONE_TIME);

        // PanHasher must not be called before validation
        assertThatThrownBy(() -> service.tokenise(request))
                .isInstanceOf(PanValidationException.class);

        verify(panHasher, never()).hash(anyString());
        verify(tokenVaultRepository, never()).save(any());
    }

    // ── PAN validation — Luhn ────────────────────────────────────────────────

    @Test
    void tokenise_luhnInvalidPan_throwsPanValidationException() {
        // 4111111111111112 fails Luhn (last digit changed from 1 to 2)
        TokeniseRequest request = buildRequest("4111111111111112", TokenType.ONE_TIME);

        assertThatThrownBy(() -> service.tokenise(request))
                .isInstanceOf(PanValidationException.class)
                .hasMessageContaining("Luhn");

        verify(tokenVaultRepository, never()).save(any());
    }

    // ── Key ring empty ────────────────────────────────────────────────────────

    @Test
    void tokenise_keyRingHasNoActiveKey_throwsTokenisationException() {
        TokeniseRequest request = buildRequest(VALID_PAN, TokenType.ONE_TIME);

        when(panHasher.hash(VALID_PAN)).thenReturn(VALID_PAN_HASH);
        when(keyRing.getActive()).thenThrow(new IllegalStateException("No active key version has been promoted in the key ring"));

        assertThatThrownBy(() -> service.tokenise(request))
                .isInstanceOf(TokenisationException.class);

        verify(tokenVaultRepository, never()).save(any());
        verify(auditLogger).logFailure(eq(AuditEventType.TOKENISE_FAILURE),
                any(), eq(MERCHANT_ID), any(), any(), anyString(), any());
    }

    // ── Audit log on failure ──────────────────────────────────────────────────

    @Test
    void tokenise_encryptionFails_writesFailureAuditBeforeRethrowing() {
        TokeniseRequest request = buildRequest(VALID_PAN, TokenType.ONE_TIME);
        KeyMaterial activeKey = buildKeyMaterial();
        KeyVersion activeVersion = buildKeyVersion();

        when(panHasher.hash(VALID_PAN)).thenReturn(VALID_PAN_HASH);
        when(keyRing.getActive()).thenReturn(activeKey);
        when(keyVersionRepository.findActiveOrThrow()).thenReturn(activeVersion);
        when(cipher.encrypt(any(), any())).thenThrow(
                new com.yourorg.tokenisation.crypto.EncryptionException("AES-GCM encryption failed"));

        assertThatThrownBy(() -> service.tokenise(request))
                .isInstanceOf(TokenisationException.class);

        ArgumentCaptor<String> failureReasonCaptor = ArgumentCaptor.forClass(String.class);
        verify(auditLogger).logFailure(eq(AuditEventType.TOKENISE_FAILURE), any(),
                eq(MERCHANT_ID), any(), any(), failureReasonCaptor.capture(), any());
        assertThat(failureReasonCaptor.getValue()).doesNotContain(VALID_PAN);
    }

    // ── Null request guard ────────────────────────────────────────────────────

    @Test
    void tokenise_nullRequest_throwsNullPointerException() {
        assertThatThrownBy(() -> service.tokenise(null))
                .isInstanceOf(NullPointerException.class);
    }

    // ── Test helpers ──────────────────────────────────────────────────────────

    private TokeniseRequest buildRequest(String pan, TokenType tokenType) {
        TokeniseRequest request = new TokeniseRequest();
        request.setPan(pan);
        request.setTokenType(tokenType);
        request.setMerchantId(MERCHANT_ID);
        request.setCardScheme("VISA");
        request.setExpiryMonth(12);
        request.setExpiryYear(2027);
        return request;
    }

    private KeyMaterial buildKeyMaterial() {
        byte[] kek = new byte[32];
        return new KeyMaterial(UUID.randomUUID().toString(), kek, Instant.now().plusSeconds(3600));
    }

    private KeyVersion buildKeyVersion() {
        return KeyVersion.builder()
                .kmsKeyId("local-dev-key")
                .kmsProvider("LOCAL_DEV")
                .keyAlias("test-key")
                .encryptedKekBlob("ignored")
                .status(KeyStatus.ACTIVE)
                .activatedAt(Instant.now())
                .rotateBy(Instant.now().plusSeconds(365L * 24 * 60 * 60))
                .createdBy("test")
                .checksum("test-checksum")
                .build();
    }

    private EncryptResult buildEncryptResult() {
        byte[] ciphertext = new byte[16];
        byte[] iv = new byte[12];
        byte[] authTag = new byte[16];
        byte[] encryptedDek = new byte[60];
        return new EncryptResult(ciphertext, iv, authTag, encryptedDek);
    }

    private TokenVault buildExistingVault(TokenType tokenType) {
        return TokenVault.builder()
                .token(UUID.randomUUID().toString())
                .encryptedPan(new byte[16])
                .iv(new byte[12])
                .authTag(new byte[16])
                .encryptedDek(new byte[60])
                .keyVersion(buildKeyVersion())
                .panHash(VALID_PAN_HASH)
                .tokenType(tokenType)
                .lastFour("1111")
                .cardScheme("VISA")
                .expiryMonth((short) 12)
                .expiryYear((short) 2027)
                .merchantId(MERCHANT_ID)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(TOKEN_TTL_DAYS * 86400))
                .build();
    }
}
