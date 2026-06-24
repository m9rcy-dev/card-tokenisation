package com.yourorg.tokenisation.service;

import com.yourorg.tokenisation.api.request.CardReplacementRequest;
import com.yourorg.tokenisation.api.request.TokeniseRequest;
import com.yourorg.tokenisation.api.response.TokeniseResponse;
import com.yourorg.tokenisation.audit.AuditEventType;
import com.yourorg.tokenisation.audit.AuditLogger;
import com.yourorg.tokenisation.crypto.*;
import com.yourorg.tokenisation.domain.KeyStatus;
import com.yourorg.tokenisation.domain.KeyVersion;
import com.yourorg.tokenisation.domain.TokenVault;
import com.yourorg.tokenisation.exception.CardAlreadyTokenisedException;
import com.yourorg.tokenisation.exception.PanValidationException;
import com.yourorg.tokenisation.exception.TokenNotFoundException;
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
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link TokenisationService}.
 *
 * <p>All collaborators are mocked. Tests cover:
 * <ul>
 *   <li>Happy path — new token creation and de-dup return
 *   <li>De-dup — existing token for same PAN is returned without new vault record
 *   <li>PAN validation — null, blank, non-numeric, Luhn-invalid
 *   <li>Key ring empty — {@link IllegalStateException} from {@link InMemoryDekKeyRing#getActive()}
 *   <li>Token revocation — deactivation and audit
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class TokenisationServiceTest {

    private static final String VALID_PAN = "4111111111111111";
    private static final String VALID_PAN_HASH = "test-pan-hash-value";
    private static final String HMAC_VERSION_ID = "cccccccc-0000-0000-0000-000000000001";
    private static final HashResult VALID_HASH_RESULT = new HashResult(VALID_PAN_HASH, HMAC_VERSION_ID);
    private static final long TOKEN_TTL_DAYS = 1825L;

    @Mock private AesGcmCipher cipher;
    @Mock private PanHasher panHasher;
    @Mock private InMemoryDekKeyRing dekRing;
    @Mock private InMemoryHmacKeyRing hmacKeyRing;
    @Mock private TokenVaultRepository tokenVaultRepository;
    @Mock private KeyVersionRepository keyVersionRepository;
    @Mock private AuditLogger auditLogger;

    private TokenisationService service;

    @BeforeEach
    void setUp() {
        service = new TokenisationService(cipher, panHasher, dekRing, hmacKeyRing,
                tokenVaultRepository, keyVersionRepository, auditLogger, TOKEN_TTL_DAYS);
    }

    // ── Happy path — new token ───────────────────────────────────────────────

    @Test
    void tokenise_newPan_persistsNewVaultRecordAndReturnsToken() {
        TokeniseRequest request = buildRequest(VALID_PAN);
        KeyMaterial activeKey = buildKeyMaterial();
        KeyVersion activeVersion = buildKeyVersion();
        EncryptResult encryptResult = buildEncryptResult();

        when(panHasher.hash(VALID_PAN)).thenReturn(VALID_HASH_RESULT);
        when(tokenVaultRepository.findActiveByPanHash(VALID_PAN_HASH)).thenReturn(Optional.empty());
        when(dekRing.getActive()).thenReturn(activeKey);
        when(keyVersionRepository.findById(any(UUID.class))).thenReturn(Optional.of(activeVersion));
        when(cipher.encrypt(any(), any())).thenReturn(encryptResult);
        when(tokenVaultRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        TokeniseResponse response = service.tokenise(request);

        assertThat(response.getToken()).isNotBlank();
        assertThat(response.getLastFour()).isEqualTo("1111");
        assertThat(response.getCardScheme()).isEqualTo("MC");
        verify(tokenVaultRepository).save(any(TokenVault.class));
        verify(auditLogger).logSuccess(eq(AuditEventType.TOKENISE), any(), any(), any(), any());
    }

    // ── De-dup — same PAN returns existing token ─────────────────────────────

    @Test
    void tokenise_samePanCalledTwice_returnsSameTokenWithoutNewVaultRecord() {
        TokeniseRequest request = buildRequest(VALID_PAN);
        TokenVault existingVault = buildExistingVault();

        when(panHasher.hash(VALID_PAN)).thenReturn(VALID_HASH_RESULT);
        when(tokenVaultRepository.findActiveByPanHash(VALID_PAN_HASH))
                .thenReturn(Optional.of(existingVault));

        TokeniseResponse response = service.tokenise(request);

        assertThat(response.getToken()).isEqualTo(existingVault.getToken());
        verify(tokenVaultRepository, never()).save(any());
        verify(cipher, never()).encrypt(any(), any());
        verify(auditLogger).logSuccess(eq(AuditEventType.TOKENISE),
                eq(existingVault.getTokenId()), any(), any(), any());
    }

    @Test
    void tokenise_samePanCalledTwice_returnsSameToken() {
        TokeniseRequest request = buildRequest(VALID_PAN);
        TokenVault existingVault = buildExistingVault();

        when(panHasher.hash(VALID_PAN)).thenReturn(VALID_HASH_RESULT);
        when(tokenVaultRepository.findActiveByPanHash(VALID_PAN_HASH))
                .thenReturn(Optional.of(existingVault));

        TokeniseResponse first = service.tokenise(request);
        TokeniseResponse second = service.tokenise(request);

        assertThat(first.getToken()).isEqualTo(second.getToken());
    }

    // ── HMAC rotation — dual-lookup dedup ────────────────────────────────────

    @Test
    void tokenise_duringHmacRotation_fallsBackToOldHashForDedup() {
        String oldHmacVersionId = "aaaaaaaa-0000-0000-0000-000000000099";
        String oldHash = "old-pan-hash-value";
        TokenVault existingVault = buildExistingVault();

        when(panHasher.hash(VALID_PAN)).thenReturn(VALID_HASH_RESULT);
        when(tokenVaultRepository.findActiveByPanHash(VALID_PAN_HASH)).thenReturn(Optional.empty());
        when(hmacKeyRing.findRotatingVersionId()).thenReturn(Optional.of(oldHmacVersionId));
        when(panHasher.hashWithVersion(VALID_PAN, oldHmacVersionId)).thenReturn(oldHash);
        when(tokenVaultRepository.findActiveByPanHash(oldHash)).thenReturn(Optional.of(existingVault));

        TokeniseResponse response = service.tokenise(buildRequest(VALID_PAN));

        assertThat(response.getToken()).isEqualTo(existingVault.getToken());
        verify(tokenVaultRepository, never()).save(any());
        verify(cipher, never()).encrypt(any(), any());
        verify(auditLogger).logSuccess(eq(AuditEventType.TOKENISE),
                eq(existingVault.getTokenId()), any(), any(), any());
    }

    @Test
    void tokenise_duringHmacRotation_oldHashAlsoMisses_createsNewToken() {
        String oldHmacVersionId = "aaaaaaaa-0000-0000-0000-000000000099";
        String oldHash = "old-pan-hash-value";
        KeyMaterial activeKey = buildKeyMaterial();
        KeyVersion activeVersion = buildKeyVersion();
        EncryptResult encryptResult = buildEncryptResult();

        when(panHasher.hash(VALID_PAN)).thenReturn(VALID_HASH_RESULT);
        when(tokenVaultRepository.findActiveByPanHash(VALID_PAN_HASH)).thenReturn(Optional.empty());
        when(hmacKeyRing.findRotatingVersionId()).thenReturn(Optional.of(oldHmacVersionId));
        when(panHasher.hashWithVersion(VALID_PAN, oldHmacVersionId)).thenReturn(oldHash);
        when(tokenVaultRepository.findActiveByPanHash(oldHash)).thenReturn(Optional.empty());
        when(dekRing.getActive()).thenReturn(activeKey);
        when(keyVersionRepository.findById(any(UUID.class))).thenReturn(Optional.of(activeVersion));
        when(cipher.encrypt(any(), any())).thenReturn(encryptResult);
        when(tokenVaultRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        TokeniseResponse response = service.tokenise(buildRequest(VALID_PAN));

        assertThat(response.getToken()).isNotBlank();
        verify(tokenVaultRepository).save(any(TokenVault.class));
    }

    // ── PAN validation — null ────────────────────────────────────────────────

    @Test
    void tokenise_nullPan_throwsPanValidationException() {
        TokeniseRequest request = buildRequest(null);

        assertThatThrownBy(() -> service.tokenise(request))
                .isInstanceOf(PanValidationException.class)
                .hasMessageContaining("null or blank");

        verify(tokenVaultRepository, never()).save(any());
        verify(auditLogger).logFailure(eq(AuditEventType.TOKENISE_FAILURE),
                any(), any(), any(), anyString(), any());
    }

    @Test
    void tokenise_blankPan_throwsPanValidationException() {
        TokeniseRequest request = buildRequest("   ");

        assertThatThrownBy(() -> service.tokenise(request))
                .isInstanceOf(PanValidationException.class)
                .hasMessageContaining("null or blank");

        verify(tokenVaultRepository, never()).save(any());
    }

    // ── PAN validation — format ───────────────────────────────────────────────

    @ParameterizedTest
    @ValueSource(strings = {"411111111111", "1234", "abcdefghijklmnop", "4111-1111-1111-1111"})
    void tokenise_invalidPanFormat_throwsPanValidationException(String invalidPan) {
        TokeniseRequest request = buildRequest(invalidPan);

        assertThatThrownBy(() -> service.tokenise(request))
                .isInstanceOf(PanValidationException.class);

        verify(panHasher, never()).hash(anyString());
        verify(tokenVaultRepository, never()).save(any());
    }

    // ── PAN validation — Luhn ────────────────────────────────────────────────

    @Test
    void tokenise_luhnInvalidPan_throwsPanValidationException() {
        TokeniseRequest request = buildRequest("4111111111111112");

        assertThatThrownBy(() -> service.tokenise(request))
                .isInstanceOf(PanValidationException.class)
                .hasMessageContaining("Luhn");

        verify(tokenVaultRepository, never()).save(any());
    }

    // ── Key ring empty ────────────────────────────────────────────────────────

    @Test
    void tokenise_keyRingHasNoActiveKey_throwsTokenisationException() {
        TokeniseRequest request = buildRequest(VALID_PAN);

        when(panHasher.hash(VALID_PAN)).thenReturn(VALID_HASH_RESULT);
        when(tokenVaultRepository.findActiveByPanHash(VALID_PAN_HASH)).thenReturn(Optional.empty());
        when(dekRing.getActive()).thenThrow(new IllegalStateException("No active key version has been promoted in the key ring"));

        assertThatThrownBy(() -> service.tokenise(request))
                .isInstanceOf(TokenisationException.class);

        verify(tokenVaultRepository, never()).save(any());
        verify(auditLogger).logFailure(eq(AuditEventType.TOKENISE_FAILURE),
                any(), any(), any(), anyString(), any());
    }

    // ── Audit log on failure ──────────────────────────────────────────────────

    @Test
    void tokenise_encryptionFails_writesFailureAuditBeforeRethrowing() {
        TokeniseRequest request = buildRequest(VALID_PAN);
        KeyMaterial activeKey = buildKeyMaterial();
        KeyVersion activeVersion = buildKeyVersion();

        when(panHasher.hash(VALID_PAN)).thenReturn(VALID_HASH_RESULT);
        when(tokenVaultRepository.findActiveByPanHash(VALID_PAN_HASH)).thenReturn(Optional.empty());
        when(dekRing.getActive()).thenReturn(activeKey);
        when(keyVersionRepository.findById(any(UUID.class))).thenReturn(Optional.of(activeVersion));
        when(cipher.encrypt(any(), any())).thenThrow(
                new com.yourorg.tokenisation.crypto.EncryptionException("AES-GCM encryption failed"));

        assertThatThrownBy(() -> service.tokenise(request))
                .isInstanceOf(TokenisationException.class);

        ArgumentCaptor<String> failureReasonCaptor = ArgumentCaptor.forClass(String.class);
        verify(auditLogger).logFailure(eq(AuditEventType.TOKENISE_FAILURE), any(),
                any(), any(), failureReasonCaptor.capture(), any());
        assertThat(failureReasonCaptor.getValue()).doesNotContain(VALID_PAN);
    }

    // ── Null request guard ────────────────────────────────────────────────────

    @Test
    void tokenise_nullRequest_throwsNullPointerException() {
        assertThatThrownBy(() -> service.tokenise(null))
                .isInstanceOf(NullPointerException.class);
    }

    // ── Token revocation ─────────────────────────────────────────────────────

    @Test
    void revokeToken_activeToken_deactivatesAndWritesAudit() {
        TokenVault vault = buildExistingVault();
        when(tokenVaultRepository.findActiveByToken(vault.getToken())).thenReturn(Optional.of(vault));
        when(tokenVaultRepository.save(any())).thenReturn(vault);

        service.revokeToken(vault.getToken());

        assertThat(vault.isActive()).isFalse();
        verify(tokenVaultRepository).save(vault);
        verify(auditLogger).logSuccess(eq(AuditEventType.TOKEN_REVOKED),
                eq(vault.getTokenId()), any(), any(), any());
    }

    @Test
    void revokeToken_unknownToken_throwsTokenNotFoundException() {
        String unknownToken = "unknown-token";
        when(tokenVaultRepository.findActiveByToken(unknownToken)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.revokeToken(unknownToken))
                .isInstanceOf(TokenNotFoundException.class);

        verify(tokenVaultRepository, never()).save(any());
    }

    @Test
    void revokeToken_nullToken_throwsNullPointerException() {
        assertThatThrownBy(() -> service.revokeToken(null))
                .isInstanceOf(NullPointerException.class);
    }

    // ── Card replacement ──────────────────────────────────────────────────────

    private static final String NEW_PAN        = "5105105105105100";
    private static final String NEW_PAN_HASH   = "new-pan-hash";
    private static final HashResult NEW_HASH_RESULT = new HashResult(NEW_PAN_HASH, HMAC_VERSION_ID);

    @Test
    void replaceCard_validNewPan_updatesVaultAndAuditsCardReplaced() {
        TokenVault vault = buildExistingVault();
        KeyMaterial activeKey = buildKeyMaterial();
        KeyVersion activeVersion = buildKeyVersion();
        EncryptResult encryptResult = buildEncryptResult();

        when(tokenVaultRepository.findActiveByToken(vault.getToken())).thenReturn(Optional.of(vault));
        when(panHasher.hash(NEW_PAN)).thenReturn(NEW_HASH_RESULT);
        when(tokenVaultRepository.findActiveByPanHash(NEW_PAN_HASH)).thenReturn(Optional.empty());
        when(dekRing.getActive()).thenReturn(activeKey);
        when(keyVersionRepository.findById(any(UUID.class))).thenReturn(Optional.of(activeVersion));
        when(cipher.encrypt(any(), any())).thenReturn(encryptResult);
        when(tokenVaultRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        service.replaceCard(vault.getToken(), buildReplacementRequest(NEW_PAN));

        verify(cipher).encrypt(any(), any());
        verify(tokenVaultRepository).save(vault);
        verify(auditLogger).logSuccess(eq(AuditEventType.CARD_REPLACED),
                eq(vault.getTokenId()), any(), any(), any());
    }

    @Test
    void replaceCard_validNewPan_returnsResponseWithNewLastFour() {
        TokenVault vault = buildExistingVault();
        KeyMaterial activeKey = buildKeyMaterial();
        KeyVersion activeVersion = buildKeyVersion();
        EncryptResult encryptResult = buildEncryptResult();

        when(tokenVaultRepository.findActiveByToken(vault.getToken())).thenReturn(Optional.of(vault));
        when(panHasher.hash(NEW_PAN)).thenReturn(NEW_HASH_RESULT);
        when(tokenVaultRepository.findActiveByPanHash(NEW_PAN_HASH)).thenReturn(Optional.empty());
        when(dekRing.getActive()).thenReturn(activeKey);
        when(keyVersionRepository.findById(any(UUID.class))).thenReturn(Optional.of(activeVersion));
        when(cipher.encrypt(any(), any())).thenReturn(encryptResult);
        when(tokenVaultRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        var response = service.replaceCard(vault.getToken(), buildReplacementRequest(NEW_PAN));

        assertThat(response.getLastFour()).isEqualTo("5100");
    }

    @Test
    void replaceCard_samePanIdentityCase_succeedsWithoutConflict() {
        TokenVault vault = buildExistingVault();
        KeyMaterial activeKey = buildKeyMaterial();
        KeyVersion activeVersion = buildKeyVersion();
        EncryptResult encryptResult = buildEncryptResult();

        when(tokenVaultRepository.findActiveByToken(vault.getToken())).thenReturn(Optional.of(vault));
        when(panHasher.hash(NEW_PAN)).thenReturn(NEW_HASH_RESULT);
        when(tokenVaultRepository.findActiveByPanHash(NEW_PAN_HASH)).thenReturn(Optional.of(vault));
        when(dekRing.getActive()).thenReturn(activeKey);
        when(keyVersionRepository.findById(any(UUID.class))).thenReturn(Optional.of(activeVersion));
        when(cipher.encrypt(any(), any())).thenReturn(encryptResult);
        when(tokenVaultRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        service.replaceCard(vault.getToken(), buildReplacementRequest(NEW_PAN));

        verify(tokenVaultRepository).save(vault);
    }

    @Test
    void replaceCard_unknownToken_throwsTokenNotFoundException() {
        when(tokenVaultRepository.findActiveByToken("unknown")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.replaceCard("unknown", buildReplacementRequest(NEW_PAN)))
                .isInstanceOf(TokenNotFoundException.class);

        verify(tokenVaultRepository, never()).save(any());
    }

    @Test
    void replaceCard_newPanAlreadyHasDifferentToken_throwsCardAlreadyTokenisedException() {
        TokenVault existingVault = buildExistingVault();
        TokenVault differentVault = buildExistingVault();

        when(tokenVaultRepository.findActiveByToken(existingVault.getToken()))
                .thenReturn(Optional.of(existingVault));
        when(panHasher.hash(NEW_PAN)).thenReturn(NEW_HASH_RESULT);
        when(tokenVaultRepository.findActiveByPanHash(NEW_PAN_HASH))
                .thenReturn(Optional.of(differentVault));

        assertThatThrownBy(() -> service.replaceCard(existingVault.getToken(), buildReplacementRequest(NEW_PAN)))
                .isInstanceOf(CardAlreadyTokenisedException.class);

        verify(tokenVaultRepository, never()).save(any());
        verify(cipher, never()).encrypt(any(), any());
    }

    @Test
    void replaceCard_luhnInvalidNewPan_throwsPanValidationException() {
        assertThatThrownBy(() -> service.replaceCard("any-token", buildReplacementRequest("4111111111111112")))
                .isInstanceOf(PanValidationException.class)
                .hasMessageContaining("Luhn");

        verify(tokenVaultRepository, never()).save(any());
    }

    @Test
    void replaceCard_nullPan_throwsPanValidationException() {
        assertThatThrownBy(() -> service.replaceCard("any-token", buildReplacementRequest(null)))
                .isInstanceOf(PanValidationException.class);
    }

    @Test
    void replaceCard_keyRingEmpty_throwsTokenisationException() {
        TokenVault vault = buildExistingVault();

        when(tokenVaultRepository.findActiveByToken(vault.getToken())).thenReturn(Optional.of(vault));
        when(panHasher.hash(NEW_PAN)).thenReturn(NEW_HASH_RESULT);
        when(tokenVaultRepository.findActiveByPanHash(NEW_PAN_HASH)).thenReturn(Optional.empty());
        when(dekRing.getActive()).thenThrow(new IllegalStateException("No active key"));

        assertThatThrownBy(() -> service.replaceCard(vault.getToken(), buildReplacementRequest(NEW_PAN)))
                .isInstanceOf(TokenisationException.class);
    }

    @Test
    void replaceCard_nullToken_throwsNullPointerException() {
        assertThatThrownBy(() -> service.replaceCard(null, buildReplacementRequest(NEW_PAN)))
                .isInstanceOf(NullPointerException.class);
    }

    // ── Test helpers ──────────────────────────────────────────────────────────

    private CardReplacementRequest buildReplacementRequest(String pan) {
        CardReplacementRequest request = new CardReplacementRequest();
        request.setPan(pan);
        request.setCardScheme("MC");
        request.setExpiryMonth(6);
        request.setExpiryYear(2029);
        return request;
    }

    private TokeniseRequest buildRequest(String pan) {
        TokeniseRequest request = new TokeniseRequest();
        request.setPan(pan);
        request.setCardScheme("MC");
        request.setExpiryMonth(12);
        request.setExpiryYear(2027);
        return request;
    }

    private KeyMaterial buildKeyMaterial() {
        byte[] dek = new byte[32];
        return new KeyMaterial(UUID.randomUUID().toString(), dek, Instant.now().plusSeconds(3600));
    }

    private KeyVersion buildKeyVersion() {
        return KeyVersion.builder()
                .kmsKeyId("local-dev-key")
                .kmsProvider("LOCAL_DEV")
                .keyAlias("test-key")
                .encryptedDekBlob(new byte[60])
                .status(KeyStatus.ACTIVE)
                .activatedAt(Instant.now())
                .rotateBy(Instant.now().plusSeconds(365L * 24 * 60 * 60))
                .createdBy("test")
                .build();
    }

    private EncryptResult buildEncryptResult() {
        byte[] ciphertext = new byte[16];
        byte[] iv = new byte[12];
        byte[] authTag = new byte[16];
        return new EncryptResult(ciphertext, iv, authTag);
    }

    private TokenVault buildExistingVault() {
        return TokenVault.builder()
                .token(UUID.randomUUID().toString())
                .encryptedPan(new byte[16])
                .iv(new byte[12])
                .authTag(new byte[16])
                .keyVersion(buildKeyVersion())
                .panHash(VALID_PAN_HASH)
                .lastFour("1111")
                .cardScheme("MC")
                .expiryMonth((short) 12)
                .expiryYear((short) 2027)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(TOKEN_TTL_DAYS * 86400))
                .build();
    }
}
