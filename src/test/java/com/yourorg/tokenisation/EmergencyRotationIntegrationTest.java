package com.yourorg.tokenisation;

import com.yourorg.tokenisation.api.request.TokeniseRequest;
import com.yourorg.tokenisation.api.response.DetokeniseResponse;
import com.yourorg.tokenisation.api.response.TokeniseResponse;
import com.yourorg.tokenisation.crypto.InMemoryKeyRing;
import com.yourorg.tokenisation.crypto.TamperDetector;
import com.yourorg.tokenisation.domain.KeyStatus;
import com.yourorg.tokenisation.domain.KeyVersion;
import com.yourorg.tokenisation.domain.TokenType;
import com.yourorg.tokenisation.kms.KmsProvider;
import com.yourorg.tokenisation.repository.AuditLogRepository;
import com.yourorg.tokenisation.repository.KeyVersionRepository;
import com.yourorg.tokenisation.repository.TokenVaultRepository;
import com.yourorg.tokenisation.rotation.KeyRotationService;
import com.yourorg.tokenisation.rotation.RotationJob;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for emergency key rotation triggered by a compromise event.
 *
 * <p>Verifies:
 * <ul>
 *   <li>The compromised key is immediately blocked for detokenisation (HTTP 500)
 *   <li>After batch re-encryption, detokenisation of pre-compromise tokens is restored
 *   <li>New tokenisations after emergency rotation use the new key
 *   <li>Audit trail contains {@code EMERGENCY_ROTATION_STARTED} and
 *       {@code KEY_INTEGRITY_VIOLATION} events
 * </ul>
 *
 * <p>Uses the same {@link #setUpForRotationTest()} as
 * {@link ScheduledRotationIntegrationTest} — the seed key is restored to ACTIVE
 * with a real checksum before each test.
 */
class EmergencyRotationIntegrationTest extends AbstractIntegrationTest {

    private static final String MERCHANT_A = "MERCHANT_EMRG";
    private static final String VISA_PAN   = "4111111111111111";
    private static final String MC_PAN     = "5500005555555559";

    @Autowired private TestRestTemplate restTemplate;
    @Autowired private KeyVersionRepository keyVersionRepository;
    @Autowired private TokenVaultRepository tokenVaultRepository;
    @Autowired private AuditLogRepository auditLogRepository;
    @Autowired private JdbcTemplate jdbcTemplate;
    @Autowired private TamperDetector tamperDetector;
    @Autowired private KeyRotationService keyRotationService;
    @Autowired private RotationJob rotationJob;
    @Autowired private InMemoryKeyRing keyRing;
    @Autowired private KmsProvider kmsProvider;

    @BeforeEach
    void setUpForRotationTest() {
        jdbcTemplate.execute("DELETE FROM token_vault");
        jdbcTemplate.execute("DELETE FROM token_audit_log");
        jdbcTemplate.execute(
                "UPDATE key_versions SET status = 'RETIRED' WHERE id != '" + SEED_KEY_VERSION_ID + "'::uuid");
        jdbcTemplate.execute(
                "UPDATE key_versions SET status = 'ACTIVE' WHERE id = '" + SEED_KEY_VERSION_ID + "'::uuid");

        KeyVersion seedKey = keyVersionRepository.findActiveOrThrow();
        seedKey.initializeChecksum(tamperDetector.computeChecksum(seedKey));
        keyVersionRepository.save(seedKey);

        byte[] seedKek = kmsProvider.unwrapKek(seedKey.getEncryptedKekBlob());
        try {
            keyRing.load(SEED_KEY_VERSION_ID, seedKek, seedKey.getRotateBy());
            keyRing.promoteActive(SEED_KEY_VERSION_ID);
        } finally {
            Arrays.fill(seedKek, (byte) 0);
        }
    }

    // ── Immediate detokenisation block ────────────────────────────────────────

    @Test
    void emergencyRotation_compromisedKey_immediatelyBlocksDetokenisation() {
        String token = tokenise(VISA_PAN, TokenType.ONE_TIME);
        UUID compromisedKeyId = UUID.fromString(SEED_KEY_VERSION_ID);

        keyRotationService.initiateEmergencyRotation(compromisedKeyId, "emergency-key-v2");

        // Detokenisation of a token under the compromised key must be blocked (500)
        ResponseEntity<String> response = detokeniseRaw(token, String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @Test
    void emergencyRotation_compromisedKey_markedCompromisedInDb() {
        UUID compromisedKeyId = UUID.fromString(SEED_KEY_VERSION_ID);

        keyRotationService.initiateEmergencyRotation(compromisedKeyId, "emergency-key-v2");

        KeyVersion compromisedKey = keyVersionRepository.findById(compromisedKeyId).orElseThrow();
        assertThat(compromisedKey.getStatus()).isEqualTo(KeyStatus.COMPROMISED);
    }

    @Test
    void emergencyRotation_newKeyBecomeActiveImmediately() {
        UUID compromisedKeyId = UUID.fromString(SEED_KEY_VERSION_ID);

        keyRotationService.initiateEmergencyRotation(compromisedKeyId, "emergency-key-v2");

        assertThat(keyVersionRepository.findActive())
                .isPresent()
                .get()
                .satisfies(kv -> assertThat(kv.getId()).isNotEqualTo(compromisedKeyId));
    }

    // ── Re-encryption and detokenisation restoration ──────────────────────────

    @Test
    void emergencyRotation_afterBatchReencryption_detokenisationRestored() {
        List<String> tokens = List.of(
                tokenise(VISA_PAN, TokenType.ONE_TIME),
                tokenise(MC_PAN, TokenType.ONE_TIME));
        UUID compromisedKeyId = UUID.fromString(SEED_KEY_VERSION_ID);

        keyRotationService.initiateEmergencyRotation(compromisedKeyId, "emergency-key-v2");
        rotationJob.processRotationBatch();

        // After re-encryption, all tokens should be detokenisable (using new key)
        for (String token : tokens) {
            ResponseEntity<DetokeniseResponse> response = detokenise(token);
            assertThat(response.getStatusCode())
                    .as("Token %s should be detokenisable after re-encryption", token)
                    .isEqualTo(HttpStatus.OK);
            assertThat(response.getBody().getPan()).isIn(VISA_PAN, MC_PAN);
        }
    }

    @Test
    void emergencyRotation_afterBatch_oldKeyRetired() {
        tokenise(VISA_PAN, TokenType.ONE_TIME);
        UUID compromisedKeyId = UUID.fromString(SEED_KEY_VERSION_ID);

        keyRotationService.initiateEmergencyRotation(compromisedKeyId, "emergency-key-v2");
        rotationJob.processRotationBatch();

        // Compromised key should transition from COMPROMISED → RETIRED after batch
        KeyVersion compromisedKey = keyVersionRepository.findById(compromisedKeyId).orElseThrow();
        assertThat(compromisedKey.getStatus()).isEqualTo(KeyStatus.RETIRED);
    }

    @Test
    void emergencyRotation_newTokenisationsUseNewKey() {
        UUID compromisedKeyId = UUID.fromString(SEED_KEY_VERSION_ID);

        keyRotationService.initiateEmergencyRotation(compromisedKeyId, "emergency-key-v2");

        // Tokenise after emergency rotation — must use new ACTIVE key
        String newToken = tokenise(VISA_PAN, TokenType.ONE_TIME);

        assertThat(tokenVaultRepository.findActiveByToken(newToken).orElseThrow()
                .getKeyVersion().getId())
                .isNotEqualTo(compromisedKeyId);
    }

    @Test
    void emergencyRotation_newTokensAfterRotation_detokenisable() {
        UUID compromisedKeyId = UUID.fromString(SEED_KEY_VERSION_ID);
        keyRotationService.initiateEmergencyRotation(compromisedKeyId, "emergency-key-v2");
        rotationJob.processRotationBatch();

        String newToken = tokenise(VISA_PAN, TokenType.ONE_TIME);
        ResponseEntity<DetokeniseResponse> response = detokenise(newToken);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().getPan()).isEqualTo(VISA_PAN);
    }

    // ── Audit trail ───────────────────────────────────────────────────────────

    @Test
    void emergencyRotation_writesEmergencyRotationStartedAndKeyIntegrityViolationAudit() {
        jdbcTemplate.execute("DELETE FROM token_audit_log");
        UUID compromisedKeyId = UUID.fromString(SEED_KEY_VERSION_ID);

        keyRotationService.initiateEmergencyRotation(compromisedKeyId, "emergency-key-v2");

        List<String> auditEventTypes = auditLogRepository.findAll().stream()
                .map(r -> r.getEventType())
                .toList();
        assertThat(auditEventTypes).contains("EMERGENCY_ROTATION_STARTED");
        assertThat(auditEventTypes).contains("KEY_INTEGRITY_VIOLATION");
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private String tokenise(String pan, TokenType tokenType) {
        TokeniseRequest request = new TokeniseRequest();
        request.setPan(pan);
        request.setTokenType(tokenType);
        request.setMerchantId(MERCHANT_A);
        request.setCardScheme("VISA");
        request.setExpiryMonth(12);
        request.setExpiryYear(2027);
        ResponseEntity<TokeniseResponse> response = restTemplate.postForEntity(
                "/api/v1/tokens", request, TokeniseResponse.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        return response.getBody().getToken();
    }

    private ResponseEntity<DetokeniseResponse> detokenise(String token) {
        return detokeniseRaw(token, DetokeniseResponse.class);
    }

    private <T> ResponseEntity<T> detokeniseRaw(String token, Class<T> responseType) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Merchant-ID", MERCHANT_A);
        return restTemplate.exchange(
                "/api/v1/tokens/" + token,
                HttpMethod.GET,
                new HttpEntity<>(headers),
                responseType);
    }
}
