package com.yourorg.tokenisation;

import com.yourorg.tokenisation.api.request.TokeniseRequest;
import com.yourorg.tokenisation.api.response.DetokeniseResponse;
import com.yourorg.tokenisation.api.response.TokeniseResponse;
import com.yourorg.tokenisation.crypto.InMemoryKeyRing;
import com.yourorg.tokenisation.crypto.TamperDetector;
import com.yourorg.tokenisation.domain.KeyStatus;
import com.yourorg.tokenisation.domain.KeyVersion;
import com.yourorg.tokenisation.domain.RotationReason;
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for scheduled key rotation.
 *
 * <p>Verifies the full rotation cycle end-to-end:
 * <ol>
 *   <li>Tokens created under the old key
 *   <li>{@link KeyRotationService#initiateScheduledRotation} transitions old key to ROTATING
 *       and creates a new ACTIVE key
 *   <li>{@link RotationJob#processRotationBatch} re-encrypts all tokens to the new key
 *   <li>Old key is retired automatically when the count reaches zero
 *   <li>All pre-rotation tokens remain detokenisable after rotation
 * </ol>
 *
 * <p>The scheduler is disabled in the test profile ({@code rotation.batch.cron: "-"}).
 * Tests invoke {@link RotationJob#processRotationBatch()} directly for deterministic control.
 *
 * <h3>Key version setup</h3>
 * The seed key inserted at context startup uses a placeholder checksum
 * ({@code "seed-checksum"}). Before each test, {@link #setUpForRotationTest()}:
 * <ul>
 *   <li>Retires any extra key versions left by previous tests (prevents two ACTIVE rows).
 *   <li>Resets the seed key to {@code ACTIVE} in the database.
 *   <li>Computes the real HMAC-SHA256 checksum and persists it — so that
 *       {@link com.yourorg.tokenisation.crypto.TamperDetector#assertIntegrity} passes.
 *   <li>Reloads the seed key into {@link InMemoryKeyRing} with fresh {@code ACTIVE} status
 *       and re-promotes it, so that tokenisation uses the correct key material.
 * </ul>
 */
class ScheduledRotationIntegrationTest extends AbstractIntegrationTest {

    private static final String MERCHANT_A = "MERCHANT_ROT";
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
        // 1. Clean token data (leave key_versions intact for the ring)
        jdbcTemplate.execute("DELETE FROM token_vault");
        jdbcTemplate.execute("DELETE FROM token_audit_log");

        // 2. Retire any extra key versions created by previous rotation tests.
        //    This prevents a partial-unique-index violation when we reset the seed key to ACTIVE.
        jdbcTemplate.execute(
                "UPDATE key_versions SET status = 'RETIRED' WHERE id != '" + SEED_KEY_VERSION_ID + "'::uuid");
        jdbcTemplate.execute(
                "UPDATE key_versions SET status = 'ACTIVE' WHERE id = '" + SEED_KEY_VERSION_ID + "'::uuid");

        // 3. Update the seed key's checksum to the real HMAC value so assertIntegrity passes.
        //    The seed key was inserted at startup with checksum = "seed-checksum" (placeholder).
        KeyVersion seedKey = keyVersionRepository.findActiveOrThrow();
        seedKey.initializeChecksum(tamperDetector.computeChecksum(seedKey));
        keyVersionRepository.save(seedKey);

        // 4. Reload seed key into the ring with fresh ACTIVE status and re-promote it.
        //    Previous rotation tests may have promoted a different key or retired the seed entry.
        byte[] seedKek = kmsProvider.unwrapKek(seedKey.getEncryptedKekBlob());
        try {
            keyRing.load(SEED_KEY_VERSION_ID, seedKek, seedKey.getRotateBy());
            keyRing.promoteActive(SEED_KEY_VERSION_ID);
        } finally {
            Arrays.fill(seedKek, (byte) 0);
        }
    }

    // ── Rotation state transitions ─────────────────────────────────────────────

    @Test
    void scheduledRotation_oldKeyBecomesRotating_newKeyBecomesActive() {
        UUID oldKeyId = UUID.fromString(SEED_KEY_VERSION_ID);

        keyRotationService.initiateScheduledRotation("test-key-v2", RotationReason.SCHEDULED);

        assertThat(keyVersionRepository.findById(oldKeyId).orElseThrow().getStatus())
                .isEqualTo(KeyStatus.ROTATING);
        assertThat(keyVersionRepository.findActive())
                .isPresent()
                .get()
                .satisfies(kv -> assertThat(kv.getId()).isNotEqualTo(oldKeyId));
    }

    @Test
    void scheduledRotation_newKeyHasRealChecksum() {
        keyRotationService.initiateScheduledRotation("test-key-v2", RotationReason.SCHEDULED);

        KeyVersion newKey = keyVersionRepository.findActiveOrThrow();
        // Real checksum should be 64 lowercase hex chars (HMAC-SHA256)
        assertThat(newKey.getChecksum()).matches("[0-9a-f]{64}");
    }

    // ── Full batch re-encryption ───────────────────────────────────────────────

    @Test
    void scheduledRotation_afterBatch_allTokensMigratedToNewKey() {
        String token1 = tokenise(VISA_PAN, TokenType.ONE_TIME);
        String token2 = tokenise(MC_PAN, TokenType.ONE_TIME);

        UUID oldKeyId = UUID.fromString(SEED_KEY_VERSION_ID);
        keyRotationService.initiateScheduledRotation("test-key-v2", RotationReason.SCHEDULED);
        UUID newKeyId = keyVersionRepository.findActiveOrThrow().getId();

        rotationJob.processRotationBatch();

        assertThat(tokenVaultRepository.countActiveByKeyVersionId(oldKeyId)).isZero();
        assertThat(tokenVaultRepository.findActiveByToken(token1).orElseThrow()
                .getKeyVersion().getId()).isEqualTo(newKeyId);
        assertThat(tokenVaultRepository.findActiveByToken(token2).orElseThrow()
                .getKeyVersion().getId()).isEqualTo(newKeyId);
    }

    @Test
    void scheduledRotation_afterBatch_oldKeyRetired() {
        tokenise(VISA_PAN, TokenType.ONE_TIME);
        UUID oldKeyId = UUID.fromString(SEED_KEY_VERSION_ID);

        keyRotationService.initiateScheduledRotation("test-key-v2", RotationReason.SCHEDULED);
        rotationJob.processRotationBatch();

        assertThat(keyVersionRepository.findById(oldKeyId).orElseThrow().getStatus())
                .isEqualTo(KeyStatus.RETIRED);
    }

    @Test
    void scheduledRotation_noTokensToMigrate_oldKeyRetiredImmediately() {
        UUID oldKeyId = UUID.fromString(SEED_KEY_VERSION_ID);

        keyRotationService.initiateScheduledRotation("test-key-v2", RotationReason.SCHEDULED);
        rotationJob.processRotationBatch();

        assertThat(keyVersionRepository.findById(oldKeyId).orElseThrow().getStatus())
                .isEqualTo(KeyStatus.RETIRED);
    }

    // ── Post-rotation detokenisation ──────────────────────────────────────────

    @Test
    void scheduledRotation_preRotationTokens_remainDetokenisableAfterRotation() {
        List<String> tokens = new ArrayList<>();
        tokens.add(tokenise(VISA_PAN, TokenType.ONE_TIME));
        tokens.add(tokenise(MC_PAN, TokenType.ONE_TIME));
        tokens.add(tokenise(VISA_PAN, TokenType.RECURRING));

        keyRotationService.initiateScheduledRotation("test-key-v2", RotationReason.SCHEDULED);
        rotationJob.processRotationBatch();

        for (String token : tokens) {
            ResponseEntity<DetokeniseResponse> response = detokenise(token);
            assertThat(response.getStatusCode())
                    .as("Token %s should be detokenisable after rotation", token)
                    .isEqualTo(HttpStatus.OK);
            assertThat(response.getBody().getPan()).isIn(VISA_PAN, MC_PAN);
        }
    }

    @Test
    void scheduledRotation_newTokenisationsUseNewKey() {
        UUID oldKeyId = UUID.fromString(SEED_KEY_VERSION_ID);
        keyRotationService.initiateScheduledRotation("test-key-v2", RotationReason.SCHEDULED);

        // Tokenise after rotation — must use new ACTIVE key
        String newToken = tokenise(VISA_PAN, TokenType.ONE_TIME);

        assertThat(tokenVaultRepository.findActiveByToken(newToken).orElseThrow()
                .getKeyVersion().getId())
                .isNotEqualTo(oldKeyId);
    }

    @Test
    void scheduledRotation_newTokenisationAfterRotation_remainsDetokenisable() {
        keyRotationService.initiateScheduledRotation("test-key-v2", RotationReason.SCHEDULED);
        rotationJob.processRotationBatch();

        // Tokenise a new token after rotation completes
        String newToken = tokenise(VISA_PAN, TokenType.ONE_TIME);

        ResponseEntity<DetokeniseResponse> response = detokenise(newToken);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().getPan()).isEqualTo(VISA_PAN);
    }

    // ── Audit trail ───────────────────────────────────────────────────────────

    @Test
    void scheduledRotation_writesKeyRotationStartedAuditEvent() {
        jdbcTemplate.execute("DELETE FROM token_audit_log");

        keyRotationService.initiateScheduledRotation("test-key-v2", RotationReason.SCHEDULED);

        assertThat(auditLogRepository.findAll())
                .anyMatch(r -> "KEY_ROTATION_STARTED".equals(r.getEventType()));
    }

    @Test
    void scheduledRotation_afterBatch_writesKeyRotationCompletedAuditEvent() {
        tokenise(VISA_PAN, TokenType.ONE_TIME);
        jdbcTemplate.execute("DELETE FROM token_audit_log");

        keyRotationService.initiateScheduledRotation("test-key-v2", RotationReason.SCHEDULED);
        rotationJob.processRotationBatch();

        assertThat(auditLogRepository.findAll())
                .anyMatch(r -> "KEY_ROTATION_COMPLETED".equals(r.getEventType()));
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
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Merchant-ID", MERCHANT_A);
        return restTemplate.exchange(
                "/api/v1/tokens/" + token,
                HttpMethod.GET,
                new HttpEntity<>(headers),
                DetokeniseResponse.class);
    }
}
