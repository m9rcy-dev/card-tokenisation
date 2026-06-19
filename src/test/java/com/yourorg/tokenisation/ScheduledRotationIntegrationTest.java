package com.yourorg.tokenisation;

import com.yourorg.tokenisation.api.request.TokeniseRequest;
import com.yourorg.tokenisation.api.response.DetokeniseResponse;
import com.yourorg.tokenisation.api.response.TokeniseResponse;
import com.yourorg.tokenisation.crypto.InMemoryKekKeyRing;
import com.yourorg.tokenisation.domain.KeyStatus;
import com.yourorg.tokenisation.domain.KeyVersion;
import com.yourorg.tokenisation.domain.RotationReason;
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
 * Before each test, {@link #setUpForRotationTest()}:
 * <ul>
 *   <li>Retires any extra KEK versions left by previous tests (prevents two ACTIVE KEK rows).
 *   <li>Resets the seed KEK to {@code ACTIVE} in the database.
 *   <li>Reloads the seed key into {@link InMemoryKekKeyRing} with fresh {@code ACTIVE} status
 *       and re-promotes it, so that tokenisation uses the correct key material.
 * </ul>
 */
class ScheduledRotationIntegrationTest extends AbstractIntegrationTest {

    private static final String VISA_PAN   = "4111111111111111";
    private static final String MC_PAN     = "5500005555555559";

    @Autowired private TestRestTemplate restTemplate;
    @Autowired private KeyVersionRepository keyVersionRepository;
    @Autowired private TokenVaultRepository tokenVaultRepository;
    @Autowired private AuditLogRepository auditLogRepository;
    @Autowired private JdbcTemplate jdbcTemplate;
    @Autowired private KeyRotationService keyRotationService;
    @Autowired private RotationJob rotationJob;
    @Autowired private InMemoryKekKeyRing keyRing;
    @Autowired private KmsProvider kmsProvider;

    @BeforeEach
    void setUpForRotationTest() {
        // 1. Clean token data (leave key_versions intact for the ring)
        jdbcTemplate.execute("DELETE FROM token_vault");
        jdbcTemplate.execute("DELETE FROM token_audit_log");

        // 2. Retire any extra KEK versions created by previous rotation tests.
        //    Scoped to key_type='KEK' so HMAC rows are untouched (preserves HMAC ring state).
        jdbcTemplate.execute(
                "UPDATE key_versions SET status = 'RETIRED' WHERE id != '" + SEED_KEY_VERSION_ID + "'::uuid AND key_type = 'KEK'");
        jdbcTemplate.execute(
                "UPDATE key_versions SET status = 'ACTIVE' WHERE id = '" + SEED_KEY_VERSION_ID + "'::uuid");

        // 3. Reload seed key into the ring with fresh ACTIVE status and re-promote it.
        //    Previous rotation tests may have promoted a different key or retired the seed entry.
        KeyVersion seedKey = keyVersionRepository.findActiveKekOrThrow();
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

    // ── Full batch re-encryption ───────────────────────────────────────────────

    @Test
    void scheduledRotation_afterBatch_allTokensMigratedToNewKey() {
        String token1 = tokenise(VISA_PAN);
        String token2 = tokenise(MC_PAN);

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
        tokenise(VISA_PAN);
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
        tokens.add(tokenise(VISA_PAN));
        tokens.add(tokenise(MC_PAN));
        tokens.add(tokenise(VISA_PAN));

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
        String newToken = tokenise(VISA_PAN);

        assertThat(tokenVaultRepository.findActiveByToken(newToken).orElseThrow()
                .getKeyVersion().getId())
                .isNotEqualTo(oldKeyId);
    }

    @Test
    void scheduledRotation_newTokenisationAfterRotation_remainsDetokenisable() {
        keyRotationService.initiateScheduledRotation("test-key-v2", RotationReason.SCHEDULED);
        rotationJob.processRotationBatch();

        // Tokenise a new token after rotation completes
        String newToken = tokenise(VISA_PAN);

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
        tokenise(VISA_PAN);
        jdbcTemplate.execute("DELETE FROM token_audit_log");

        keyRotationService.initiateScheduledRotation("test-key-v2", RotationReason.SCHEDULED);
        rotationJob.processRotationBatch();

        assertThat(auditLogRepository.findAll())
                .anyMatch(r -> "KEY_ROTATION_COMPLETED".equals(r.getEventType()));
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private String tokenise(String pan) {
        TokeniseRequest request = new TokeniseRequest();
        request.setPan(pan);
        request.setCardScheme("VISA");
        request.setExpiryMonth(12);
        request.setExpiryYear(2027);
        ResponseEntity<TokeniseResponse> response = restTemplate.postForEntity(
                "/api/v1/tokens", request, TokeniseResponse.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        return response.getBody().getToken();
    }

    private ResponseEntity<DetokeniseResponse> detokenise(String token) {
        return restTemplate.getForEntity("/api/v1/tokens/" + token, DetokeniseResponse.class);
    }
}
