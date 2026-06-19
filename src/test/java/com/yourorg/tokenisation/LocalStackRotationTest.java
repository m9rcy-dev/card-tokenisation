package com.yourorg.tokenisation;

import com.yourorg.tokenisation.api.request.TokeniseRequest;
import com.yourorg.tokenisation.api.response.DetokeniseResponse;
import com.yourorg.tokenisation.api.response.TokeniseResponse;
import com.yourorg.tokenisation.crypto.AesGcmCipher;
import com.yourorg.tokenisation.crypto.InMemoryHmacKeyRing;
import com.yourorg.tokenisation.crypto.InMemoryKekKeyRing;
import com.yourorg.tokenisation.domain.KeyStatus;
import com.yourorg.tokenisation.domain.KeyVersion;
import com.yourorg.tokenisation.domain.RotationReason;
import com.yourorg.tokenisation.kms.KmsProvider;
import com.yourorg.tokenisation.repository.AuditLogRepository;
import com.yourorg.tokenisation.repository.KeyVersionRepository;
import com.yourorg.tokenisation.repository.TokenVaultRepository;
import com.yourorg.tokenisation.rotation.HmacRotationJob;
import com.yourorg.tokenisation.rotation.HmacRotationService;
import com.yourorg.tokenisation.rotation.KeyRotationService;
import com.yourorg.tokenisation.rotation.RotationJob;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.Arrays;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for KEK and HMAC rotation using a real LocalStack KMS instance.
 *
 * <p>Verifies that the full rotation runbook works when KMS calls (KEK unwrap) go to a
 * real AWS-compatible API (LocalStack) rather than the local-dev stub.
 *
 * <h3>LS-R-1: KEK envelope rotation</h3>
 * <ol>
 *   <li>Pre-tokenise PANs under the seed KEK version.
 *   <li>Initiate scheduled rotation — LocalStack KMS is called to unwrap the KEK for the
 *       new version (same encrypted blob, different key_versions UUID).
 *   <li>Assert the old key is ROTATING; old tokens are still detokenisable.
 *   <li>Process the re-encryption batch (in-memory DEK rewrap, no KMS call).
 *   <li>Assert old key is RETIRED, all tokens detokenisable under new key, audit trail complete.
 * </ol>
 *
 * <h3>LS-R-2: HMAC rotation</h3>
 * <ol>
 *   <li>Pre-tokenise a PAN — dedup uses the old HMAC hash.
 *   <li>Initiate HMAC rotation — new HMAC key version seeded; new tokenisations use new hash.
 *   <li>Assert dual-lookup dedup works during the rotation window (same token returned).
 *   <li>Process the HMAC re-hash batch.
 *   <li>Assert old HMAC version RETIRED, dedup works after completion.
 *   <li>Assert audit trail contains {@code HMAC_ROTATION_STARTED} and {@code HMAC_ROTATION_COMPLETED}.
 * </ol>
 *
 * <p>Run with: {@code mvn test -P localstack-tests} or {@code make localstack-test}.
 */
@Tag("localstack")
class LocalStackRotationTest extends AbstractLocalStackIntegrationTest {

    private static final String VISA_PAN = "4111111111111111";
    private static final String MC_PAN   = "5500005555555559";

    @Autowired private TestRestTemplate      restTemplate;
    @Autowired private KeyVersionRepository  keyVersionRepository;
    @Autowired private TokenVaultRepository  tokenVaultRepository;
    @Autowired private AuditLogRepository    auditLogRepository;
    @Autowired private JdbcTemplate          jdbcTemplate;
    @Autowired private KeyRotationService    keyRotationService;
    @Autowired private RotationJob           rotationJob;
    @Autowired private HmacRotationService   hmacRotationService;
    @Autowired private HmacRotationJob       hmacRotationJob;
    @Autowired private InMemoryKekKeyRing    kekKeyRing;
    @Autowired private InMemoryHmacKeyRing   hmacKeyRing;
    @Autowired private KmsProvider           kmsProvider;
    @Autowired private AesGcmCipher          cipher;

    // Discovered dynamically in @BeforeEach by key_alias
    private String seedKekId;
    private String seedHmacId;

    @BeforeEach
    void resetKeyState() {
        jdbcTemplate.execute("DELETE FROM token_vault");
        jdbcTemplate.execute("DELETE FROM token_audit_log");

        seedKekId = jdbcTemplate.queryForObject(
                "SELECT id::text FROM key_versions WHERE key_type='KEK' AND key_alias=?",
                String.class, SEED_KEK_ALIAS);
        seedHmacId = jdbcTemplate.queryForObject(
                "SELECT id::text FROM key_versions WHERE key_type='HMAC' AND key_alias=?",
                String.class, SEED_HMAC_ALIAS);

        // Reset KEK rows: retire everything except seed, re-activate seed
        jdbcTemplate.update(
                "UPDATE key_versions SET status='RETIRED', retired_at=NULL "
                        + "WHERE key_type='KEK' AND id != '" + seedKekId + "'::uuid");
        jdbcTemplate.update(
                "UPDATE key_versions SET status='ACTIVE', retired_at=NULL "
                        + "WHERE id='" + seedKekId + "'::uuid");

        // Reload seed KEK into ring via LocalStack KMS — this is the integration test!
        KeyVersion seedKek = keyVersionRepository.findById(UUID.fromString(seedKekId)).orElseThrow();
        byte[] kekBytes = kmsProvider.unwrapKek(seedKek.getEncryptedKekBlob());
        try {
            kekKeyRing.load(seedKekId, kekBytes, seedKek.getRotateBy());
            kekKeyRing.promoteActive(seedKekId);
        } finally {
            Arrays.fill(kekBytes, (byte) 0);
        }

        // Reset HMAC rows: retire non-seed, re-activate seed
        jdbcTemplate.update(
                "UPDATE key_versions SET status='RETIRED', retired_at=NULL "
                        + "WHERE key_type='HMAC' AND id != '" + seedHmacId + "'::uuid");
        jdbcTemplate.update(
                "UPDATE key_versions SET status='ACTIVE', retired_at=NULL "
                        + "WHERE id='" + seedHmacId + "'::uuid");

        // Drain stale non-seed versions from HMAC ring
        try {
            String activeId = hmacKeyRing.getActiveVersionId();
            if (!activeId.equals(seedHmacId)) {
                hmacKeyRing.retire(activeId);
            }
        } catch (IllegalStateException ignored) {
            // ring had no active pointer
        }
        hmacKeyRing.findRotatingVersionId()
                .filter(id -> !id.equals(seedHmacId))
                .ifPresent(hmacKeyRing::retire);

        // Reload seed HMAC into ring if it was retired during a previous test
        if (!hmacKeyRing.contains(seedHmacId)) {
            reloadSeedHmac();
        }
        hmacKeyRing.promoteActive(seedHmacId);
    }

    // ── LS-R-1: KEK envelope rotation ─────────────────────────────────────────

    @Test
    void kekRotation_oldKeyBecomesRotating_localStackKmsUnwrapsNewKey() {
        keyRotationService.initiateScheduledRotation("ls-kek-v2", RotationReason.SCHEDULED);

        assertThat(keyVersionRepository.findById(UUID.fromString(seedKekId)).orElseThrow().getStatus())
                .isEqualTo(KeyStatus.ROTATING);
        assertThat(keyVersionRepository.findActive())
                .isPresent()
                .get()
                .satisfies(kv -> assertThat(kv.getId().toString()).isNotEqualTo(seedKekId));
    }

    @Test
    void kekRotation_preRotationTokensDetokenisableDuringRotationWindow() {
        String visaToken = tokenise(VISA_PAN);
        String mcToken   = tokenise(MC_PAN);

        keyRotationService.initiateScheduledRotation("ls-kek-v2", RotationReason.SCHEDULED);

        // Old key is ROTATING — detokenisation must still work using old KEK from ring
        assertDetokenisable(visaToken, VISA_PAN);
        assertDetokenisable(mcToken,   MC_PAN);
    }

    @Test
    void kekRotation_afterBatch_allTokensMigratedAndDetokenisable() {
        String visaToken = tokenise(VISA_PAN);
        String mcToken   = tokenise(MC_PAN);

        UUID oldKekId = UUID.fromString(seedKekId);
        keyRotationService.initiateScheduledRotation("ls-kek-v2", RotationReason.SCHEDULED);
        UUID newKekId = keyVersionRepository.findActiveOrThrow().getId();

        rotationJob.processRotationBatch();

        assertThat(tokenVaultRepository.countActiveByKeyVersionId(oldKekId)).isZero();
        assertThat(tokenVaultRepository.findActiveByToken(visaToken).orElseThrow()
                .getKeyVersion().getId()).isEqualTo(newKekId);

        assertDetokenisable(visaToken, VISA_PAN);
        assertDetokenisable(mcToken,   MC_PAN);
    }

    @Test
    void kekRotation_afterBatch_oldKeyRetired() {
        tokenise(VISA_PAN);

        keyRotationService.initiateScheduledRotation("ls-kek-v2", RotationReason.SCHEDULED);
        rotationJob.processRotationBatch();

        assertThat(keyVersionRepository.findById(UUID.fromString(seedKekId)).orElseThrow().getStatus())
                .isEqualTo(KeyStatus.RETIRED);
    }

    @Test
    void kekRotation_auditLog_containsStartedAndCompletedEvents() {
        tokenise(VISA_PAN);

        keyRotationService.initiateScheduledRotation("ls-kek-v2", RotationReason.SCHEDULED);
        rotationJob.processRotationBatch();

        assertThat(auditLogRepository.findAll())
                .anyMatch(r -> "KEY_ROTATION_STARTED".equals(r.getEventType()))
                .anyMatch(r -> "TOKEN_REENCRYPTED".equals(r.getEventType()))
                .anyMatch(r -> "KEY_ROTATION_COMPLETED".equals(r.getEventType()));
    }

    // ── LS-R-2: HMAC rotation ─────────────────────────────────────────────────

    @Test
    void hmacRotation_preRotationTokenDetokenisableAfterBatch() {
        String visaToken = tokenise(VISA_PAN);

        hmacRotationService.initiateRotation("ls-hmac-v2");
        hmacRotationJob.processHmacRotationBatch();

        assertDetokenisable(visaToken, VISA_PAN);
        assertThat(keyVersionRepository.findById(UUID.fromString(seedHmacId)).orElseThrow().getStatus())
                .isEqualTo(KeyStatus.RETIRED);
    }

    @Test
    void hmacRotation_dualLookupDedupDuringRotationWindow() {
        String preRotationToken = tokenise(VISA_PAN);

        // Initiate rotation: new hash is now active; batch not yet run
        hmacRotationService.initiateRotation("ls-hmac-v2");

        // Re-tokenise same PAN — dual-lookup must hit the old hash and return the same token
        String duringWindowToken = tokenise(VISA_PAN);
        assertThat(duringWindowToken)
                .as("dedup during rotation window must return the same token (dual-lookup)")
                .isEqualTo(preRotationToken);

        // Complete rotation
        hmacRotationJob.processHmacRotationBatch();

        // Dedup must still work after batch completes (new hash is now canonical)
        String afterRotationToken = tokenise(VISA_PAN);
        assertThat(afterRotationToken).isEqualTo(preRotationToken);
    }

    @Test
    void hmacRotation_auditLog_containsStartedAndCompletedEvents() {
        tokenise(VISA_PAN);

        hmacRotationService.initiateRotation("ls-hmac-v2");
        hmacRotationJob.processHmacRotationBatch();

        assertThat(auditLogRepository.findAll())
                .anyMatch(r -> "HMAC_ROTATION_STARTED".equals(r.getEventType()))
                .anyMatch(r -> "PAN_HASH_RECOMPUTED".equals(r.getEventType()))
                .anyMatch(r -> "HMAC_ROTATION_COMPLETED".equals(r.getEventType()));
    }

    @Test
    void hmacRotation_oldKeyRetiredAfterBatch() {
        tokenise(VISA_PAN);

        hmacRotationService.initiateRotation("ls-hmac-v2");
        hmacRotationJob.processHmacRotationBatch();

        assertThat(keyVersionRepository.findById(UUID.fromString(seedHmacId)).orElseThrow().getStatus())
                .isEqualTo(KeyStatus.RETIRED);
        assertThat(hmacKeyRing.contains(seedHmacId)).isFalse();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private String tokenise(String pan) {
        TokeniseRequest request = new TokeniseRequest();
        request.setPan(pan);
        request.setCardScheme("VISA");
        request.setExpiryMonth(12);
        request.setExpiryYear(2027);
        ResponseEntity<TokeniseResponse> response =
                restTemplate.postForEntity("/api/v1/tokens", request, TokeniseResponse.class);
        assertThat(response.getStatusCode())
                .as("tokenise %s…%s", pan.substring(0, 4), pan.substring(pan.length() - 4))
                .isEqualTo(HttpStatus.CREATED);
        return response.getBody().getToken();
    }

    private void assertDetokenisable(String token, String expectedPan) {
        ResponseEntity<DetokeniseResponse> response =
                restTemplate.getForEntity("/api/v1/tokens/" + token, DetokeniseResponse.class);
        assertThat(response.getStatusCode())
                .as("token %s should detokenise successfully", token)
                .isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().getPan()).isEqualTo(expectedPan);
    }

    private void reloadSeedHmac() {
        KeyVersion seedHmac = keyVersionRepository.findById(UUID.fromString(seedHmacId)).orElseThrow();
        KeyVersion encryptingKek = keyVersionRepository.findById(seedHmac.getEncryptingKekId()).orElseThrow();
        byte[] kek = kmsProvider.unwrapKek(encryptingKek.getEncryptedKekBlob());
        byte[] hmacSecret = null;
        try {
            hmacSecret = cipher.decryptBytes(seedHmac.getEncryptedSecret(), kek);
            hmacKeyRing.load(seedHmacId, hmacSecret, seedHmac.getRotateBy());
        } finally {
            Arrays.fill(kek, (byte) 0);
            if (hmacSecret != null) Arrays.fill(hmacSecret, (byte) 0);
        }
    }
}
