package com.yourorg.tokenisation;

import com.yourorg.tokenisation.api.request.TokeniseRequest;
import com.yourorg.tokenisation.api.response.DetokeniseResponse;
import com.yourorg.tokenisation.api.response.TokeniseResponse;
import com.yourorg.tokenisation.crypto.InMemoryHmacKeyRing;
import com.yourorg.tokenisation.domain.KeyStatus;
import com.yourorg.tokenisation.domain.KeyVersion;
import com.yourorg.tokenisation.kms.KmsProvider;
import com.yourorg.tokenisation.repository.KeyVersionRepository;
import com.yourorg.tokenisation.repository.TokenVaultRepository;
import com.yourorg.tokenisation.rotation.HmacRotationJob;
import com.yourorg.tokenisation.rotation.HmacRotationService;
import org.junit.jupiter.api.BeforeEach;
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
 * Integration tests for the HMAC key rotation pipeline.
 *
 * <p>Verifies the full HMAC rotation cycle end-to-end:
 * <ol>
 *   <li>Tokens tokenised before rotation are deduplicated by the old HMAC hash.
 *   <li>{@link HmacRotationService#initiateRotation} creates a new ACTIVE HMAC version and
 *       moves the old to ROTATING.  New tokenisations use the new hash immediately.
 *   <li>During the rotation window, duplicate detection for old tokens falls back to the
 *       old hash (same token returned for same PAN).
 *   <li>{@link HmacRotationJob#processHmacRotationBatch()} re-hashes all vault records
 *       to the new HMAC version.
 *   <li>After completion, the old HMAC version is retired.
 *   <li>All pre-rotation tokens remain detokenisable.
 *   <li>De-duplication works normally after rotation completes (new hash is canonical).
 * </ol>
 *
 * <p>The HMAC batch scheduler is disabled in the test profile
 * ({@code rotation.hmac-batch.cron: "-"}).  Tests invoke
 * {@link HmacRotationJob#processHmacRotationBatch()} directly for deterministic control.
 */
class HmacRotationIntegrationTest extends AbstractIntegrationTest {

    private static final String VISA_PAN = "4111111111111111";
    private static final String MC_PAN   = "5500005555555559";
    private static final String AMEX_PAN = "378282246310005";

    @Autowired private TestRestTemplate restTemplate;
    @Autowired private KeyVersionRepository keyVersionRepository;
    @Autowired private TokenVaultRepository tokenVaultRepository;
    @Autowired private HmacRotationService hmacRotationService;
    @Autowired private HmacRotationJob hmacRotationJob;
    @Autowired private InMemoryHmacKeyRing hmacKeyRing;
    @Autowired private KmsProvider kmsProvider;
    @Autowired private JdbcTemplate jdbcTemplate;

    // Discovered dynamically per test — LocalDevHmacKeySeeder uses @GeneratedValue (random UUID)
    private UUID hmacSeedId;

    @BeforeEach
    void cleanSlate() {
        jdbcTemplate.execute("DELETE FROM token_vault");
        jdbcTemplate.execute("DELETE FROM token_audit_log");

        // Discover the actual seed HMAC UUID by key_alias (set by LocalDevHmacKeySeeder)
        String seedIdStr = jdbcTemplate.queryForObject(
                "SELECT id::text FROM key_versions WHERE key_type = 'HMAC' AND key_alias = 'local-dev-hmac-seed'",
                String.class);
        this.hmacSeedId = UUID.fromString(seedIdStr);

        // Reset DB: retire non-seed HMAC rows, re-activate seed, clear retired_at
        jdbcTemplate.execute(
                "UPDATE key_versions SET status = 'RETIRED', retired_at = NULL "
                        + "WHERE key_type = 'HMAC' AND id != '" + seedIdStr + "'::uuid");
        jdbcTemplate.execute(
                "UPDATE key_versions SET status = 'ACTIVE', retired_at = NULL "
                        + "WHERE id = '" + seedIdStr + "'::uuid");

        // Drain non-seed versions from the ring
        try {
            String activeId = hmacKeyRing.getActiveVersionId();
            if (!activeId.equals(seedIdStr)) {
                hmacKeyRing.retire(activeId);
            }
        } catch (IllegalStateException ignored) {
            // ring had no active pointer — nothing to drain
        }
        hmacKeyRing.findRotatingVersionId()
                .filter(id -> !id.equals(seedIdStr))
                .ifPresent(hmacKeyRing::retire);

        // Reload seed secret into ring when it was retired during a previous rotation test
        if (!hmacKeyRing.contains(seedIdStr)) {
            reloadSeedHmacIntoRing(seedIdStr);
        }
        hmacKeyRing.promoteActive(seedIdStr);
    }

    private void reloadSeedHmacIntoRing(String seedIdStr) {
        KeyVersion seedHmac = keyVersionRepository.findById(UUID.fromString(seedIdStr))
                .orElseThrow(() -> new IllegalStateException("Seed HMAC row missing: " + seedIdStr));
        byte[] hmacSecret = null;
        try {
            hmacSecret = kmsProvider.unwrapHmacKey(seedHmac.getEncryptedSecret());
            hmacKeyRing.load(seedIdStr, hmacSecret, seedHmac.getRotateBy());
        } finally {
            if (hmacSecret != null) Arrays.fill(hmacSecret, (byte) 0);
        }
    }

    // ── HMR-1: Pre-rotation tokens are detokenisable after rotation ───────────

    @Test
    void hmacRotation_allPreRotationTokensDetokenisableAfterRotation() {
        // 1. Tokenise cards before rotation
        String visaToken = tokenise(VISA_PAN);
        String mcToken   = tokenise(MC_PAN);

        assertThat(visaToken).isNotBlank();
        assertThat(mcToken).isNotBlank();

        // 2. Initiate rotation
        UUID newHmacVersionId = hmacRotationService.initiateRotation("hmac-key-test-2027");
        assertThat(newHmacVersionId).isNotNull();

        // 3. Run batch to completion
        hmacRotationJob.processHmacRotationBatch();

        // 4. Verify all pre-rotation tokens are still detokenisable
        assertDetokenisable(visaToken);
        assertDetokenisable(mcToken);

        // 5. Verify old HMAC version is RETIRED in DB
        KeyVersion oldHmac = keyVersionRepository.findById(hmacSeedId).orElseThrow();
        assertThat(oldHmac.getStatus()).isEqualTo(KeyStatus.RETIRED);
    }

    // ── HMR-2: De-dup continues to work after rotation ───────────────────────

    @Test
    void hmacRotation_dedupWorksAfterRotationCompletes() {
        // Tokenise before rotation
        String firstToken = tokenise(VISA_PAN);

        // Rotate
        hmacRotationService.initiateRotation("hmac-key-dedup-test");
        hmacRotationJob.processHmacRotationBatch();

        // Re-tokenise same PAN → must get same token (dedup)
        String secondToken = tokenise(VISA_PAN);
        assertThat(secondToken).isEqualTo(firstToken);
    }

    // ── HMR-3: Dual-lookup dedup during rotation window ──────────────────────

    @Test
    void hmacRotation_dedupWorksForOldTokensDuringRotationWindow() {
        // 1. Tokenise before rotation (old hash)
        String preRotationToken = tokenise(VISA_PAN);

        // 2. Initiate rotation — new hash active, old batch not yet run
        hmacRotationService.initiateRotation("hmac-key-window-test");

        // 3. Re-tokenise same PAN — must hit old hash via dual-lookup
        String duringRotationToken = tokenise(VISA_PAN);
        assertThat(duringRotationToken)
                .as("dedup must return the same token during rotation window (dual-lookup)")
                .isEqualTo(preRotationToken);

        // 4. Complete rotation
        hmacRotationJob.processHmacRotationBatch();

        // 5. Dedup still works after rotation completes (new hash is now canonical)
        String afterRotationToken = tokenise(VISA_PAN);
        assertThat(afterRotationToken)
                .as("dedup must still work after rotation using re-hashed vault record")
                .isEqualTo(preRotationToken);
    }

    // ── HMR-4: Vault records get new hmac_key_version_id after batch ─────────

    @Test
    void hmacRotation_batchUpdatesHmacKeyVersionIdOnAllVaultRecords() {
        tokenise(VISA_PAN);
        tokenise(MC_PAN);
        tokenise(AMEX_PAN);

        UUID newHmacId = hmacRotationService.initiateRotation("hmac-key-batch-test");

        // Records still carry old version before batch runs
        long onOldBefore = tokenVaultRepository.countActiveByHmacVersionId(hmacSeedId);
        assertThat(onOldBefore).isEqualTo(3);

        hmacRotationJob.processHmacRotationBatch();

        // All records should now be on the new HMAC version
        long onOldAfter = tokenVaultRepository.countActiveByHmacVersionId(hmacSeedId);
        long onNewAfter = tokenVaultRepository.countActiveByHmacVersionId(newHmacId);

        assertThat(onOldAfter).as("no records should remain on old HMAC version").isZero();
        assertThat(onNewAfter).as("all records should be on new HMAC version").isEqualTo(3);
    }

    // ── HMR-5: New tokens tokenised after rotation use new hash immediately ──

    @Test
    void hmacRotation_newTokensAfterRotationUseNewHash() {
        // Rotate with no prior vault records
        UUID newHmacId = hmacRotationService.initiateRotation("hmac-key-new-tokens-test");
        hmacRotationJob.processHmacRotationBatch();

        // Tokenise after rotation completes
        tokenise(VISA_PAN);

        // Token must reference the new HMAC version
        long onNewVersion = tokenVaultRepository.countActiveByHmacVersionId(newHmacId);
        assertThat(onNewVersion).isEqualTo(1);
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
                .as("tokenise %s", pan.substring(pan.length() - 4))
                .isEqualTo(HttpStatus.CREATED);
        assertThat(response.getBody()).isNotNull();
        return response.getBody().getToken();
    }

    private void assertDetokenisable(String token) {
        ResponseEntity<DetokeniseResponse> response =
                restTemplate.getForEntity("/api/v1/tokens/" + token, DetokeniseResponse.class);
        assertThat(response.getStatusCode())
                .as("token %s should be detokenisable", token)
                .isEqualTo(HttpStatus.OK);
    }
}
