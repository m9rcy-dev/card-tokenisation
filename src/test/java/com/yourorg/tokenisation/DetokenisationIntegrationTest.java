package com.yourorg.tokenisation;

import com.yourorg.tokenisation.api.request.TokeniseRequest;
import com.yourorg.tokenisation.api.response.DetokeniseResponse;
import com.yourorg.tokenisation.api.response.TokeniseResponse;
import com.yourorg.tokenisation.repository.AuditLogRepository;
import com.yourorg.tokenisation.repository.TokenVaultRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Timestamp;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for the detokenisation endpoint: {@code GET /api/v1/tokens/{token}}.
 *
 * <p>Tests verify the full stack: HTTP GET → {@code DetokenisationService}
 * → {@code TokenVaultRepository} → AES-256-GCM decrypt → audit log record.
 *
 * <p>Uses a real PostgreSQL container via {@link AbstractIntegrationTest}
 * and {@code LocalDevKmsAdapter} — no cloud credentials required.
 *
 * <p>Round-trip tests: a token is first created via {@code POST /api/v1/tokens}
 * and then recovered via {@code GET /api/v1/tokens/{token}}.
 */
class DetokenisationIntegrationTest extends AbstractIntegrationTest {

    /** Luhn-valid 16-digit Visa test PAN. */
    private static final String VISA_PAN = "4111111111111111";

    /** Luhn-valid 16-digit Mastercard test PAN. */
    private static final String MASTERCARD_PAN = "5500005555555559";

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private TokenVaultRepository tokenVaultRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void cleanDatabase() {
        jdbcTemplate.execute("DELETE FROM token_vault");
        jdbcTemplate.execute("DELETE FROM token_audit_log");
        Timestamp rotateBy = Timestamp.from(Instant.now().plusSeconds(365L * 24 * 60 * 60));
        jdbcTemplate.update("""
                INSERT INTO key_versions (id, kms_key_id, kms_provider, key_alias, encrypted_kek_blob,
                    status, activated_at, rotate_by, created_by, checksum)
                VALUES (?::uuid, ?, ?, ?, ?, ?, now(), ?, ?, ?)
                ON CONFLICT (id) DO NOTHING
                """,
                SEED_KEY_VERSION_ID,
                "local-dev-key",
                "LOCAL_DEV",
                "integration-test-seed-key",
                "ignored",
                "ACTIVE",
                rotateBy,
                "test-seeder",
                "seed-checksum"
        );
    }

    // ── Round-trip PAN recovery ──────────────────────────────────────────────

    @Test
    void detokenise_roundTrip_recoversOriginalPan() {
        String token = tokenise(VISA_PAN);

        ResponseEntity<DetokeniseResponse> response = detokenise(token);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getPan()).isEqualTo(VISA_PAN);
    }

    @Test
    void detokenise_roundTrip_responseContainsCardMetadata() {
        String token = tokenise(VISA_PAN);

        ResponseEntity<DetokeniseResponse> response = detokenise(token);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().getLastFour()).isEqualTo("1111");
        assertThat(response.getBody().getCardScheme()).isEqualTo("VISA");
        assertThat(response.getBody().getExpiryMonth()).isEqualTo(12);
        assertThat(response.getBody().getExpiryYear()).isEqualTo(2027);
    }

    @Test
    void detokenise_roundTrip_differentPans_recoversCorrectPanForEachToken() {
        String visaToken = tokenise(VISA_PAN);
        String mcToken = tokeniseWithScheme(MASTERCARD_PAN, "VISA");

        assertThat(detokenise(visaToken).getBody().getPan()).isEqualTo(VISA_PAN);
        assertThat(detokenise(mcToken).getBody().getPan()).isEqualTo(MASTERCARD_PAN);
    }

    @Test
    void detokenise_samePanTwice_sameTokenDetokenisesCorrectly() {
        String token = tokenise(VISA_PAN);
        String sameToken = tokenise(VISA_PAN);
        assertThat(token).isEqualTo(sameToken);

        ResponseEntity<DetokeniseResponse> response = detokenise(token);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().getPan()).isEqualTo(VISA_PAN);
    }

    @Test
    void detokenise_writesSuccessAuditRecord() {
        String token = tokenise(VISA_PAN);
        jdbcTemplate.execute("DELETE FROM token_audit_log");

        detokenise(token);

        assertThat(auditLogRepository.count()).isEqualTo(1);
        var auditRecord = auditLogRepository.findAll().get(0);
        assertThat(auditRecord.getEventType()).isEqualTo("DETOKENISE");
        assertThat(auditRecord.getOutcome()).isEqualTo("SUCCESS");
    }

    // ── Expired token ─────────────────────────────────────────────────────────

    @Test
    void detokenise_expiredToken_returns404() {
        String token = tokenise(VISA_PAN);
        // Directly expire the token in the DB
        jdbcTemplate.update(
                "UPDATE token_vault SET expires_at = ? WHERE token = ?",
                Timestamp.from(Instant.now().minusSeconds(60)), token);

        ResponseEntity<String> response = restTemplate.getForEntity(
                "/api/v1/tokens/" + token, String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    // ── Token not found ────────────────────────────────────────────────────────

    @Test
    void detokenise_unknownToken_returns404() {
        ResponseEntity<String> response = restTemplate.getForEntity(
                "/api/v1/tokens/00000000-0000-0000-0000-000000000000", String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    // ── Rate limiting ──────────────────────────────────────────────────────────

    @Test
    void detokenise_withinRateLimit_returns200() {
        String token = tokenise(VISA_PAN);

        ResponseEntity<DetokeniseResponse> response = detokenise(token);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    // ── Test helpers ──────────────────────────────────────────────────────────

    private String tokenise(String pan) {
        return tokeniseWithScheme(pan, "VISA");
    }

    private String tokeniseWithScheme(String pan, String cardScheme) {
        TokeniseRequest request = new TokeniseRequest();
        request.setPan(pan);
        request.setCardScheme(cardScheme);
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
