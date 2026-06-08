package com.yourorg.tokenisation;

import com.yourorg.tokenisation.api.request.TokeniseRequest;
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
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for the tokenisation endpoint: {@code POST /api/v1/tokens}.
 *
 * <p>Tests verify the full stack: HTTP request → {@code TokenisationService}
 * → {@code TokenVaultRepository} → PostgreSQL → audit log record.
 *
 * <p>Uses a real PostgreSQL container via {@link AbstractIntegrationTest}
 * and {@code LocalDevKmsAdapter} — no cloud credentials required.
 */
class TokenisationIntegrationTest extends AbstractIntegrationTest {

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

    // ── Happy path ────────────────────────────────────────────────────────────

    @Test
    void tokenise_validRequest_returns201WithToken() {
        TokeniseRequest request = buildRequest(VISA_PAN);

        ResponseEntity<TokeniseResponse> response = postTokenise(request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getToken()).isNotBlank();
        assertThat(response.getBody().getLastFour()).isEqualTo("1111");
        assertThat(response.getBody().getCardScheme()).isEqualTo("VISA");
        assertThat(response.getBody().getCreatedAt()).isNotNull();
    }

    @Test
    void tokenise_validRequest_persistsTokenVaultRecord() {
        postTokenise(buildRequest(VISA_PAN));

        assertThat(tokenVaultRepository.count()).isEqualTo(1);
    }

    @Test
    void tokenise_validRequest_writesSuccessAuditRecord() {
        postTokenise(buildRequest(VISA_PAN));

        assertThat(auditLogRepository.count()).isEqualTo(1);
        var auditRecord = auditLogRepository.findAll().get(0);
        assertThat(auditRecord.getEventType()).isEqualTo("TOKENISE");
        assertThat(auditRecord.getOutcome()).isEqualTo("SUCCESS");
        assertThat(auditRecord.getTokenId()).isNotNull();
    }

    // ── De-duplication ────────────────────────────────────────────────────────

    @Test
    void tokenise_samePanCalledTwice_returnsSameTokenAndOneVaultRecord() {
        TokeniseRequest request = buildRequest(VISA_PAN);

        ResponseEntity<TokeniseResponse> first = postTokenise(request);
        ResponseEntity<TokeniseResponse> second = postTokenise(request);

        assertThat(first.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(second.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(first.getBody().getToken()).isEqualTo(second.getBody().getToken());
        assertThat(tokenVaultRepository.count()).isEqualTo(1);
    }

    @Test
    void tokenise_differentPans_createTwoDistinctTokens() {
        ResponseEntity<TokeniseResponse> visaResponse = postTokenise(buildRequest(VISA_PAN));
        ResponseEntity<TokeniseResponse> mcResponse = postTokenise(buildRequestWithScheme(MASTERCARD_PAN, "VISA"));

        assertThat(visaResponse.getBody().getToken()).isNotEqualTo(mcResponse.getBody().getToken());
        assertThat(tokenVaultRepository.count()).isEqualTo(2);
    }

    // ── Token revocation ──────────────────────────────────────────────────────

    @Test
    void revokeToken_activeToken_returns204() {
        String token = postTokenise(buildRequest(VISA_PAN)).getBody().getToken();

        ResponseEntity<Void> response = restTemplate.exchange(
                "/api/v1/tokens/" + token,
                org.springframework.http.HttpMethod.DELETE,
                null, Void.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
    }

    @Test
    void revokeToken_activeToken_subsequentGetReturns404() {
        String token = postTokenise(buildRequest(VISA_PAN)).getBody().getToken();

        restTemplate.exchange("/api/v1/tokens/" + token,
                org.springframework.http.HttpMethod.DELETE, null, Void.class);

        ResponseEntity<String> getResponse = restTemplate.getForEntity(
                "/api/v1/tokens/" + token, String.class);
        assertThat(getResponse.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void revokeToken_unknownToken_returns404() {
        ResponseEntity<String> response = restTemplate.exchange(
                "/api/v1/tokens/00000000-0000-0000-0000-000000000000",
                org.springframework.http.HttpMethod.DELETE,
                null, String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    // ── Card scheme validation ────────────────────────────────────────────────

    @Test
    void tokenise_invalidCardScheme_returns400() {
        TokeniseRequest request = buildRequestWithScheme(VISA_PAN, "BANANA");

        ResponseEntity<String> response = restTemplate.postForEntity(
                "/api/v1/tokens", request, String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(tokenVaultRepository.count()).isZero();
    }

    @Test
    void tokenise_validCardScheme_returns201() {
        TokeniseRequest request = buildRequestWithScheme(VISA_PAN, "VISA");

        ResponseEntity<TokeniseResponse> response = postTokenise(request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    }

    // ── Validation failures ──────────────────────────────────────────────────

    @Test
    void tokenise_missingPan_returns400() {
        TokeniseRequest request = buildRequest(null);

        ResponseEntity<String> response = restTemplate.postForEntity(
                "/api/v1/tokens", request, String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(tokenVaultRepository.count()).isZero();
    }

    @Test
    void tokenise_luhnInvalidPan_returns400() {
        TokeniseRequest request = buildRequest("4111111111111112");

        ResponseEntity<String> response = restTemplate.postForEntity(
                "/api/v1/tokens", request, String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(tokenVaultRepository.count()).isZero();
    }

    @Test
    void tokenise_luhnInvalidPan_writesFailureAuditRecord() {
        restTemplate.postForEntity("/api/v1/tokens", buildRequest("4111111111111112"), String.class);

        assertThat(auditLogRepository.count()).isEqualTo(1);
        var auditRecord = auditLogRepository.findAll().get(0);
        assertThat(auditRecord.getEventType()).isEqualTo("TOKENISE_FAILURE");
        assertThat(auditRecord.getOutcome()).isEqualTo("FAILURE");
    }

    // ── Response body contents ────────────────────────────────────────────────

    @Test
    void tokenise_responseLastFourMatchesPanLastFour() {
        ResponseEntity<TokeniseResponse> response = postTokenise(buildRequest(VISA_PAN));

        assertThat(response.getBody().getLastFour()).isEqualTo(
                VISA_PAN.substring(VISA_PAN.length() - 4));
    }

    @Test
    void tokenise_tokenIsValidUuidFormat() {
        ResponseEntity<TokeniseResponse> response = postTokenise(buildRequest(VISA_PAN));

        assertThat(UUID.fromString(response.getBody().getToken())).isNotNull();
    }

    // ── Test helpers ──────────────────────────────────────────────────────────

    private ResponseEntity<TokeniseResponse> postTokenise(TokeniseRequest request) {
        return restTemplate.postForEntity("/api/v1/tokens", request, TokeniseResponse.class);
    }

    private TokeniseRequest buildRequest(String pan) {
        return buildRequestWithScheme(pan, "VISA");
    }

    private TokeniseRequest buildRequestWithScheme(String pan, String cardScheme) {
        TokeniseRequest request = new TokeniseRequest();
        request.setPan(pan);
        request.setCardScheme(cardScheme);
        request.setExpiryMonth(12);
        request.setExpiryYear(2027);
        return request;
    }
}
