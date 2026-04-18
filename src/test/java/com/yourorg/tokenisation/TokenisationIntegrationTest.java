package com.yourorg.tokenisation;

import com.yourorg.tokenisation.api.request.TokeniseRequest;
import com.yourorg.tokenisation.api.response.TokeniseResponse;
import com.yourorg.tokenisation.domain.TokenType;
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

    private static final String MERCHANT_A = "MERCHANT_A";
    private static final String MERCHANT_B = "MERCHANT_B";

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
        // Restore the seed ACTIVE key version in case a prior test class deleted it.
        // The in-memory key ring was populated with SEED_KEY_VERSION_ID at context startup
        // and persists across tests. The DB row must match for keyVersionRepository.findActiveOrThrow().
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

    // ── Happy path — ONE_TIME ─────────────────────────────────────────────────

    @Test
    void tokenise_validOneTimeRequest_returns201WithToken() {
        TokeniseRequest request = buildRequest(VISA_PAN, TokenType.ONE_TIME, MERCHANT_A);

        ResponseEntity<TokeniseResponse> response = postTokenise(request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getToken()).isNotBlank();
        assertThat(response.getBody().getTokenType()).isEqualTo(TokenType.ONE_TIME);
        assertThat(response.getBody().getLastFour()).isEqualTo("1111");
        assertThat(response.getBody().getCardScheme()).isEqualTo("VISA");
        assertThat(response.getBody().getCreatedAt()).isNotNull();
    }

    @Test
    void tokenise_validOneTimeRequest_persistsTokenVaultRecord() {
        TokeniseRequest request = buildRequest(VISA_PAN, TokenType.ONE_TIME, MERCHANT_A);

        ResponseEntity<TokeniseResponse> response = postTokenise(request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(tokenVaultRepository.count()).isEqualTo(1);
    }

    @Test
    void tokenise_validOneTimeRequest_writesSuccessAuditRecord() {
        TokeniseRequest request = buildRequest(VISA_PAN, TokenType.ONE_TIME, MERCHANT_A);

        postTokenise(request);

        assertThat(auditLogRepository.count()).isEqualTo(1);
        var auditRecord = auditLogRepository.findAll().get(0);
        assertThat(auditRecord.getEventType()).isEqualTo("TOKENISE");
        assertThat(auditRecord.getOutcome()).isEqualTo("SUCCESS");
        assertThat(auditRecord.getMerchantId()).isEqualTo(MERCHANT_A);
        assertThat(auditRecord.getTokenId()).isNotNull();
    }

    @Test
    void tokenise_oneTimeCalledTwice_createsTwoDistinctTokens() {
        TokeniseRequest request = buildRequest(VISA_PAN, TokenType.ONE_TIME, MERCHANT_A);

        ResponseEntity<TokeniseResponse> first = postTokenise(request);
        ResponseEntity<TokeniseResponse> second = postTokenise(request);

        assertThat(first.getBody().getToken()).isNotEqualTo(second.getBody().getToken());
        assertThat(tokenVaultRepository.count()).isEqualTo(2);
    }

    // ── Happy path — RECURRING ────────────────────────────────────────────────

    @Test
    void tokenise_recurringCalledTwice_returnsSameTokenAndOneVaultRecord() {
        TokeniseRequest request = buildRequest(VISA_PAN, TokenType.RECURRING, MERCHANT_A);

        ResponseEntity<TokeniseResponse> first = postTokenise(request);
        ResponseEntity<TokeniseResponse> second = postTokenise(request);

        assertThat(first.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(second.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(first.getBody().getToken()).isEqualTo(second.getBody().getToken());
        assertThat(tokenVaultRepository.count()).isEqualTo(1);
    }

    @Test
    void tokenise_recurringDifferentMerchants_createsTwoDistinctTokens() {
        TokeniseRequest requestA = buildRequest(VISA_PAN, TokenType.RECURRING, MERCHANT_A);
        TokeniseRequest requestB = buildRequest(VISA_PAN, TokenType.RECURRING, MERCHANT_B);

        ResponseEntity<TokeniseResponse> responseA = postTokenise(requestA);
        ResponseEntity<TokeniseResponse> responseB = postTokenise(requestB);

        // Same PAN but different merchants — de-dup scope is per-merchant
        assertThat(responseA.getBody().getToken()).isNotEqualTo(responseB.getBody().getToken());
        assertThat(tokenVaultRepository.count()).isEqualTo(2);
    }

    @Test
    void tokenise_recurringDifferentPans_createsTwoDistinctTokens() {
        TokeniseRequest requestVisa = buildRequest(VISA_PAN, TokenType.RECURRING, MERCHANT_A);
        TokeniseRequest requestMc = buildRequest(MASTERCARD_PAN, TokenType.RECURRING, MERCHANT_A);

        ResponseEntity<TokeniseResponse> responseVisa = postTokenise(requestVisa);
        ResponseEntity<TokeniseResponse> responseMc = postTokenise(requestMc);

        assertThat(responseVisa.getBody().getToken()).isNotEqualTo(responseMc.getBody().getToken());
        assertThat(tokenVaultRepository.count()).isEqualTo(2);
    }

    // ── Validation failures ──────────────────────────────────────────────────

    @Test
    void tokenise_missingPan_returns400() {
        TokeniseRequest request = buildRequest(null, TokenType.ONE_TIME, MERCHANT_A);

        ResponseEntity<String> response = restTemplate.postForEntity(
                "/api/v1/tokens", request, String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(tokenVaultRepository.count()).isZero();
    }

    @Test
    void tokenise_luhnInvalidPan_returns400() {
        // 4111111111111112 fails Luhn (valid format, invalid checksum)
        TokeniseRequest request = buildRequest("4111111111111112", TokenType.ONE_TIME, MERCHANT_A);

        ResponseEntity<String> response = restTemplate.postForEntity(
                "/api/v1/tokens", request, String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(tokenVaultRepository.count()).isZero();
    }

    @Test
    void tokenise_missingMerchantId_returns400() {
        TokeniseRequest request = buildRequest(VISA_PAN, TokenType.ONE_TIME, null);

        ResponseEntity<String> response = restTemplate.postForEntity(
                "/api/v1/tokens", request, String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void tokenise_missingTokenType_returns400() {
        TokeniseRequest request = buildRequest(VISA_PAN, null, MERCHANT_A);

        ResponseEntity<String> response = restTemplate.postForEntity(
                "/api/v1/tokens", request, String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    // ── Audit log on validation failure ──────────────────────────────────────

    @Test
    void tokenise_luhnInvalidPan_writesFailureAuditRecord() {
        TokeniseRequest request = buildRequest("4111111111111112", TokenType.ONE_TIME, MERCHANT_A);

        restTemplate.postForEntity("/api/v1/tokens", request, String.class);

        // Bean Validation failure (400) does NOT go through the service, so no service audit
        // Luhn validation failure (400) DOES go through the service — expects TOKENISE_FAILURE
        assertThat(auditLogRepository.count()).isEqualTo(1);
        var auditRecord = auditLogRepository.findAll().get(0);
        assertThat(auditRecord.getEventType()).isEqualTo("TOKENISE_FAILURE");
        assertThat(auditRecord.getOutcome()).isEqualTo("FAILURE");
    }

    // ── Response body contents ────────────────────────────────────────────────

    @Test
    void tokenise_visaCard_responseLastFourMatchesPanLastFour() {
        TokeniseRequest request = buildRequest(VISA_PAN, TokenType.ONE_TIME, MERCHANT_A);

        ResponseEntity<TokeniseResponse> response = postTokenise(request);

        assertThat(response.getBody().getLastFour()).isEqualTo(
                VISA_PAN.substring(VISA_PAN.length() - 4));
    }

    @Test
    void tokenise_tokenIsValidUuidFormat() {
        TokeniseRequest request = buildRequest(VISA_PAN, TokenType.ONE_TIME, MERCHANT_A);

        ResponseEntity<TokeniseResponse> response = postTokenise(request);

        String token = response.getBody().getToken();
        // Should not throw — valid UUID format
        assertThat(UUID.fromString(token)).isNotNull();
    }

    // ── Test helpers ──────────────────────────────────────────────────────────

    private ResponseEntity<TokeniseResponse> postTokenise(TokeniseRequest request) {
        return restTemplate.postForEntity("/api/v1/tokens", request, TokeniseResponse.class);
    }

    private TokeniseRequest buildRequest(String pan, TokenType tokenType, String merchantId) {
        TokeniseRequest request = new TokeniseRequest();
        request.setPan(pan);
        request.setTokenType(tokenType);
        request.setMerchantId(merchantId);
        request.setCardScheme("VISA");
        request.setExpiryMonth(12);
        request.setExpiryYear(2027);
        return request;
    }
}
