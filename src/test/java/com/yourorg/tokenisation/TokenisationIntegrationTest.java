package com.yourorg.tokenisation;

import com.yourorg.tokenisation.api.request.CardReplacementRequest;
import com.yourorg.tokenisation.api.request.TokeniseRequest;
import com.yourorg.tokenisation.api.response.DetokeniseResponse;
import com.yourorg.tokenisation.api.response.TokeniseResponse;
import com.yourorg.tokenisation.repository.AuditLogRepository;
import com.yourorg.tokenisation.repository.TokenVaultRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
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
    void setUp() {
        // PATCH is not supported by java.net.HttpURLConnection — switch to Apache HttpClient
        restTemplate.getRestTemplate().setRequestFactory(new HttpComponentsClientHttpRequestFactory());
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

    // ── Card replacement ──────────────────────────────────────────────────────

    /** A second Luhn-valid Mastercard PAN for replacement tests. */
    private static final String NEW_MC_PAN = "5105105105105100";

    @Test
    void replaceCard_detokeniseAfterReplacement_returnsNewPan() {
        String token = postTokenise(buildRequest(MASTERCARD_PAN)).getBody().getToken();

        patchReplaceCard(token, NEW_MC_PAN);

        ResponseEntity<DetokeniseResponse> detokenised = restTemplate.getForEntity(
                "/api/v1/tokens/" + token, DetokeniseResponse.class);
        assertThat(detokenised.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(detokenised.getBody().getPan()).isEqualTo(NEW_MC_PAN);
    }

    @Test
    void replaceCard_tokenValueUnchangedAfterReplacement() {
        String tokenBefore = postTokenise(buildRequest(MASTERCARD_PAN)).getBody().getToken();

        ResponseEntity<TokeniseResponse> replaceResponse = patchReplaceCard(tokenBefore, NEW_MC_PAN);

        assertThat(replaceResponse.getBody().getToken()).isEqualTo(tokenBefore);
    }

    @Test
    void replaceCard_lastFourUpdated_afterReplacement() {
        String token = postTokenise(buildRequest(MASTERCARD_PAN)).getBody().getToken();

        ResponseEntity<TokeniseResponse> replaceResponse = patchReplaceCard(token, NEW_MC_PAN);

        assertThat(replaceResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(replaceResponse.getBody().getLastFour()).isEqualTo("5100");
    }

    @Test
    void replaceCard_expiryUpdated_afterReplacement() {
        String token = postTokenise(buildRequest(MASTERCARD_PAN)).getBody().getToken();
        patchReplaceCard(token, NEW_MC_PAN);

        ResponseEntity<DetokeniseResponse> detokenised = restTemplate.getForEntity(
                "/api/v1/tokens/" + token, DetokeniseResponse.class);
        assertThat(detokenised.getBody().getExpiryMonth()).isEqualTo(6);
        assertThat(detokenised.getBody().getExpiryYear()).isEqualTo(2029);
    }

    @Test
    void replaceCard_writesCardReplacedAuditRecord() {
        String token = postTokenise(buildRequest(MASTERCARD_PAN)).getBody().getToken();
        jdbcTemplate.execute("DELETE FROM token_audit_log");

        patchReplaceCard(token, NEW_MC_PAN);

        assertThat(auditLogRepository.count()).isEqualTo(1);
        var auditRecord = auditLogRepository.findAll().get(0);
        assertThat(auditRecord.getEventType()).isEqualTo("CARD_REPLACED");
        assertThat(auditRecord.getOutcome()).isEqualTo("SUCCESS");
    }

    @Test
    void replaceCard_samePanReplacedAgain_returns200() {
        String token = postTokenise(buildRequest(MASTERCARD_PAN)).getBody().getToken();
        // Replace with new PAN first
        patchReplaceCard(token, NEW_MC_PAN);
        // Replace again with the same new PAN — identity case, must succeed
        ResponseEntity<TokeniseResponse> response = patchReplaceCard(token, NEW_MC_PAN);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void replaceCard_newPanAlreadyHasToken_returns409() {
        // Tokenise MASTERCARD_PAN → token-A
        String tokenA = postTokenise(buildRequest(MASTERCARD_PAN)).getBody().getToken();
        // Tokenise NEW_MC_PAN → token-B
        postTokenise(buildRequest(NEW_MC_PAN));
        // Try to replace token-A with NEW_MC_PAN — conflict, NEW_MC_PAN already has token-B
        ResponseEntity<String> response = restTemplate.exchange(
                "/api/v1/tokens/" + tokenA,
                HttpMethod.PATCH,
                new HttpEntity<>(buildReplacementRequest(NEW_MC_PAN)),
                String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
    }

    @Test
    void replaceCard_unknownToken_returns404() {
        ResponseEntity<String> response = restTemplate.exchange(
                "/api/v1/tokens/00000000-0000-0000-0000-000000000000",
                HttpMethod.PATCH,
                new HttpEntity<>(buildReplacementRequest(NEW_MC_PAN)),
                String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void replaceCard_revokedToken_returns404() {
        String token = postTokenise(buildRequest(MASTERCARD_PAN)).getBody().getToken();
        restTemplate.exchange("/api/v1/tokens/" + token,
                HttpMethod.DELETE, null, Void.class);

        ResponseEntity<String> response = restTemplate.exchange(
                "/api/v1/tokens/" + token,
                HttpMethod.PATCH,
                new HttpEntity<>(buildReplacementRequest(NEW_MC_PAN)),
                String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void replaceCard_invalidCardScheme_returns400() {
        String token = postTokenise(buildRequest(MASTERCARD_PAN)).getBody().getToken();

        CardReplacementRequest request = buildReplacementRequest(NEW_MC_PAN);
        request.setCardScheme("AMEX");
        ResponseEntity<String> response = restTemplate.exchange(
                "/api/v1/tokens/" + token, HttpMethod.PATCH,
                new HttpEntity<>(request), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void replaceCard_luhnInvalidPan_returns400() {
        String token = postTokenise(buildRequest(MASTERCARD_PAN)).getBody().getToken();

        ResponseEntity<String> response = restTemplate.exchange(
                "/api/v1/tokens/" + token, HttpMethod.PATCH,
                new HttpEntity<>(buildReplacementRequest("4111111111111112")), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void replaceCard_missingPan_returns400() {
        String token = postTokenise(buildRequest(MASTERCARD_PAN)).getBody().getToken();

        ResponseEntity<String> response = restTemplate.exchange(
                "/api/v1/tokens/" + token, HttpMethod.PATCH,
                new HttpEntity<>(buildReplacementRequest(null)), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    // ── Test helpers ──────────────────────────────────────────────────────────

    private ResponseEntity<TokeniseResponse> patchReplaceCard(String token, String newPan) {
        return restTemplate.exchange(
                "/api/v1/tokens/" + token,
                HttpMethod.PATCH,
                new HttpEntity<>(buildReplacementRequest(newPan)),
                TokeniseResponse.class);
    }

    private CardReplacementRequest buildReplacementRequest(String pan) {
        CardReplacementRequest request = new CardReplacementRequest();
        request.setPan(pan);
        request.setCardScheme("MC");
        request.setExpiryMonth(6);
        request.setExpiryYear(2029);
        return request;
    }

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
