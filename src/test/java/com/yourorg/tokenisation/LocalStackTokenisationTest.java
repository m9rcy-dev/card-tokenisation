package com.yourorg.tokenisation;

import com.yourorg.tokenisation.api.request.TokeniseRequest;
import com.yourorg.tokenisation.api.response.DetokeniseResponse;
import com.yourorg.tokenisation.api.response.TokeniseResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Smoke tests for tokenisation and detokenisation against a real LocalStack KMS instance.
 *
 * <p>Verifies the fundamental AWS KMS path: KEK is decrypted via LocalStack KMS on startup,
 * loaded into the in-memory ring, and used for envelope encryption during tokenise/detokenise.
 *
 * <p>Run with: {@code mvn test -P localstack-tests} or {@code make localstack-test}.
 */
@Tag("localstack")
class LocalStackTokenisationTest extends AbstractLocalStackIntegrationTest {

    private static final String VISA_PAN = "4111111111111111";
    private static final String MC_PAN   = "5500005555555559";

    @Autowired private TestRestTemplate restTemplate;
    @Autowired private JdbcTemplate     jdbcTemplate;

    @BeforeEach
    void cleanTokenData() {
        jdbcTemplate.execute("DELETE FROM token_vault");
        jdbcTemplate.execute("DELETE FROM token_audit_log");
    }

    @Test
    void tokenise_withLocalStackKms_returns201AndToken() {
        ResponseEntity<TokeniseResponse> response = tokenise(VISA_PAN);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getToken()).isNotBlank();
    }

    @Test
    void detokenise_afterTokenise_returnsOriginalPan() {
        String token = tokenise(VISA_PAN).getBody().getToken();

        ResponseEntity<DetokeniseResponse> response =
                restTemplate.getForEntity("/api/v1/tokens/" + token, DetokeniseResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().getPan()).isEqualTo(VISA_PAN);
    }

    @Test
    void tokenise_samePan_returnsSameToken() {
        String firstToken  = tokenise(VISA_PAN).getBody().getToken();
        String secondToken = tokenise(VISA_PAN).getBody().getToken();

        assertThat(secondToken)
                .as("same PAN should produce the same token (deduplication)")
                .isEqualTo(firstToken);
    }

    @Test
    void tokenise_differentPans_returnsDifferentTokens() {
        String visaToken = tokenise(VISA_PAN).getBody().getToken();
        String mcToken   = tokenise(MC_PAN).getBody().getToken();

        assertThat(mcToken).isNotEqualTo(visaToken);
    }

    @Test
    void detokenise_unknownToken_returns404() {
        ResponseEntity<Void> response =
                restTemplate.getForEntity("/api/v1/tokens/UNKNOWN-TOKEN-9999", Void.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private ResponseEntity<TokeniseResponse> tokenise(String pan) {
        TokeniseRequest request = new TokeniseRequest();
        request.setPan(pan);
        request.setCardScheme("VISA");
        request.setExpiryMonth(12);
        request.setExpiryYear(2027);
        return restTemplate.postForEntity("/api/v1/tokens", request, TokeniseResponse.class);
    }
}
