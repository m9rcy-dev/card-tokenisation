package com.yourorg.tokenisation;

import com.yourorg.tokenisation.api.request.TokeniseRequest;
import com.yourorg.tokenisation.api.response.HealthResponse;
import com.yourorg.tokenisation.api.response.MetricsResponse;
import com.yourorg.tokenisation.api.response.TokeniseResponse;
import com.yourorg.tokenisation.domain.TokenType;
import com.yourorg.tokenisation.monitoring.MetricsCollector;
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

import java.sql.Timestamp;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for {@code GET /api/v1/health} and {@code GET /api/v1/metrics}.
 *
 * <p>Uses a real PostgreSQL container via {@link AbstractIntegrationTest} and verifies:
 * <ul>
 *   <li>Health endpoint returns 200 UP when DB and key ring are reachable.
 *   <li>Metrics endpoint returns 200 with correct counter values.
 *   <li>Metrics counters increment correctly after tokenise and detokenise requests.
 *   <li>Swagger UI is accessible.
 * </ul>
 */
class HealthMetricsIntegrationTest extends AbstractIntegrationTest {

    private static final String VISA_PAN = "4111111111111111";
    private static final String MERCHANT_A = "HEALTH_MERCHANT";

    @Autowired private TestRestTemplate restTemplate;
    @Autowired private JdbcTemplate jdbcTemplate;
    @Autowired private MetricsCollector metricsCollector;

    @BeforeEach
    void cleanDatabase() {
        jdbcTemplate.execute("DELETE FROM token_vault");
        jdbcTemplate.execute("DELETE FROM token_audit_log");

        // Ensure seed key row is present
        Timestamp rotateBy = Timestamp.from(Instant.now().plusSeconds(365L * 24 * 60 * 60));
        jdbcTemplate.update("""
                INSERT INTO key_versions (id, kms_key_id, kms_provider, key_alias, encrypted_kek_blob,
                    status, activated_at, rotate_by, created_by, checksum)
                VALUES (?::uuid, ?, ?, ?, ?, ?, now(), ?, ?, ?)
                ON CONFLICT (id) DO NOTHING
                """,
                SEED_KEY_VERSION_ID, "local-dev-key", "LOCAL_DEV",
                "integration-test-seed-key", "ignored", "ACTIVE",
                rotateBy, "test-seeder", "seed-checksum");
    }

    // ── Health ────────────────────────────────────────────────────────────────

    @Test
    void health_withDatabaseAndKeyRing_returns200Up() {
        ResponseEntity<HealthResponse> response =
                restTemplate.getForEntity("/api/v1/health", HealthResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getStatus()).isEqualTo("UP");
    }

    @Test
    void health_checksContainDatabaseAndKeyRing() {
        ResponseEntity<HealthResponse> response =
                restTemplate.getForEntity("/api/v1/health", HealthResponse.class);

        assertThat(response.getBody().getChecks())
                .containsEntry("database", "UP")
                .containsEntry("keyRing", "UP");
    }

    @Test
    void health_responseContainsTimestamp() {
        ResponseEntity<HealthResponse> response =
                restTemplate.getForEntity("/api/v1/health", HealthResponse.class);

        assertThat(response.getBody().getTimestamp()).isNotNull();
    }

    // ── Metrics ───────────────────────────────────────────────────────────────

    @Test
    void metrics_returns200() {
        ResponseEntity<MetricsResponse> response =
                restTemplate.getForEntity("/api/v1/metrics", MetricsResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
    }

    @Test
    void metrics_uptimeIsPositive() {
        ResponseEntity<MetricsResponse> response =
                restTemplate.getForEntity("/api/v1/metrics", MetricsResponse.class);

        assertThat(response.getBody().getUptimeSeconds()).isGreaterThanOrEqualTo(0);
    }

    @Test
    void metrics_responseContainsTimestamp() {
        ResponseEntity<MetricsResponse> response =
                restTemplate.getForEntity("/api/v1/metrics", MetricsResponse.class);

        assertThat(response.getBody().getTimestamp()).isNotNull();
    }

    @Test
    void metrics_tokeniseRequest_incrementsTokeniseCounter() {
        long before = metricsCollector.getTokeniseRequests();

        TokeniseRequest request = buildRequest(VISA_PAN);
        ResponseEntity<TokeniseResponse> tokeniseResp =
                restTemplate.postForEntity("/api/v1/tokens", request, TokeniseResponse.class);
        assertThat(tokeniseResp.getStatusCode()).isEqualTo(HttpStatus.CREATED);

        ResponseEntity<MetricsResponse> metrics =
                restTemplate.getForEntity("/api/v1/metrics", MetricsResponse.class);

        assertThat(metrics.getBody().getTokeniseRequests()).isGreaterThan(before);
    }

    @Test
    void metrics_detokeniseRequest_incrementsDetokeniseCounter() {
        // Tokenise first to get a token
        TokeniseRequest request = buildRequest(VISA_PAN);
        String token = restTemplate.postForEntity("/api/v1/tokens", request, TokeniseResponse.class)
                .getBody().getToken();

        long before = metricsCollector.getDetokeniseRequests();

        // Detokenise
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Merchant-ID", MERCHANT_A);
        restTemplate.exchange(
                "/api/v1/tokens/" + token,
                HttpMethod.GET,
                new HttpEntity<>(headers),
                String.class);

        ResponseEntity<MetricsResponse> metrics =
                restTemplate.getForEntity("/api/v1/metrics", MetricsResponse.class);

        assertThat(metrics.getBody().getDetokeniseRequests()).isGreaterThan(before);
    }

    // ── Swagger UI ────────────────────────────────────────────────────────────

    @Test
    void swaggerUi_isAccessible() {
        ResponseEntity<String> response =
                restTemplate.getForEntity("/swagger-ui.html", String.class);

        // Swagger UI redirects to /swagger-ui/index.html — 3xx or 200 both indicate accessible
        assertThat(response.getStatusCode().value())
                .as("Swagger UI should be accessible (200 or 3xx)")
                .isLessThan(400);
    }

    @Test
    void openApiDocs_isAccessible() {
        ResponseEntity<String> response =
                restTemplate.getForEntity("/v3/api-docs", String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("Card Tokenisation System API");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private TokeniseRequest buildRequest(String pan) {
        TokeniseRequest r = new TokeniseRequest();
        r.setPan(pan);
        r.setTokenType(TokenType.ONE_TIME);
        r.setMerchantId(MERCHANT_A);
        r.setCardScheme("VISA");
        r.setExpiryMonth(12);
        r.setExpiryYear(2027);
        return r;
    }
}
