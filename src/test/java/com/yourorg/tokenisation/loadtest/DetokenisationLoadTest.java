package com.yourorg.tokenisation.loadtest;

import com.yourorg.tokenisation.api.request.TokeniseRequest;
import com.yourorg.tokenisation.api.response.DetokeniseResponse;
import com.yourorg.tokenisation.api.response.TokeniseResponse;
import com.yourorg.tokenisation.domain.TokenType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Instant;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Detokenisation load tests — {@code GET /api/v1/tokens/{token}}.
 *
 * <p>Each test pre-seeds the required number of ONE_TIME tokens via a parallel
 * tokenisation seeding phase, then dispatches detokenisation requests at the
 * target concurrency level. Asserts:
 * <ul>
 *   <li>Zero errors (non-2xx responses or thrown exceptions).
 *   <li>p99 per-request latency within the specified threshold.
 * </ul>
 *
 * <p>Only runs with: {@code JAVA_HOME=/opt/homebrew/opt/openjdk@21 mvn test -P load-tests}
 */
@Tag("load")
class DetokenisationLoadTest extends AbstractLoadTest {

    private static final String MERCHANT = "LOAD_MERCHANT_DET";

    @Autowired private TestRestTemplate restTemplate;
    @Autowired private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void cleanDatabase() {
        jdbcTemplate.execute("DELETE FROM token_vault");
        jdbcTemplate.execute("DELETE FROM token_audit_log");
    }

    // ── Scale variants ────────────────────────────────────────────────────────
    //
    // Concurrency is capped at 20 to match the HikariCP pool size. Seeding
    // parallelism is also 20 so it does not exhaust the pool before the test phase.

    /** LT-D-1K: 1,000 requests · 10 concurrent · p99 ≤ 2000ms */
    @Test
    void detokenise_1000requests_10concurrent_p99Under2000ms() {
        runLoad("LT-D-1K", 1_000, 10, 2_000L);
    }

    /** LT-D-5K: 5,000 requests · 15 concurrent · p99 ≤ 2000ms */
    @Test
    void detokenise_5000requests_15concurrent_p99Under2000ms() {
        runLoad("LT-D-5K", 5_000, 15, 2_000L);
    }

    /** LT-D-10K: 10,000 requests · 20 concurrent · p99 ≤ 2000ms */
    @Test
    void detokenise_10000requests_20concurrent_p99Under2000ms() {
        runLoad("LT-D-10K", 10_000, 20, 2_000L);
    }

    /** LT-D-20K: 20,000 requests · 20 concurrent · p99 ≤ 2000ms */
    @Test
    void detokenise_20000requests_20concurrent_p99Under2000ms() {
        runLoad("LT-D-20K", 20_000, 20, 2_000L);
    }

    /** LT-D-50K: 50,000 requests · 20 concurrent · p99 ≤ 2000ms */
    @Test
    void detokenise_50000requests_20concurrent_p99Under2000ms() {
        runLoad("LT-D-50K", 50_000, 20, 2_000L);
    }

    // ── Driver ────────────────────────────────────────────────────────────────

    private void runLoad(String testName, int total, int concurrency, long p99ThresholdMs) {
        // Phase 1: seed tokens (parallel, unmeasured)
        String[] tokens = seedTokens(total, 20);

        // Phase 2: detokenise load run
        long[] latencies = new long[total];
        AtomicLong errorCount = new AtomicLong();
        ExecutorService executor = buildVirtualThreadExecutor(concurrency);
        long wallStart = System.currentTimeMillis();

        for (int i = 0; i < total; i++) {
            final int slot = i;
            final String token = tokens[slot];
            executor.submit(() -> {
                long t0 = System.currentTimeMillis();
                try {
                    ResponseEntity<DetokeniseResponse> resp = detokenise(token, MERCHANT);
                    if (!resp.getStatusCode().is2xxSuccessful()) {
                        errorCount.incrementAndGet();
                    }
                } catch (Exception e) {
                    errorCount.incrementAndGet();
                } finally {
                    latencies[slot] = System.currentTimeMillis() - t0;
                }
            });
        }

        awaitCompletion(executor, 600);

        long wallClockMs = System.currentTimeMillis() - wallStart;
        LatencyStats stats = computeStats(latencies);

        LoadTestResult result = new LoadTestResult(testName, total, concurrency, wallClockMs,
                stats.p50(), stats.p95(), stats.p99(), stats.max(),
                errorCount.get(), 0L, Instant.now());
        result.writeToFile();

        assertThat(errorCount.get())
                .as("[%s] zero errors expected (got %d)", testName, errorCount.get())
                .isZero();
        assertThat(stats.p99())
                .as("[%s] p99 %dms must be ≤ %dms", testName, stats.p99(), p99ThresholdMs)
                .isLessThanOrEqualTo(p99ThresholdMs);
    }

    /**
     * Pre-seeds {@code count} ONE_TIME tokens using a parallel tokenisation burst.
     *
     * <p>Uses unique random PANs to avoid RECURRING de-duplication. The seeding phase
     * is not included in the latency measurement.
     *
     * @param count       number of tokens to create
     * @param parallelism seeding concurrency (capped at 20 to stay within pool bounds)
     * @return array of token strings in the order they were assigned to slots
     */
    private String[] seedTokens(int count, int parallelism) {
        String[] tokens = new String[count];
        AtomicLong seedErrors = new AtomicLong();
        ExecutorService seeder = buildVirtualThreadExecutor(parallelism);

        for (int i = 0; i < count; i++) {
            final int slot = i;
            seeder.submit(() -> {
                String pan = PanGenerator.generateVisa16();
                TokeniseRequest req = buildRequest(pan);
                try {
                    ResponseEntity<TokeniseResponse> resp =
                            restTemplate.postForEntity("/api/v1/tokens", req, TokeniseResponse.class);
                    if (resp.getStatusCode() == HttpStatus.CREATED && resp.getBody() != null) {
                        tokens[slot] = resp.getBody().getToken();
                    } else {
                        seedErrors.incrementAndGet();
                    }
                } catch (Exception e) {
                    seedErrors.incrementAndGet();
                }
            });
        }

        awaitCompletion(seeder, 600);

        assertThat(seedErrors.get())
                .as("Token seeding must complete without errors")
                .isZero();
        return tokens;
    }

    private ResponseEntity<DetokeniseResponse> detokenise(String token, String merchantId) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Merchant-ID", merchantId);
        return restTemplate.exchange(
                "/api/v1/tokens/" + token,
                HttpMethod.GET,
                new HttpEntity<>(headers),
                DetokeniseResponse.class);
    }

    private TokeniseRequest buildRequest(String pan) {
        TokeniseRequest r = new TokeniseRequest();
        r.setPan(pan);
        r.setTokenType(TokenType.ONE_TIME);
        r.setMerchantId(MERCHANT);
        r.setCardScheme("VISA");
        r.setExpiryMonth(12);
        r.setExpiryYear(2027);
        return r;
    }
}
