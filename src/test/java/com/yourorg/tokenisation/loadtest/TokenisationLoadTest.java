package com.yourorg.tokenisation.loadtest;

import com.yourorg.tokenisation.api.request.TokeniseRequest;
import com.yourorg.tokenisation.api.response.TokeniseResponse;
import com.yourorg.tokenisation.domain.TokenType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Instant;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tokenisation load tests — {@code POST /api/v1/tokens}.
 *
 * <p>Each test submits N requests at C concurrent virtual threads and asserts:
 * <ul>
 *   <li>Zero errors (non-2xx responses or thrown exceptions).
 *   <li>p99 per-request latency within the specified threshold.
 *   <li>Heap growth within the specified threshold.
 * </ul>
 *
 * <p>Results are written to {@code target/load-test-results/} as JSON after each test.
 *
 * <p>Only runs with: {@code JAVA_HOME=/opt/homebrew/opt/openjdk@21 mvn test -P load-tests}
 */
@Tag("load")
class TokenisationLoadTest extends AbstractLoadTest {

    private static final String MERCHANT = "LOAD_MERCHANT_TOK";

    @Autowired private TestRestTemplate restTemplate;
    @Autowired private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void cleanDatabase() {
        jdbcTemplate.execute("DELETE FROM token_vault");
        jdbcTemplate.execute("DELETE FROM token_audit_log");
    }

    // ── Scale variants ────────────────────────────────────────────────────────
    //
    // Concurrency is capped at 20 to match the HikariCP pool size configured in
    // application-load-test.yml. With pool-size == concurrency, every thread gets
    // a connection immediately — no queuing, no timeouts on a developer laptop.
    // The p99 thresholds are set conservatively (2 s) to accommodate the variable
    // performance of a Testcontainers PostgreSQL container.

    /** LT-T-1K: 1,000 requests · 10 concurrent · p99 ≤ 2000ms · heap growth ≤ +128MB */
    @Test
    void tokenise_1000requests_10concurrent_p99Under2000ms() {
        runLoad("LT-T-1K", 1_000, 10, 2_000L, 128L);
    }

    /** LT-T-5K: 5,000 requests · 15 concurrent · p99 ≤ 2000ms · heap growth ≤ +256MB */
    @Test
    void tokenise_5000requests_15concurrent_p99Under2000ms() {
        runLoad("LT-T-5K", 5_000, 15, 2_000L, 256L);
    }

    /** LT-T-10K: 10,000 requests · 20 concurrent · p99 ≤ 2000ms · heap growth ≤ +384MB */
    @Test
    void tokenise_10000requests_20concurrent_p99Under2000ms() {
        runLoad("LT-T-10K", 10_000, 20, 2_000L, 384L);
    }

    /** LT-T-20K: 20,000 requests · 20 concurrent · p99 ≤ 2000ms · heap growth ≤ +512MB */
    @Test
    void tokenise_20000requests_20concurrent_p99Under2000ms() {
        runLoad("LT-T-20K", 20_000, 20, 2_000L, 512L);
    }

    /** LT-T-50K: 50,000 requests · 20 concurrent · p99 ≤ 2000ms · heap growth ≤ +768MB */
    @Test
    void tokenise_50000requests_20concurrent_p99Under2000ms() {
        runLoad("LT-T-50K", 50_000, 20, 2_000L, 768L);
    }

    // ── Driver ────────────────────────────────────────────────────────────────

    private void runLoad(String testName, int total, int concurrency,
                         long p99ThresholdMs, long heapGrowthThresholdMb) {
        long heapBefore = captureHeapMb();
        long wallStart = System.currentTimeMillis();

        long[] latencies = new long[total];
        AtomicLong errorCount = new AtomicLong();
        ExecutorService executor = buildVirtualThreadExecutor(concurrency);

        for (int i = 0; i < total; i++) {
            final int slot = i;
            executor.submit(() -> {
                String pan = PanGenerator.generateVisa16();
                TokeniseRequest req = buildRequest(pan);
                long t0 = System.currentTimeMillis();
                try {
                    ResponseEntity<TokeniseResponse> resp =
                            restTemplate.postForEntity("/api/v1/tokens", req, TokeniseResponse.class);
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
        long heapGrowthMb = captureHeapMb() - heapBefore;
        LatencyStats stats = computeStats(latencies);

        LoadTestResult result = new LoadTestResult(testName, total, concurrency, wallClockMs,
                stats.p50(), stats.p95(), stats.p99(), stats.max(),
                errorCount.get(), heapGrowthMb, Instant.now());
        result.writeToFile();

        assertThat(errorCount.get())
                .as("[%s] zero errors expected (got %d)", testName, errorCount.get())
                .isZero();
        assertThat(stats.p99())
                .as("[%s] p99 %dms must be ≤ %dms", testName, stats.p99(), p99ThresholdMs)
                .isLessThanOrEqualTo(p99ThresholdMs);
        assertThat(heapGrowthMb)
                .as("[%s] heap growth %dMB must be ≤ %dMB", testName, heapGrowthMb, heapGrowthThresholdMb)
                .isLessThanOrEqualTo(heapGrowthThresholdMb);
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
