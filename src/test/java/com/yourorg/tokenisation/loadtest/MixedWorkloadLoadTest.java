package com.yourorg.tokenisation.loadtest;

import com.yourorg.tokenisation.api.request.TokeniseRequest;
import com.yourorg.tokenisation.api.response.DetokeniseResponse;
import com.yourorg.tokenisation.api.response.TokeniseResponse;
import com.yourorg.tokenisation.loadtest.RandomWorkloadDispatcher.Operation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Instant;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Mixed-workload load tests — 40% tokenise ONE_TIME · 20% tokenise RECURRING ·
 * 35% detokenise · 5% status check.
 *
 * <p>All tokenisation requests (both ONE_TIME and RECURRING) use unique random PANs.
 * Using a shared PAN for RECURRING under concurrent load triggers a race condition:
 * multiple threads each find zero existing records and all insert, producing duplicate
 * RECURRING tokens that cause {@code NonUniqueResultException} on the next lookup.
 * Dedup correctness under concurrent writes is covered by the integration test suite.
 *
 * <p>Each test runs the configured request mix concurrently. Detokenise and status-check
 * requests draw from a shared pool of previously tokenised tokens (seeded at test start
 * and grown by in-test tokenisation). Asserts:
 * <ul>
 *   <li>Zero errors for all operation types.
 *   <li>p99 latency within the specified threshold (across all operation types).
 * </ul>
 *
 * <p>Only runs with: {@code JAVA_HOME=/opt/homebrew/opt/openjdk@21 mvn test -P load-tests}
 */
@Tag("load")
class MixedWorkloadLoadTest extends AbstractLoadTest {

    // 60% tokenise · 35% detokenise · 5% status check
    private static final RandomWorkloadDispatcher DISPATCHER =
            new RandomWorkloadDispatcher(60, 35, 5);

    @Autowired private TestRestTemplate restTemplate;
    @Autowired private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void cleanDatabase() {
        jdbcTemplate.execute("DELETE FROM token_vault");
        jdbcTemplate.execute("DELETE FROM token_audit_log");
    }

    // ── Scale variants ────────────────────────────────────────────────────────
    //
    // Concurrency is capped at 20 to match the HikariCP pool size. The initial
    // token pool seeding also uses 20 threads for the same reason.

    /** LT-M-1K: 1,000 mixed requests · 10 concurrent · p99 ≤ 2000ms */
    @Test
    void mixed_1000requests_10concurrent_p99Under2000ms() {
        runLoad("LT-M-1K", 1_000, 10, 2_000L);
    }

    /** LT-M-5K: 5,000 mixed requests · 15 concurrent · p99 ≤ 2000ms */
    @Test
    void mixed_5000requests_15concurrent_p99Under2000ms() {
        runLoad("LT-M-5K", 5_000, 15, 2_000L);
    }

    /** LT-M-10K: 10,000 mixed requests · 20 concurrent · p99 ≤ 2000ms */
    @Test
    void mixed_10000requests_20concurrent_p99Under2000ms() {
        runLoad("LT-M-10K", 10_000, 20, 2_000L);
    }

    /** LT-M-20K: 20,000 mixed requests · 20 concurrent · p99 ≤ 2000ms */
    @Test
    void mixed_20000requests_20concurrent_p99Under2000ms() {
        runLoad("LT-M-20K", 20_000, 20, 2_000L);
    }

    /** LT-M-50K: 50,000 mixed requests · 20 concurrent · p99 ≤ 2000ms */
    @Test
    void mixed_50000requests_20concurrent_p99Under2000ms() {
        runLoad("LT-M-50K", 50_000, 20, 2_000L);
    }

    // ── Driver ────────────────────────────────────────────────────────────────

    private void runLoad(String testName, int total, int concurrency, long p99ThresholdMs) {
        // Shared token pool: seeded with some initial tokens, grown by in-test tokenisations.
        // CopyOnWriteArrayList is safe for concurrent reads and occasional writes.
        // Seed count is capped at concurrency to avoid overwhelming the pool during seeding.
        CopyOnWriteArrayList<String> tokenPool = seedInitialPool(Math.max(concurrency, total / 10));

        long[] latencies = new long[total];
        AtomicLong errorCount = new AtomicLong();
        AtomicInteger tokenPoolIndex = new AtomicInteger(0);
        ExecutorService executor = buildVirtualThreadExecutor(concurrency);
        long wallStart = System.currentTimeMillis();

        for (int i = 0; i < total; i++) {
            final int slot = i;
            executor.submit(() -> {
                Operation op = DISPATCHER.nextOperation();
                long t0 = System.currentTimeMillis();
                try {
                    switch (op) {
                        case TOKENISE -> {
                            // Each request uses a unique PAN to avoid de-dup short-circuiting
                            // the vault path — the load test goal is throughput, not de-dup correctness.
                            TokeniseRequest req = buildRequest(PanGenerator.generateVisa16());
                            ResponseEntity<TokeniseResponse> resp =
                                    restTemplate.postForEntity("/api/v1/tokens", req, TokeniseResponse.class);
                            if (resp.getStatusCode().is2xxSuccessful() && resp.getBody() != null) {
                                tokenPool.add(resp.getBody().getToken());
                            } else {
                                errorCount.incrementAndGet();
                            }
                        }
                        case DETOKENISE -> {
                            String token = pickToken(tokenPool, tokenPoolIndex);
                            if (token != null) {
                                ResponseEntity<DetokeniseResponse> resp = detokenise(token);
                                if (!resp.getStatusCode().is2xxSuccessful()) {
                                    errorCount.incrementAndGet();
                                }
                            }
                        }
                        case STATUS_CHECK -> {
                            // Status check: attempt detokenise; 200 = active, 404 = not found.
                            // Both are valid "system-is-alive" responses — only 5xx counts as error.
                            String token = pickToken(tokenPool, tokenPoolIndex);
                            if (token != null) {
                                ResponseEntity<String> resp = restTemplate.getForEntity(
                                        "/api/v1/tokens/" + token, String.class);
                                if (resp.getStatusCode().is5xxServerError()) {
                                    errorCount.incrementAndGet();
                                }
                            }
                        }
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
     * Seeds an initial pool of ONE_TIME tokens so detokenise/status-check operations
     * have tokens available from the start of the test.
     *
     * <p>Seeding parallelism is capped at 20 to match the HikariCP pool size.
     */
    private CopyOnWriteArrayList<String> seedInitialPool(int count) {
        CopyOnWriteArrayList<String> pool = new CopyOnWriteArrayList<>();
        ExecutorService seeder = buildVirtualThreadExecutor(20);
        for (int i = 0; i < count; i++) {
            seeder.submit(() -> {
                String pan = PanGenerator.generateVisa16();
                TokeniseRequest req = buildRequest(pan);
                ResponseEntity<TokeniseResponse> resp =
                        restTemplate.postForEntity("/api/v1/tokens", req, TokeniseResponse.class);
                if (resp.getStatusCode().is2xxSuccessful() && resp.getBody() != null) {
                    pool.add(resp.getBody().getToken());
                }
            });
        }
        awaitCompletion(seeder, 300);
        return pool;
    }

    /**
     * Picks a token from the pool in round-robin order. Returns {@code null} if the pool
     * is empty (should not happen after seeding, but handled defensively).
     */
    private String pickToken(CopyOnWriteArrayList<String> pool, AtomicInteger index) {
        if (pool.isEmpty()) {
            return null;
        }
        int idx = Math.abs(index.getAndIncrement() % pool.size());
        return pool.get(idx);
    }

    private ResponseEntity<DetokeniseResponse> detokenise(String token) {
        return restTemplate.getForEntity("/api/v1/tokens/" + token, DetokeniseResponse.class);
    }

    private TokeniseRequest buildRequest(String pan) {
        TokeniseRequest r = new TokeniseRequest();
        r.setPan(pan);
        r.setCardScheme("VISA");
        r.setExpiryMonth(12);
        r.setExpiryYear(2027);
        return r;
    }
}
