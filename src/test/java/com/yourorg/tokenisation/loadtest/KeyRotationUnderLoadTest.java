package com.yourorg.tokenisation.loadtest;

import com.yourorg.tokenisation.api.request.TokeniseRequest;
import com.yourorg.tokenisation.api.response.DetokeniseResponse;
import com.yourorg.tokenisation.api.response.TokeniseResponse;
import com.yourorg.tokenisation.config.RotationProperties;
import com.yourorg.tokenisation.crypto.InMemoryKeyRing;
import com.yourorg.tokenisation.crypto.TamperDetector;
import com.yourorg.tokenisation.domain.KeyVersion;
import com.yourorg.tokenisation.domain.RotationReason;
import com.yourorg.tokenisation.domain.TokenType;
import com.yourorg.tokenisation.kms.KmsProvider;
import com.yourorg.tokenisation.repository.KeyVersionRepository;
import com.yourorg.tokenisation.repository.TokenVaultRepository;
import com.yourorg.tokenisation.rotation.KeyRotationService;
import com.yourorg.tokenisation.rotation.RotationJob;
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
import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Key rotation under live traffic load tests.
 *
 * <p>Each test validates that the rotation batch pipeline completes correctly while
 * tokenisation and detokenisation requests continue to arrive concurrently.
 *
 * <h3>Test plan</h3>
 * <ol>
 *   <li>Pre-seed 10,000 ONE_TIME tokens under the seed key.
 *   <li>Measure baseline throughput (requests/second) for 3 seconds of steady traffic.
 *   <li>Initiate scheduled rotation and drive the batch loop to completion.
 *   <li>Measure throughput during the rotation window.
 *   <li>Assert that all pre-seeded tokens remain detokenisable after rotation.
 * </ol>
 *
 * <p>Only runs with: {@code JAVA_HOME=/opt/homebrew/opt/openjdk@21 mvn test -P load-tests}
 */
@Tag("load")
class KeyRotationUnderLoadTest extends AbstractLoadTest {

    private static final int SEED_TOKEN_COUNT = 1_000;
    private static final String MERCHANT = "LOAD_MERCHANT_ROT";

    @Autowired private TestRestTemplate restTemplate;
    @Autowired private JdbcTemplate jdbcTemplate;
    @Autowired private KeyVersionRepository keyVersionRepository;
    @Autowired private TokenVaultRepository tokenVaultRepository;
    @Autowired private KeyRotationService keyRotationService;
    @Autowired private RotationJob rotationJob;
    @Autowired private RotationProperties rotationProperties;
    @Autowired private InMemoryKeyRing keyRing;
    @Autowired private KmsProvider kmsProvider;
    @Autowired private TamperDetector tamperDetector;
    @Autowired private BulkTokenSeeder bulkSeeder;

    /** Token strings for the 10K pre-seeded tokens — populated by {@link #setUpForRotationTest()}. */
    private String[] seededTokens;

    @BeforeEach
    void setUpForRotationTest() {
        jdbcTemplate.execute("DELETE FROM token_vault");
        jdbcTemplate.execute("DELETE FROM token_audit_log");

        // Retire any keys left by a previous test, reset seed key to ACTIVE
        jdbcTemplate.execute(
                "UPDATE key_versions SET status = 'RETIRED' WHERE id != '" + SEED_KEY_VERSION_ID + "'::uuid");
        jdbcTemplate.execute(
                "UPDATE key_versions SET status = 'ACTIVE' WHERE id = '" + SEED_KEY_VERSION_ID + "'::uuid");

        // Recompute real HMAC checksum for seed key (inserted with placeholder "seed-checksum")
        KeyVersion seedKey = keyVersionRepository.findActiveOrThrow();
        seedKey.initializeChecksum(tamperDetector.computeChecksum(seedKey));
        keyVersionRepository.save(seedKey);

        // Reload seed key into ring and re-promote it
        byte[] seedKek = kmsProvider.unwrapKek(seedKey.getEncryptedKekBlob());
        try {
            keyRing.load(SEED_KEY_VERSION_ID, seedKek, seedKey.getRotateBy());
            keyRing.promoteActive(SEED_KEY_VERSION_ID);
        } finally {
            Arrays.fill(seedKek, (byte) 0);
        }

        // Pre-seed tokens under the seed key (parallel, not measured for latency)
        seededTokens = seedTokens(SEED_TOKEN_COUNT, 20);
    }

    // ── LT-R-1 ───────────────────────────────────────────────────────────────

    /**
     * LT-R-1: 1,000 pre-seeded tokens · rotation completes with 0 live traffic errors ·
     * ≤20% throughput degradation · 0 tokens remain on old key after rotation.
     */
    @Test
    void rotation_completesWithZeroLiveTrafficErrors_and_noTokensOnOldKey() {
        long heapBefore = captureHeapMb();
        UUID oldKeyId = UUID.fromString(SEED_KEY_VERSION_ID);

        // Baseline: measure steady-state RPS for 3 seconds before rotation starts
        AtomicLong baselineCompleted = new AtomicLong();
        AtomicLong liveErrors = new AtomicLong();
        AtomicBoolean stopTraffic = new AtomicBoolean(false);

        ExecutorService trafficPool = Executors.newFixedThreadPool(20,
                Thread.ofVirtual().name("live-traffic-", 0).factory());
        for (int i = 0; i < 20; i++) {
            trafficPool.submit(() -> {
                while (!stopTraffic.get()) {
                    try {
                        String pan = PanGenerator.generateVisa16();
                        ResponseEntity<TokeniseResponse> resp =
                                restTemplate.postForEntity("/api/v1/tokens",
                                        buildTokeniseRequest(pan), TokeniseResponse.class);
                        if (resp.getStatusCode().is2xxSuccessful()) {
                            baselineCompleted.incrementAndGet();
                        } else {
                            liveErrors.incrementAndGet();
                        }
                    } catch (Exception e) {
                        liveErrors.incrementAndGet();
                    }
                }
            });
        }

        // Let traffic run for 3s to establish baseline
        sleep(3_000);
        long baselineRps = baselineCompleted.get() / 3;
        long beforeRotation = baselineCompleted.get();

        // Initiate rotation — processRotationBatch now drains all batches in one call
        keyRotationService.initiateScheduledRotation("load-test-key-v2", RotationReason.SCHEDULED);
        long rotationStart = System.currentTimeMillis();
        rotationJob.processRotationBatch(); // drains all batches + triggers cutover
        long rotationDurationSecs = Math.max(1, (System.currentTimeMillis() - rotationStart) / 1_000);

        long duringRotation = baselineCompleted.get() - beforeRotation;
        long rotationRps = duringRotation / rotationDurationSecs;

        // Stop background traffic
        stopTraffic.set(true);
        trafficPool.shutdown();
        try {
            trafficPool.awaitTermination(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        long heapGrowthMb = captureHeapMb() - heapBefore;

        // LT-R-1 assertions
        assertThat(liveErrors.get())
                .as("LT-R-1: zero live traffic errors during rotation")
                .isZero();
        assertThat(rotationRps)
                .as("LT-R-1: throughput during rotation (%d rps) must be ≥ 80%% of baseline (%d rps)",
                        rotationRps, baselineRps)
                .isGreaterThanOrEqualTo((long) (baselineRps * 0.80));
        assertThat(tokenVaultRepository.countActiveByKeyVersionId(oldKeyId))
                .as("LT-R-1: 0 tokens remain on old key after rotation")
                .isZero();

        // Write result
        new LoadTestResult("LT-R-1", SEED_TOKEN_COUNT, 20,
                System.currentTimeMillis() - rotationStart,
                0, 0, 0, 0, liveErrors.get(), heapGrowthMb, Instant.now()).writeToFile();
    }

    // ── LT-R-2 ───────────────────────────────────────────────────────────────

    /**
     * LT-R-2: All 1,000 pre-rotation tokens are detokenisable after rotation completes.
     */
    @Test
    void rotation_allPreRotationTokensDetokenisableAfterRotation() {
        UUID oldKeyId = UUID.fromString(SEED_KEY_VERSION_ID);

        // Run rotation to completion — single call now drains all batches + triggers cutover
        keyRotationService.initiateScheduledRotation("load-test-key-v2", RotationReason.SCHEDULED);
        rotationJob.processRotationBatch();

        // Verify all pre-seeded tokens are still detokenisable (parallel verification)
        long[] latencies = new long[seededTokens.length];
        AtomicLong verifyErrors = new AtomicLong();
        ExecutorService verifier = buildVirtualThreadExecutor(20);

        for (int i = 0; i < seededTokens.length; i++) {
            final int slot = i;
            final String token = seededTokens[slot];
            verifier.submit(() -> {
                long t0 = System.currentTimeMillis();
                try {
                    ResponseEntity<DetokeniseResponse> resp = detokenise(token, MERCHANT);
                    if (resp.getStatusCode() != HttpStatus.OK) {
                        verifyErrors.incrementAndGet();
                    }
                } catch (Exception e) {
                    verifyErrors.incrementAndGet();
                } finally {
                    latencies[slot] = System.currentTimeMillis() - t0;
                }
            });
        }

        awaitCompletion(verifier, 600);
        LatencyStats stats = computeStats(latencies);

        new LoadTestResult("LT-R-2", seededTokens.length, 20, 0,
                stats.p50(), stats.p95(), stats.p99(), stats.max(),
                verifyErrors.get(), 0L, Instant.now()).writeToFile();

        assertThat(verifyErrors.get())
                .as("LT-R-2: all %d pre-rotation tokens must be detokenisable after rotation",
                        seededTokens.length)
                .isZero();
    }

    // ── LT-R-3 ───────────────────────────────────────────────────────────────

    /**
     * LT-R-3: Heap growth during the full rotation cycle does not exceed 256MB.
     */
    @Test
    void rotation_heapGrowthDuringRotation_withinBounds() {
        long heapBefore = captureHeapMb();
        UUID oldKeyId = UUID.fromString(SEED_KEY_VERSION_ID);

        // Run full rotation cycle — single call drains all batches + triggers cutover
        keyRotationService.initiateScheduledRotation("load-test-key-v2", RotationReason.SCHEDULED);
        rotationJob.processRotationBatch();

        long heapGrowthMb = captureHeapMb() - heapBefore;

        new LoadTestResult("LT-R-3", SEED_TOKEN_COUNT, rotationProperties.getBatch().getParallelism(), 0,
                0, 0, 0, 0, 0L, heapGrowthMb, Instant.now()).writeToFile();

        assertThat(heapGrowthMb)
                .as("LT-R-3: heap growth during rotation must be ≤ 256MB (actual: %dMB)", heapGrowthMb)
                .isLessThanOrEqualTo(256L);
    }

    // ── LT-R-4 ───────────────────────────────────────────────────────────────

    /**
     * LT-R-4: 100,000 pre-seeded tokens · all migrated to new key · heap growth ≤ 512MB.
     *
     * <p>Tokens are seeded via JDBC bulk insert (not HTTP) so setup completes in seconds
     * rather than minutes. Rotation uses the parallel rewrap executor — the actual
     * throughput is captured in the result file for capacity planning.
     *
     * <p>Run with: {@code mvn test -P load-tests -Dtest="*100000*"}
     */
    @Test
    void rotation_100000requests_allMigratedToNewKey() {
        // Seed 100K tokens via JDBC bulk insert — bypasses HTTP API for speed
        bulkSeeder.seedTokens(100_000, MERCHANT, 1_000);
        long heapBefore = captureHeapMb();
        UUID oldKeyId = UUID.fromString(SEED_KEY_VERSION_ID);

        keyRotationService.initiateScheduledRotation("load-test-key-v2", RotationReason.SCHEDULED);
        long start = System.currentTimeMillis();
        rotationJob.processRotationBatch(); // drains all 100 batches × 1000 records in one shot
        long durationMs = System.currentTimeMillis() - start;

        long remaining  = tokenVaultRepository.countActiveByKeyVersionId(oldKeyId);
        long heapGrowth = captureHeapMb() - heapBefore;

        new LoadTestResult("LT-R-4", 100_000, rotationProperties.getBatch().getParallelism(),
                durationMs, 0, 0, 0, 0, 0L, heapGrowth, Instant.now()).writeToFile();

        assertThat(remaining)
                .as("LT-R-4: 0 tokens remain on old key after 100K rotation")
                .isZero();
        assertThat(heapGrowth)
                .as("LT-R-4: heap growth during 100K rotation must be ≤ 512MB (actual: %dMB)", heapGrowth)
                .isLessThanOrEqualTo(512L);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private String[] seedTokens(int count, int parallelism) {
        String[] tokens = new String[count];
        AtomicLong errors = new AtomicLong();
        // parallelism must be ≤ pool-size (20) to avoid Hikari exhaustion during seeding
        ExecutorService seeder = buildVirtualThreadExecutor(parallelism);
        for (int i = 0; i < count; i++) {
            final int slot = i;
            seeder.submit(() -> {
                String pan = PanGenerator.generateVisa16();
                ResponseEntity<TokeniseResponse> resp =
                        restTemplate.postForEntity("/api/v1/tokens",
                                buildTokeniseRequest(pan), TokeniseResponse.class);
                if (resp.getStatusCode() == HttpStatus.CREATED && resp.getBody() != null) {
                    tokens[slot] = resp.getBody().getToken();
                } else {
                    errors.incrementAndGet();
                }
            });
        }
        awaitCompletion(seeder, 600);
        assertThat(errors.get()).as("Seeding must complete without errors").isZero();
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

    private TokeniseRequest buildTokeniseRequest(String pan) {
        TokeniseRequest r = new TokeniseRequest();
        r.setPan(pan);
        r.setTokenType(TokenType.ONE_TIME);
        r.setMerchantId(MERCHANT);
        r.setCardScheme("VISA");
        r.setExpiryMonth(12);
        r.setExpiryYear(2027);
        return r;
    }

    private void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
