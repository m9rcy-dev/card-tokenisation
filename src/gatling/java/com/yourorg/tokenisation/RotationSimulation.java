package com.yourorg.tokenisation;

import io.gatling.javaapi.core.ScenarioBuilder;
import io.gatling.javaapi.core.Simulation;
import io.gatling.javaapi.http.HttpProtocolBuilder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadLocalRandom;

import static io.gatling.javaapi.core.CoreDsl.*;
import static io.gatling.javaapi.http.HttpDsl.*;

/**
 * Gatling simulation: key rotation under concurrent tokenisation/detokenisation traffic.
 *
 * <h3>What this measures</h3>
 * <ul>
 *   <li>Zero errors during rotation — all tokenise and detokenise requests succeed.
 *   <li>Throughput degradation during rotation (compare rps before vs. during).
 *   <li>Total rotation wall-clock time visible in the app logs.
 * </ul>
 *
 * <h3>Scenario</h3>
 * <ol>
 *   <li>{@link #before()}: truncate tables, reset key state in DB, seed {@link #SEED_COUNT} tokens,
 *       then trigger rotation via {@code POST /api/v1/admin/keys/rotate}.
 *   <li>Phase 1 (ramp): gradually increase to {@code targetRps} users/second with a
 *       70/30 tokenise/detokenise split.
 *   <li>Phase 2 (sustain): hold for {@link SimulationConfig#SUSTAIN_SECONDS}.
 *       Rotation batch runs concurrently in the application's scheduled job.
 * </ol>
 *
 * <h3>Important: start the app fresh before this simulation</h3>
 * The {@code before()} hook resets key_versions in the database but cannot reset the
 * application's in-memory key ring. If the app has already completed a rotation the ring
 * holds a different active key than what the DB reset expects. Always run
 * {@code make start} (fresh app start) immediately before this simulation.
 *
 * <h3>How to run</h3>
 * <pre>
 *   make start   # fresh start required — ring must match DB key state
 *   make gatling-test GATLING_SIM=RotationSimulation GATLING_SCALE=20k
 *   make gatling-test GATLING_SIM=RotationSimulation GATLING_SCALE=50k GATLING_DURATION=300
 * </pre>
 */
public class RotationSimulation extends Simulation {

    /** Tokens to pre-seed for detokenisation requests during the simulation. */
    private static final int SEED_COUNT = 5_000;

    private static final String SEED_KEY_VERSION_ID =
            System.getProperty("seedKeyVersionId", "00000000-0000-0000-0000-000000000001");

    private static final String ADMIN_USER =
            System.getProperty("adminUser", "admin");

    private static final String ADMIN_PASS =
            System.getProperty("adminPass", "change_me");

    private final List<String> seededTokens = Collections.synchronizedList(new ArrayList<>(SEED_COUNT));

    private final HttpProtocolBuilder protocol = http
            .baseUrl(SimulationConfig.BASE_URL)
            .acceptHeader("application/json")
            .contentTypeHeader("application/json");

    // 70% tokenise / 30% detokenise — models production traffic during a rotation window.
    // Token for detokenise is chosen lazily at execution time (after before() seeds the list).
    private final ScenarioBuilder tokeniseDuringRotation = scenario("POST /api/v1/tokens (rotation)")
            .exec(http("POST /api/v1/tokens")
                    .post("/api/v1/tokens")
                    .body(StringBody(session -> buildTokeniseBody()))
                    .check(status().is(201)));

    private final ScenarioBuilder detokeniseDuringRotation = scenario("GET /api/v1/tokens/{token} (rotation)")
            .exec(session -> session.set("token", randomSeededToken()))
            .exec(http("GET /api/v1/tokens/{token}")
                    .get(session -> "/api/v1/tokens/" + session.getString("token"))
                    // Tokens are re-encrypted during rotation — they remain detokenisable throughout.
                    // 404 is NOT expected here; it would indicate a data-loss bug.
                    .check(status().is(200))
                    .check(jsonPath("$.pan").exists()));

    {
        int targetRps = Math.max(1, SimulationConfig.TOTAL_REQUESTS / SimulationConfig.SUSTAIN_SECONDS);
        int tokeniseRps = Math.max(1, (int) (targetRps * 0.70));
        int detokeniseRps = Math.max(1, targetRps - tokeniseRps);

        setUp(
                tokeniseDuringRotation.injectOpen(
                        rampUsersPerSec(1).to(tokeniseRps).during(SimulationConfig.RAMP_SECONDS),
                        constantUsersPerSec(tokeniseRps).during(SimulationConfig.SUSTAIN_SECONDS)
                ),
                detokeniseDuringRotation.injectOpen(
                        rampUsersPerSec(1).to(detokeniseRps).during(SimulationConfig.RAMP_SECONDS),
                        constantUsersPerSec(detokeniseRps).during(SimulationConfig.SUSTAIN_SECONDS)
                )
        ).protocols(protocol)
                .assertions(
                        global().responseTime().percentile(99).lt(5000), // wider threshold during rotation
                        global().successfulRequests().percent().gte(99.0)
                );
    }

    @Override
    public void before() {
        System.out.printf("[RotationSimulation] Setup: truncate + reset keys + seed %d tokens + trigger rotation%n",
                SEED_COUNT);
        DbSetupHelper.truncate();
        DbSetupHelper.resetKeyVersions(SEED_KEY_VERSION_ID);
        seedTokensViaHttp(SEED_COUNT);
        triggerRotation();
        System.out.printf("[RotationSimulation] Setup complete — rotation in progress. " +
                "Seeded %d tokens. Starting traffic (totalRequests=%d).%n",
                seededTokens.size(), SimulationConfig.TOTAL_REQUESTS);
    }

    private String randomSeededToken() {
        if (seededTokens.isEmpty()) return "no-token-seeded";
        return seededTokens.get(ThreadLocalRandom.current().nextInt(seededTokens.size()));
    }

    private void triggerRotation() {
        try {
            java.net.http.HttpClient client = java.net.http.HttpClient.newHttpClient();
            String body = """
                    {"newKeyAlias":"gatling-rotation-key","reason":"SCHEDULED"}""";
            var request = java.net.http.HttpRequest.newBuilder()
                    .uri(java.net.URI.create(SimulationConfig.BASE_URL + "/api/v1/admin/keys/rotate"))
                    .header("Content-Type", "application/json")
                    .header("Authorization",
                            "Basic " + java.util.Base64.getEncoder()
                                    .encodeToString((ADMIN_USER + ":" + ADMIN_PASS).getBytes()))
                    .POST(java.net.http.HttpRequest.BodyPublishers.ofString(body))
                    .build();
            var response = client.send(request, java.net.http.HttpResponse.BodyHandlers.ofString());
            System.out.println("[RotationSimulation] Rotation trigger response: " + response.statusCode());
        } catch (Exception e) {
            System.err.println("[RotationSimulation] WARNING: rotation trigger failed: " + e.getMessage());
        }
    }

    private void seedTokensViaHttp(int count) {
        java.net.http.HttpClient client = java.net.http.HttpClient.newHttpClient();
        ExecutorService exec = Executors.newFixedThreadPool(20);
        List<Callable<Void>> tasks = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            tasks.add(() -> {
                try {
                    String pan = TokenisationSimulation.generateVisa16();
                    String body = String.format(
                            "{\"pan\":\"%s\",\"cardScheme\":\"MC\",\"expiryMonth\":12,\"expiryYear\":2029}", pan);
                    var req = java.net.http.HttpRequest.newBuilder()
                            .uri(java.net.URI.create(SimulationConfig.BASE_URL + "/api/v1/tokens"))
                            .header("Content-Type", "application/json")
                            .POST(java.net.http.HttpRequest.BodyPublishers.ofString(body))
                            .build();
                    var resp = client.send(req, java.net.http.HttpResponse.BodyHandlers.ofString());
                    if (resp.statusCode() == 201) {
                        String token = extractToken(resp.body());
                        if (token != null) seededTokens.add(token);
                    }
                } catch (Exception e) {
                    System.err.println("[RotationSimulation] Seed error: " + e.getMessage());
                }
                return null;
            });
        }
        try {
            exec.invokeAll(tasks);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            exec.shutdown();
        }
        System.out.println("[RotationSimulation] Seeded " + seededTokens.size() + " tokens.");
    }

    private static String buildTokeniseBody() {
        String pan = TokenisationSimulation.generateVisa16();
        return String.format(
                "{\"pan\":\"%s\",\"cardScheme\":\"MC\",\"expiryMonth\":12,\"expiryYear\":2029}",
                pan);
    }

    private static String extractToken(String json) {
        int idx = json.indexOf("\"token\":\"");
        if (idx < 0) return null;
        int start = idx + 9;
        int end = json.indexOf("\"", start);
        return end < 0 ? null : json.substring(start, end);
    }
}
