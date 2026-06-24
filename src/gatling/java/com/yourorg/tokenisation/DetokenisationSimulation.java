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
 * Gatling simulation for the detokenisation endpoint ({@code GET /api/v1/tokens/{token}}).
 *
 * <h3>Setup phase</h3>
 * The {@link #before()} hook seeds the database with up to {@link #SEED_COUNT} tokens via
 * HTTP tokenisation requests (sequential, not measured). The main simulation picks tokens
 * at random from the seeded pool — each token may be hit multiple times at large scales,
 * which exercises the hot-path (no per-request DB write) realistically.
 *
 * <h3>How to run</h3>
 * <pre>
 *   make start
 *   make gatling-test GATLING_SIM=DetokenisationSimulation GATLING_SCALE=20k
 *   make gatling-test GATLING_SIM=DetokenisationSimulation GATLING_SCALE=100k GATLING_DURATION=300
 * </pre>
 *
 * <p>The simulation asserts p99 ≤ 2000ms and ≥ 99% success rate.
 */
public class DetokenisationSimulation extends Simulation {

    private static final int SEED_COUNT = 10_000;

    private final List<String> seededTokens = Collections.synchronizedList(new ArrayList<>(SEED_COUNT));

    private final HttpProtocolBuilder protocol = http
            .baseUrl(SimulationConfig.BASE_URL)
            .acceptHeader("application/json");

    // Token is chosen at runtime (inside exec lambda) so it is read from seededTokens
    // AFTER before() has populated the list — not at class-init time.
    private final ScenarioBuilder detokenise = scenario("Detokenise GET /api/v1/tokens/{token}")
            .exec(session -> session.set("token", randomToken()))
            .exec(http("GET /api/v1/tokens/{token}")
                    .get(session -> "/api/v1/tokens/" + session.getString("token"))
                    .check(status().is(200))
                    .check(jsonPath("$.pan").exists()));

    {
        int targetRps = Math.max(1, SimulationConfig.TOTAL_REQUESTS / SimulationConfig.SUSTAIN_SECONDS);

        setUp(
                detokenise.injectOpen(
                        rampUsersPerSec(1).to(targetRps).during(SimulationConfig.RAMP_SECONDS),
                        constantUsersPerSec(targetRps).during(SimulationConfig.SUSTAIN_SECONDS)
                )
        ).protocols(protocol)
                .assertions(
                        global().responseTime().percentile(99).lt(2000),
                        global().successfulRequests().percent().gte(99.0)
                );
    }

    @Override
    public void before() {
        System.out.printf("[DetokenisationSimulation] Clearing DB and seeding %d tokens...%n", SEED_COUNT);
        DbSetupHelper.truncate();
        seedTokensViaHttp(SEED_COUNT);
        System.out.printf("[DetokenisationSimulation] Seeded %d tokens. Starting simulation " +
                "(totalRequests=%d, targetRps=%d).%n",
                seededTokens.size(), SimulationConfig.TOTAL_REQUESTS,
                Math.max(1, SimulationConfig.TOTAL_REQUESTS / SimulationConfig.SUSTAIN_SECONDS));
    }

    private String randomToken() {
        if (seededTokens.isEmpty()) return "no-token-seeded";
        return seededTokens.get(ThreadLocalRandom.current().nextInt(seededTokens.size()));
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
                    System.err.println("[DetokenisationSimulation] Seed error: " + e.getMessage());
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
    }

    private static String extractToken(String json) {
        int idx = json.indexOf("\"token\":\"");
        if (idx < 0) return null;
        int start = idx + 9;
        int end = json.indexOf("\"", start);
        return end < 0 ? null : json.substring(start, end);
    }
}
