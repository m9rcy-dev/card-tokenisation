package com.yourorg.tokenisation;

import io.gatling.javaapi.core.ScenarioBuilder;
import io.gatling.javaapi.core.Simulation;
import io.gatling.javaapi.http.HttpProtocolBuilder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static io.gatling.javaapi.core.CoreDsl.*;
import static io.gatling.javaapi.http.HttpDsl.*;

/**
 * Gatling simulation for the detokenisation endpoint ({@code GET /api/v1/tokens/{token}}).
 *
 * <h3>Setup phase</h3>
 * The {@link #before()} hook seeds the database with {@link #SEED_COUNT} tokens via
 * HTTP tokenisation requests (sequential, not measured), then stores the resulting token
 * strings in a shared circular feed. The main simulation draws tokens from this feed so
 * every detokenisation request targets a real, valid token.
 *
 * <h3>Scales (drive via {@code -DtotalRequests=N})</h3>
 * Same as {@link TokenisationSimulation} — 20K, 50K, 100K, 1M.
 *
 * <p>The simulation asserts p99 ≤ 2000ms and ≥ 99% success rate.
 */
public class DetokenisationSimulation extends Simulation {

    /**
     * Number of tokens to pre-seed before the simulation starts.
     * Round-robin selection means each token is detokenised multiple times for large scales —
     * this exercises the cache-warm detokenisation path realistically.
     */
    private static final int SEED_COUNT = Math.min(SimulationConfig.TOTAL_REQUESTS, 10_000);

    private final List<String> seedTokens = Collections.synchronizedList(new ArrayList<>(SEED_COUNT));

    private final HttpProtocolBuilder protocol = http
            .baseUrl(SimulationConfig.BASE_URL)
            .acceptHeader("application/json")
            .header("X-Merchant-ID", SimulationConfig.MERCHANT_ID);

    private final ScenarioBuilder detokenise = scenario("Detokenise GET /api/v1/tokens/{token}")
            .feed(listFeeder(buildFeed()).circular())
            .exec(http("GET /api/v1/tokens/{token}")
                    .get(session -> "/api/v1/tokens/" + session.getString("token"))
                    .check(status().is(200))
                    .check(jsonPath("$.pan").exists()));

    {
        int targetRps = Math.max(1, SimulationConfig.TOTAL_REQUESTS / SimulationConfig.SUSTAIN_SECONDS);

        setUp(
                detokenise.injectOpen(
                        rampUsers(SimulationConfig.MAX_USERS).during(SimulationConfig.RAMP_SECONDS),
                        constantUsersPerSec(SimulationConfig.MAX_USERS).during(SimulationConfig.SUSTAIN_SECONDS)
                ).throttle(
                        reachRps(targetRps).in(SimulationConfig.RAMP_SECONDS),
                        holdFor(SimulationConfig.SUSTAIN_SECONDS)
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
        seedTokens(SEED_COUNT);
        System.out.printf("[DetokenisationSimulation] Seeded %d tokens. Starting simulation " +
                "(totalRequests=%d).%n", seedTokens.size(), SimulationConfig.TOTAL_REQUESTS);
    }

    private void seedTokens(int count) {
        // Sequential seeding via HTTP — not measured, just prepares the dataset
        java.net.http.HttpClient client = java.net.http.HttpClient.newHttpClient();
        for (int i = 0; i < count; i++) {
            try {
                String pan = TokenisationSimulation.generateVisa16();
                String body = String.format("""
                        {"pan":"%s","tokenType":"ONE_TIME","merchantId":"%s",
                         "cardScheme":"VISA","expiryMonth":12,"expiryYear":2029}""",
                        pan, SimulationConfig.MERCHANT_ID);

                var request = java.net.http.HttpRequest.newBuilder()
                        .uri(java.net.URI.create(SimulationConfig.BASE_URL + "/api/v1/tokens"))
                        .header("Content-Type", "application/json")
                        .POST(java.net.http.HttpRequest.BodyPublishers.ofString(body))
                        .build();

                var response = client.send(request, java.net.http.HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() == 201) {
                    // Extract token from JSON (avoid pulling in a JSON library dependency)
                    String token = extractToken(response.body());
                    if (token != null) seedTokens.add(token);
                }
            } catch (Exception e) {
                System.err.println("[DetokenisationSimulation] Seed error at slot " + i + ": " + e.getMessage());
            }
        }
    }

    private List<java.util.Map<String, Object>> buildFeed() {
        List<java.util.Map<String, Object>> feed = new ArrayList<>(seedTokens.size());
        for (String t : seedTokens) {
            feed.add(java.util.Map.of("token", t));
        }
        return feed;
    }

    /** Extracts the {@code token} field from a JSON response without a JSON library. */
    private static String extractToken(String json) {
        int idx = json.indexOf("\"token\":\"");
        if (idx < 0) return null;
        int start = idx + 9;
        int end = json.indexOf("\"", start);
        return end < 0 ? null : json.substring(start, end);
    }
}
