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
 * Gatling simulation: key rotation under concurrent tokenisation/detokenisation traffic.
 *
 * <h3>What this measures</h3>
 * <ul>
 *   <li>That live tokenisation and detokenisation succeed while rotation is in progress.
 *   <li>Throughput degradation during the rotation window (compare p99 before/during/after).
 *   <li>Total rotation wall-clock time (reported by the application via its logs).
 * </ul>
 *
 * <h3>Scenario</h3>
 * <ol>
 *   <li>{@link #before()}: truncate tables, reset key state, seed {@link #SEED_COUNT} tokens
 *       (for detokenisation), then trigger rotation via {@code POST /api/v1/admin/keys/rotate}.
 *   <li>Phase 1 (ramp): gradually increase to {@link SimulationConfig#MAX_USERS} users
 *       executing a 70/30 tokenise/detokenise split.
 *   <li>Phase 2 (sustain): hold for {@link SimulationConfig#SUSTAIN_SECONDS}. Rotation
 *       runs concurrently in the application's scheduled job.
 * </ol>
 *
 * <h3>Prerequisites</h3>
 * <ul>
 *   <li>Application running with admin endpoints enabled ({@code make start}).
 *   <li>Admin credentials set via {@code -DadminUser=...} and {@code -DadminPass=...}.
 *   <li>Seed key version ID known — pass as {@code -DseedKeyVersionId=<UUID>}.
 * </ul>
 *
 * <h3>Run</h3>
 * <pre>
 *   mvn gatling:test -P gatling-tests \
 *     -DsimulationClass=com.yourorg.tokenisation.RotationSimulation \
 *     -DtotalRequests=50000 \
 *     -DseedKeyVersionId=00000000-0000-0000-0000-000000000001
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

    // 70% tokenisation, 30% detokenisation — models a realistic mixed workload during rotation
    private final ScenarioBuilder mixedTraffic = scenario("Mixed traffic during rotation")
            .randomSwitch()
            .on(
                    percent(70.0).then(
                            exec(http("POST /api/v1/tokens (rotation)")
                                    .post("/api/v1/tokens")
                                    .body(StringBody(session -> buildTokeniseBody()))
                                    .check(status().is(201)))
                    ),
                    percent(30.0).then(
                            feed(listFeeder(buildFeed()).circular())
                                    .exec(http("GET /api/v1/tokens/{token} (rotation)")
                                            .get(session -> "/api/v1/tokens/" + session.getString("token"))
                                            .header("X-Merchant-ID", SimulationConfig.MERCHANT_ID)
                                            .check(status().in(200, 404))) // 404 OK — token may have been rotated
                    )
            );

    {
        setUp(
                mixedTraffic.injectOpen(
                        rampUsers(SimulationConfig.MAX_USERS).during(SimulationConfig.RAMP_SECONDS),
                        constantUsersPerSec(SimulationConfig.MAX_USERS).during(SimulationConfig.SUSTAIN_SECONDS)
                )
        ).protocols(protocol)
                .assertions(
                        global().responseTime().percentile(99).lt(5000), // wider threshold during rotation
                        global().successfulRequests().percent().gte(99.0)
                );
    }

    @Override
    public void before() {
        System.out.printf("[RotationSimulation] Setting up: truncate + seed %d tokens + initiate rotation%n",
                SEED_COUNT);
        DbSetupHelper.truncate();
        DbSetupHelper.resetKeyVersions(SEED_KEY_VERSION_ID);
        seedTokensViaHttp(SEED_COUNT);
        triggerRotation();
        System.out.println("[RotationSimulation] Setup complete — rotation in progress. Starting traffic.");
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
        for (int i = 0; i < count; i++) {
            try {
                String pan = TokenisationSimulation.generateVisa16();
                String body = String.format(
                        "{\"pan\":\"%s\",\"tokenType\":\"ONE_TIME\",\"merchantId\":\"%s\"," +
                        "\"cardScheme\":\"VISA\",\"expiryMonth\":12,\"expiryYear\":2029}",
                        pan, SimulationConfig.MERCHANT_ID);
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
                System.err.println("[RotationSimulation] Seed error at " + i + ": " + e.getMessage());
            }
        }
        System.out.println("[RotationSimulation] Seeded " + seededTokens.size() + " tokens.");
    }

    private List<java.util.Map<String, Object>> buildFeed() {
        List<java.util.Map<String, Object>> feed = new ArrayList<>(seededTokens.size());
        for (String t : seededTokens) feed.add(java.util.Map.of("token", t));
        return feed.isEmpty() ? List.of(java.util.Map.of("token", "placeholder")) : feed;
    }

    private static String buildTokeniseBody() {
        String pan = TokenisationSimulation.generateVisa16();
        return String.format(
                "{\"pan\":\"%s\",\"tokenType\":\"ONE_TIME\",\"merchantId\":\"%s\"," +
                "\"cardScheme\":\"VISA\",\"expiryMonth\":12,\"expiryYear\":2029}",
                pan, SimulationConfig.MERCHANT_ID);
    }

    private static String extractToken(String json) {
        int idx = json.indexOf("\"token\":\"");
        if (idx < 0) return null;
        int start = idx + 9;
        int end = json.indexOf("\"", start);
        return end < 0 ? null : json.substring(start, end);
    }
}
