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
 * Mixed-workload Gatling simulation: 70% tokenise / 30% detokenise.
 *
 * <p>This models the expected production traffic pattern where a payment processor
 * tokenises card data on first use and detokenises on subsequent authorisations.
 * The 70/30 split reflects a typical merchant that processes a mix of new-card and
 * returning-customer transactions.
 *
 * <h3>How to run</h3>
 * <pre>
 *   make start                             # start the app first
 *   make gatling-test                      # default: MixedSimulation at 20k requests
 *   make gatling-test GATLING_SCALE=100k   # 100k total (833 rps over 120s)
 *   # Reduce RPS by spreading over a longer window:
 *   make gatling-test GATLING_SCALE=100k GATLING_DURATION=300   # 333 rps over 5 min
 * </pre>
 *
 * <h3>What this simulation measures</h3>
 * <ul>
 *   <li>End-to-end throughput under realistic mixed read/write load
 *   <li>Separate p50/p95/p99 breakdowns for tokenise vs. detokenise in the HTML report
 *   <li>Error rate — both paths must achieve ≥ 99% success rate
 * </ul>
 *
 * <h3>Setup phase</h3>
 * {@link #before()} seeds {@value #SEED_COUNT} tokens via sequential HTTP tokenisation
 * requests (not measured) so the detokenise path always targets a valid token.
 * At large scales each seeded token is detokenised multiple times — this is intentional
 * and exercises the read-heavy (no-write-path) detokenise code realistically.
 */
public class MixedSimulation extends Simulation {

    private static final int SEED_COUNT = 10_000;

    private final List<String> seededTokens = Collections.synchronizedList(new ArrayList<>(SEED_COUNT));

    private final HttpProtocolBuilder protocol = http
            .baseUrl(SimulationConfig.BASE_URL)
            .acceptHeader("application/json")
            .contentTypeHeader("application/json");

    private final ScenarioBuilder tokenise = scenario("Tokenise POST /api/v1/tokens")
            .exec(http("POST /api/v1/tokens")
                    .post("/api/v1/tokens")
                    .body(StringBody(session -> buildTokeniseBody()))
                    .check(status().is(201))
                    .check(jsonPath("$.token").exists()));

    // Token is resolved lazily at execution time (inside exec lambda) so it is read
    // from seededTokens AFTER before() has populated the list.
    private final ScenarioBuilder detokenise = scenario("Detokenise GET /api/v1/tokens/{token}")
            .exec(session -> session.set("token", randomToken()))
            .exec(http("GET /api/v1/tokens/{token}")
                    .get(session -> "/api/v1/tokens/" + session.getString("token"))
                    .check(status().is(200))
                    .check(jsonPath("$.pan").exists()));

    {
        int targetRps    = Math.max(1, SimulationConfig.TOTAL_REQUESTS / SimulationConfig.SUSTAIN_SECONDS);
        int tokeniseRps  = Math.max(1, (int) (targetRps * 0.70));
        int detokeniseRps = Math.max(1, targetRps - tokeniseRps);
        int ramp    = SimulationConfig.RAMP_SECONDS;
        int sustain = SimulationConfig.SUSTAIN_SECONDS;

        setUp(
                tokenise.injectOpen(
                        rampUsersPerSec(1).to(tokeniseRps).during(ramp),
                        constantUsersPerSec(tokeniseRps).during(sustain)
                ),
                detokenise.injectOpen(
                        rampUsersPerSec(1).to(detokeniseRps).during(ramp),
                        constantUsersPerSec(detokeniseRps).during(sustain)
                )
        ).protocols(protocol)
                .assertions(
                        global().responseTime().percentile(99).lt(2000),
                        global().successfulRequests().percent().gte(99.0)
                );
    }

    @Override
    public void before() {
        int targetRps = Math.max(1, SimulationConfig.TOTAL_REQUESTS / SimulationConfig.SUSTAIN_SECONDS);
        System.out.printf("[MixedSimulation] Clearing DB and seeding %d tokens for detokenise path...%n",
                SEED_COUNT);
        DbSetupHelper.truncate();
        seedTokensViaHttp(SEED_COUNT);
        System.out.printf("[MixedSimulation] Seeded %d tokens. Starting simulation " +
                "(totalRequests=%d, targetRps=%d, 70%% tokenise / 30%% detokenise).%n",
                seededTokens.size(), SimulationConfig.TOTAL_REQUESTS, targetRps);
    }

    private String randomToken() {
        if (seededTokens.isEmpty()) return "no-token-seeded";
        return seededTokens.get(ThreadLocalRandom.current().nextInt(seededTokens.size()));
    }

    private void seedTokensViaHttp(int count) {
        // Parallel seeding — 20 concurrent HTTP workers reduce setup time from ~150s to ~8s for 10k tokens.
        java.net.http.HttpClient client = java.net.http.HttpClient.newHttpClient();
        ExecutorService exec = Executors.newFixedThreadPool(20);
        List<Callable<Void>> tasks = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            tasks.add(() -> {
                try {
                    String pan = TokenisationSimulation.generateVisa16();
                    String body = buildTokeniseBody(pan);
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
                    System.err.println("[MixedSimulation] Seed error: " + e.getMessage());
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

    private static String buildTokeniseBody() {
        return buildTokeniseBody(TokenisationSimulation.generateVisa16());
    }

    private static String buildTokeniseBody(String pan) {
        return String.format(
                "{\"pan\":\"%s\",\"cardScheme\":\"MC\",\"expiryMonth\":12,\"expiryYear\":2029}", pan);
    }

    private static String extractToken(String json) {
        int idx = json.indexOf("\"token\":\"");
        if (idx < 0) return null;
        int start = idx + 9;
        int end = json.indexOf("\"", start);
        return end < 0 ? null : json.substring(start, end);
    }
}
