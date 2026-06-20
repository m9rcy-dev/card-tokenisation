package com.yourorg.tokenisation;

import io.gatling.javaapi.core.ScenarioBuilder;
import io.gatling.javaapi.core.Simulation;
import io.gatling.javaapi.http.HttpProtocolBuilder;

import java.util.concurrent.ThreadLocalRandom;

import static io.gatling.javaapi.core.CoreDsl.*;
import static io.gatling.javaapi.http.HttpDsl.*;

/**
 * Gatling simulation for the tokenisation endpoint ({@code POST /api/v1/tokens}).
 *
 * <h3>How to run</h3>
 * <pre>
 *   make start                                          # start the app first
 *   make gatling-test GATLING_SIM=TokenisationSimulation GATLING_SCALE=20k
 *   make gatling-test GATLING_SIM=TokenisationSimulation GATLING_SCALE=100k
 *   # Spread 100k over 5 minutes to reduce RPS from 833 to 333:
 *   make gatling-test GATLING_SIM=TokenisationSimulation GATLING_SCALE=100k GATLING_DURATION=300
 * </pre>
 *
 * <h3>What this simulation measures</h3>
 * <ul>
 *   <li>Pure write throughput — every request is a unique PAN, no dedup path hit
 *   <li>Throughput (rps) and response time percentiles (p50, p75, p95, p99)
 *   <li>Error rate (non-201 responses)
 * </ul>
 *
 * <p>Results are written to {@code target/gatling/} as an HTML report.
 */
public class TokenisationSimulation extends Simulation {

    private final HttpProtocolBuilder protocol = http
            .baseUrl(SimulationConfig.BASE_URL)
            .acceptHeader("application/json")
            .contentTypeHeader("application/json");

    /**
     * Generates a random Luhn-valid 16-digit Visa PAN for each request.
     * Using a random PAN per request avoids hitting the RECURRING de-duplication
     * path and exercises the full tokenisation write path every time.
     */
    private final ScenarioBuilder tokenise = scenario("Tokenise POST /api/v1/tokens")
            .exec(http("POST /api/v1/tokens")
                    .post("/api/v1/tokens")
                    .body(StringBody(session -> buildRequestBody()))
                    .check(status().is(201))
                    .check(jsonPath("$.token").saveAs("createdToken")));

    {
        // targetRps drives both ramp ceiling and sustained injection rate so that
        // approximately TOTAL_REQUESTS are fired over SUSTAIN_SECONDS.
        int targetRps = Math.max(1, SimulationConfig.TOTAL_REQUESTS / SimulationConfig.SUSTAIN_SECONDS);

        setUp(
                tokenise.injectOpen(
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
        int targetRps = Math.max(1, SimulationConfig.TOTAL_REQUESTS / SimulationConfig.SUSTAIN_SECONDS);
        System.out.printf("[TokenisationSimulation] Clearing database before run " +
                "(totalRequests=%d, targetRps=%d).%n",
                SimulationConfig.TOTAL_REQUESTS, targetRps);
        DbSetupHelper.truncate();
    }

    private static String buildRequestBody() {
        String pan = generateVisa16();
        return String.format("""
                {
                  "pan": "%s",
                  "cardScheme": "MC",
                  "expiryMonth": 12,
                  "expiryYear": 2029
                }""", pan);
    }

    /**
     * Generates a random Luhn-valid 16-digit Visa PAN (starts with 4).
     *
     * <p>Processes right-to-left: the rightmost payload digit (index 14) is doubled first,
     * then every other digit going left. This matches the service's {@code isLuhnValid()}
     * and {@code PanGenerator.luhnCheckDigit()} — PANs that pass here will pass the server.
     */
    static String generateVisa16() {
        ThreadLocalRandom rng = ThreadLocalRandom.current();
        int[] digits = new int[16];
        digits[0] = 4;
        for (int i = 1; i < 15; i++) {
            digits[i] = rng.nextInt(10);
        }
        // Compute Luhn check digit right-to-left: double every second digit starting
        // from the rightmost payload digit (index 14).
        int sum = 0;
        boolean doubleIt = true;
        for (int i = 14; i >= 0; i--) {
            int d = digits[i];
            if (doubleIt) {
                d *= 2;
                if (d > 9) d -= 9;
            }
            sum += d;
            doubleIt = !doubleIt;
        }
        digits[15] = (10 - (sum % 10)) % 10;
        StringBuilder sb = new StringBuilder(16);
        for (int d : digits) sb.append(d);
        return sb.toString();
    }
}
