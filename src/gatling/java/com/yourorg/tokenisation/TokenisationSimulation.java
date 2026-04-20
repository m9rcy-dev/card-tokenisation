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
 * <h3>Scales (drive via {@code -DtotalRequests=N})</h3>
 * <ul>
 *   <li>20K  → {@code mvn gatling:test -P gatling-tests -DtotalRequests=20000}
 *   <li>50K  → {@code -DtotalRequests=50000}
 *   <li>100K → {@code -DtotalRequests=100000}
 *   <li>1M   → {@code -DtotalRequests=1000000}
 * </ul>
 *
 * <h3>Prerequisites</h3>
 * <ol>
 *   <li>Application is running: {@code make start}
 *   <li>Database is reachable at {@code dbUrl} (defaults to localhost:5432/tokenisation)
 *   <li>Seed key is loaded in the application's key ring
 * </ol>
 *
 * <h3>What this simulation measures</h3>
 * <ul>
 *   <li>Throughput (requests/second) at the configured user count
 *   <li>Response time percentiles (p50, p75, p95, p99) from Gatling HTML report
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
        // Target: TOTAL_REQUESTS in SUSTAIN_SECONDS at MAX_USERS concurrency.
        // Ramp up over RAMP_SECONDS before sustaining.
        int targetRps = Math.max(1, SimulationConfig.TOTAL_REQUESTS / SimulationConfig.SUSTAIN_SECONDS);

        setUp(
                tokenise.injectOpen(
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
        System.out.printf("[TokenisationSimulation] Clearing database before run " +
                "(totalRequests=%d, maxUsers=%d)%n",
                SimulationConfig.TOTAL_REQUESTS, SimulationConfig.MAX_USERS);
        DbSetupHelper.truncate();
    }

    private static String buildRequestBody() {
        String pan = generateVisa16();
        return String.format("""
                {
                  "pan": "%s",
                  "tokenType": "ONE_TIME",
                  "merchantId": "%s",
                  "cardScheme": "VISA",
                  "expiryMonth": 12,
                  "expiryYear": 2029
                }""", pan, SimulationConfig.MERCHANT_ID);
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
