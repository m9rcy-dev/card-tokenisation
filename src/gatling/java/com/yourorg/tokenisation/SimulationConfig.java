package com.yourorg.tokenisation;

/**
 * Shared configuration for all Gatling simulations.
 *
 * <p>Values are read from Java system properties so they can be overridden per-invocation:
 * <pre>
 *   mvn gatling:test -P gatling-tests \
 *     -DbaseUrl=http://localhost:8080 \
 *     -DtotalRequests=50000 \
 *     -DsustainSeconds=120 \
 *     -DdbUrl=jdbc:postgresql://localhost:5432/tokenisation
 * </pre>
 *
 * <h3>How scale works</h3>
 * All simulations derive their target throughput as:
 * <pre>
 *   targetRps = totalRequests / sustainSeconds
 * </pre>
 * Virtual users are injected at {@code targetRps} users/second. Each user fires one
 * request and exits (open workload model). For 100k requests over 120 seconds:
 * targetRps = 833 — the simulation fires 833 new virtual users every second.
 *
 * <p>Spread load over a longer window when the target RPS is too high for the machine:
 * {@code -DtotalRequests=100000 -DsustainSeconds=300} → 333 rps.
 *
 * <p>Default values target a local development instance started via {@code make start}.
 */
public final class SimulationConfig {

    /** Base URL of the running application. Override with {@code -DbaseUrl=...}. */
    public static final String BASE_URL =
            System.getProperty("baseUrl", "http://localhost:8080");

    /**
     * Total number of requests the simulation should generate.
     * Controls target RPS together with {@link #SUSTAIN_SECONDS}:
     * {@code targetRps = TOTAL_REQUESTS / SUSTAIN_SECONDS}.
     * Override with {@code -DtotalRequests=N} (e.g. 20000, 50000, 100000, 1000000).
     */
    public static final int TOTAL_REQUESTS =
            Integer.parseInt(System.getProperty("totalRequests", "20000"));

    /** Ramp-up duration in seconds. Users per second climbs from 1 to targetRps during this window. */
    public static final int RAMP_SECONDS =
            Integer.parseInt(System.getProperty("rampSeconds", "30"));

    /**
     * Sustained load duration in seconds after ramp-up.
     * Increase this to spread a large {@link #TOTAL_REQUESTS} over a longer window
     * and reduce instantaneous RPS: {@code -DsustainSeconds=300} halves the RPS of a
     * 120-second run at the same total request count.
     */
    public static final int SUSTAIN_SECONDS =
            Integer.parseInt(System.getProperty("sustainSeconds", "120"));

    // ── Database connection for before()/after() hooks ────────────────────────

    /** JDBC URL for the database backing the target application instance. */
    public static final String DB_URL =
            System.getProperty("dbUrl", "jdbc:postgresql://localhost:5432/tokenisation");

    /** Database username. Override with {@code -DdbUser=...}. */
    public static final String DB_USER =
            System.getProperty("dbUser", "tokenisation_app");

    /** Database password. Override with {@code -DdbPass=...}. */
    public static final String DB_PASS =
            System.getProperty("dbPass", "change_me");

    private SimulationConfig() {}
}
