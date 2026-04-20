package com.yourorg.tokenisation;

/**
 * Shared configuration for all Gatling simulations.
 *
 * <p>Values are read from Java system properties so they can be overridden per-invocation:
 * <pre>
 *   mvn gatling:test -P gatling-tests \
 *     -DbaseUrl=http://localhost:8080 \
 *     -DtotalRequests=50000 \
 *     -DdbUrl=jdbc:postgresql://localhost:5432/tokenisation
 * </pre>
 *
 * <p>Default values target a local development instance started via {@code make start}.
 */
public final class SimulationConfig {

    /** Base URL of the running application. Override with {@code -DbaseUrl=...}. */
    public static final String BASE_URL =
            System.getProperty("baseUrl", "http://localhost:8080");

    /**
     * Total number of requests the simulation should generate.
     * Override with {@code -DtotalRequests=N} (e.g. 20000, 50000, 100000, 1000000).
     */
    public static final int TOTAL_REQUESTS =
            Integer.parseInt(System.getProperty("totalRequests", "20000"));

    /** Maximum concurrent users (virtual users in Gatling terms). */
    public static final int MAX_USERS =
            Integer.parseInt(System.getProperty("maxUsers", "20"));

    /** Ramp-up duration in seconds before reaching {@link #MAX_USERS}. */
    public static final int RAMP_SECONDS =
            Integer.parseInt(System.getProperty("rampSeconds", "30"));

    /** Sustained load duration in seconds after ramp-up. */
    public static final int SUSTAIN_SECONDS =
            Integer.parseInt(System.getProperty("sustainSeconds", "120"));

    /** Merchant ID header value sent on all requests. */
    public static final String MERCHANT_ID =
            System.getProperty("merchantId", "GATLING_MERCHANT");

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
