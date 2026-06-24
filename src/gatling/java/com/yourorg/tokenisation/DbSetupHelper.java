package com.yourorg.tokenisation;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.UUID;

/**
 * Standalone JDBC helper for Gatling simulation setup and teardown.
 *
 * <p>Gatling simulations run outside the Spring application context, so database
 * preparation cannot use Spring beans. This helper connects directly to PostgreSQL
 * using the JDBC URL, username, and password from {@link SimulationConfig}.
 *
 * <p>Call {@link #truncate()} in a simulation's {@code before()} hook to ensure a
 * clean slate before each simulation run. This prevents stale tokens from a previous
 * run affecting throughput or correctness measurements.
 *
 * <p><strong>Prerequisites:</strong> The database must be reachable and the user must
 * have DELETE privileges on {@code token_vault} and {@code token_audit_log}.
 */
public final class DbSetupHelper {

    private DbSetupHelper() {}

    /**
     * Truncates {@code token_vault} and {@code token_audit_log}.
     *
     * <p>Uses DELETE rather than TRUNCATE to avoid table-level locks and maintain
     * compatibility with the append-only audit log role restriction defined in V6
     * migration. The tokenisation_app role has DELETE on token_vault and INSERT-only
     * on token_audit_log — so this helper must be called with a superuser or a
     * dedicated test role that has DELETE on both tables.
     */
    public static void truncate() {
        try (Connection conn = openConnection();
             Statement stmt = conn.createStatement()) {
            stmt.execute("DELETE FROM token_vault");
            stmt.execute("DELETE FROM token_audit_log");
            System.out.println("[DbSetupHelper] token_vault and token_audit_log cleared.");
        } catch (SQLException e) {
            throw new RuntimeException("DbSetupHelper.truncate() failed: " + e.getMessage(), e);
        }
    }

    /**
     * Resets KEK state so exactly one ACTIVE KEK exists — whichever one is currently
     * ACTIVE in the database — and all other KEK versions are RETIRED.
     *
     * <p>HMAC key versions are intentionally untouched so that PAN de-duplication
     * continues to work after the reset.
     *
     * <p>Call this before rotation simulations to drain any leftover ROTATING or
     * COMPROMISED KEKs from a previous run, leaving the app in a clean pre-rotation
     * state that matches its in-memory ring.
     *
     * @throws IllegalStateException if no ACTIVE KEK exists (app is not running or ring
     *                               failed to initialise)
     */
    public static void resetKeyVersions() {
        try (Connection conn = openConnection()) {
            // Discover the UUID the live app is actually using — do not assume a fixed UUID.
            // LocalDevKeySeeder uses gen_random_uuid(); only TestDataSeederConfig (test-only)
            // inserts the well-known 00000000-...-000001 UUID.
            String activeKekId;
            try (PreparedStatement find = conn.prepareStatement(
                    "SELECT id FROM key_versions WHERE key_type = 'KEK' AND status = 'ACTIVE' LIMIT 1")) {
                var rs = find.executeQuery();
                if (!rs.next()) {
                    throw new IllegalStateException(
                            "[DbSetupHelper] No ACTIVE KEK in key_versions. " +
                            "Is the application running and fully initialised?");
                }
                activeKekId = rs.getString(1);
            }
            // Retire only KEK rows — leave HMAC rows untouched so pan_hash lookups still work.
            try (PreparedStatement retire = conn.prepareStatement(
                    "UPDATE key_versions SET status = 'RETIRED' " +
                    "WHERE key_type = 'KEK' AND id != ?::uuid AND status != 'RETIRED'")) {
                retire.setString(1, activeKekId);
                int rows = retire.executeUpdate();
                if (rows > 0) {
                    System.out.println("[DbSetupHelper] Retired " + rows + " stale KEK version(s) from previous run.");
                }
            }
            System.out.println("[DbSetupHelper] KEK versions reset. Active KEK: [" + activeKekId + "]");
        } catch (SQLException e) {
            throw new RuntimeException("DbSetupHelper.resetKeyVersions() failed: " + e.getMessage(), e);
        }
    }

    /**
     * Returns the count of active tokens on the given key version — useful for
     * polling in rotation simulation until all tokens are migrated.
     *
     * @param keyVersionId the key version UUID to count
     * @return number of active token_vault rows on that key version
     */
    public static long countActiveTokens(UUID keyVersionId) {
        try (Connection conn = openConnection();
             PreparedStatement ps = conn.prepareStatement(
                     "SELECT COUNT(*) FROM token_vault WHERE key_version_id = ?::uuid AND is_active = true")) {
            ps.setString(1, keyVersionId.toString());
            var rs = ps.executeQuery();
            rs.next();
            return rs.getLong(1);
        } catch (SQLException e) {
            throw new RuntimeException("DbSetupHelper.countActiveTokens() failed: " + e.getMessage(), e);
        }
    }

    private static Connection openConnection() throws SQLException {
        return DriverManager.getConnection(
                SimulationConfig.DB_URL,
                SimulationConfig.DB_USER,
                SimulationConfig.DB_PASS);
    }
}
