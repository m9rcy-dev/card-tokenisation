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
     * Resets key version state so the seed key is ACTIVE and all other keys are RETIRED.
     *
     * <p>Call this before rotation simulations to ensure the key ring starts in a known state.
     *
     * @param seedKeyVersionId the UUID of the seed key version to set ACTIVE
     */
    public static void resetKeyVersions(String seedKeyVersionId) {
        try (Connection conn = openConnection()) {
            try (PreparedStatement retire = conn.prepareStatement(
                    "UPDATE key_versions SET status = 'RETIRED' WHERE id != ?::uuid")) {
                retire.setString(1, seedKeyVersionId);
                retire.executeUpdate();
            }
            try (PreparedStatement activate = conn.prepareStatement(
                    "UPDATE key_versions SET status = 'ACTIVE' WHERE id = ?::uuid")) {
                activate.setString(1, seedKeyVersionId);
                activate.executeUpdate();
            }
            System.out.println("[DbSetupHelper] Key versions reset: seed key [" + seedKeyVersionId + "] is ACTIVE.");
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
