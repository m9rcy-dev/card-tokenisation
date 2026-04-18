package com.yourorg.tokenisation;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Asserts that the {@code tokenisation_app} database role has exactly the right
 * privilege set on each application table.
 *
 * <p>This test provides the PP-1 pre-production hardening guarantee: the audit log
 * is append-only at the database level. Once an audit event is written, neither
 * the application role nor a compromised application process can alter or delete it.
 *
 * <p>The verification is done by querying {@code information_schema.role_table_grants},
 * which lists all privileges that have been explicitly granted to a role on a table.
 * A privilege absent from the result means it was never granted — which is the correct
 * end-state for UPDATE and DELETE on {@code token_audit_log}.
 *
 * <h3>Expected privilege matrix</h3>
 * <pre>
 *   Table               SELECT   INSERT   UPDATE   DELETE
 *   key_versions          YES      YES      YES      NO
 *   token_vault           YES      YES      YES      YES
 *   token_audit_log       YES      YES      NO       NO   ← append-only
 * </pre>
 */
class DbRoleRestrictionTest extends AbstractIntegrationTest {

    private static final String ROLE = "tokenisation_app";

    @Autowired
    private JdbcTemplate jdbcTemplate;

    // ── token_audit_log ───────────────────────────────────────────────────────

    @Test
    void auditLog_tokenisationApp_hasSelectPrivilege() {
        assertGranted("token_audit_log", "SELECT");
    }

    @Test
    void auditLog_tokenisationApp_hasInsertPrivilege() {
        assertGranted("token_audit_log", "INSERT");
    }

    @Test
    void auditLog_tokenisationApp_lacksUpdatePrivilege() {
        assertNotGranted("token_audit_log", "UPDATE");
    }

    @Test
    void auditLog_tokenisationApp_lacksDeletePrivilege() {
        assertNotGranted("token_audit_log", "DELETE");
    }

    // ── key_versions ──────────────────────────────────────────────────────────

    @Test
    void keyVersions_tokenisationApp_hasSelectPrivilege() {
        assertGranted("key_versions", "SELECT");
    }

    @Test
    void keyVersions_tokenisationApp_hasInsertPrivilege() {
        assertGranted("key_versions", "INSERT");
    }

    @Test
    void keyVersions_tokenisationApp_hasUpdatePrivilege() {
        assertGranted("key_versions", "UPDATE");
    }

    @Test
    void keyVersions_tokenisationApp_lacksDeletePrivilege() {
        assertNotGranted("key_versions", "DELETE");
    }

    // ── token_vault ───────────────────────────────────────────────────────────

    @Test
    void tokenVault_tokenisationApp_hasSelectPrivilege() {
        assertGranted("token_vault", "SELECT");
    }

    @Test
    void tokenVault_tokenisationApp_hasInsertPrivilege() {
        assertGranted("token_vault", "INSERT");
    }

    @Test
    void tokenVault_tokenisationApp_hasUpdatePrivilege() {
        assertGranted("token_vault", "UPDATE");
    }

    @Test
    void tokenVault_tokenisationApp_hasDeletePrivilege() {
        assertGranted("token_vault", "DELETE");
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /**
     * Asserts that {@code tokenisation_app} has been granted {@code privilege} on {@code table}.
     *
     * @param table     the table name (lower-case, as stored in information_schema)
     * @param privilege the privilege type (SELECT, INSERT, UPDATE, DELETE)
     */
    private void assertGranted(String table, String privilege) {
        List<String> granted = fetchGrantedPrivileges(table);
        assertThat(granted)
                .as("Expected %s to have %s privilege on %s", ROLE, privilege, table)
                .contains(privilege);
    }

    /**
     * Asserts that {@code tokenisation_app} has NOT been granted {@code privilege} on {@code table}.
     *
     * @param table     the table name
     * @param privilege the privilege type
     */
    private void assertNotGranted(String table, String privilege) {
        List<String> granted = fetchGrantedPrivileges(table);
        assertThat(granted)
                .as("Expected %s NOT to have %s privilege on %s", ROLE, privilege, table)
                .doesNotContain(privilege);
    }

    /**
     * Queries {@code information_schema.role_table_grants} and returns the list of
     * privilege types granted to {@code tokenisation_app} on the given table.
     *
     * @param table the table name to query
     * @return list of privilege type strings (e.g. ["SELECT", "INSERT"])
     */
    private List<String> fetchGrantedPrivileges(String table) {
        return jdbcTemplate.queryForList(
                """
                SELECT privilege_type
                FROM information_schema.role_table_grants
                WHERE grantee = ?
                  AND table_name = ?
                  AND table_schema = 'public'
                """,
                String.class,
                ROLE, table);
    }
}
