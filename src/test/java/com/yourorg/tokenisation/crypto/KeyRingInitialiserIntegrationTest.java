package com.yourorg.tokenisation.crypto;

import com.yourorg.tokenisation.AbstractIntegrationTest;
import com.yourorg.tokenisation.domain.KeyStatus;

import static com.yourorg.tokenisation.AbstractIntegrationTest.SEED_KEY_VERSION_ID;
import com.yourorg.tokenisation.kms.KmsProvider;
import com.yourorg.tokenisation.repository.KeyVersionRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;

import org.springframework.dao.InvalidDataAccessApiUsageException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Integration test for {@link KeyRingInitialiser}.
 *
 * <p>{@link KeyRingInitialiser} is mocked out of the Spring context (via {@link MockBean})
 * to prevent it from auto-running during context startup. Each test seeds the
 * {@code key_versions} table, then constructs and invokes the real initialiser manually.
 * The Spring-managed {@link InMemoryKeyRing} bean is used as the assertion target
 * so that we verify the same ring that production code would use.
 *
 * <p>Uses a real PostgreSQL container via {@link AbstractIntegrationTest}.
 * No cloud credentials required — {@code LocalDevKmsAdapter} is active.
 */
class KeyRingInitialiserIntegrationTest extends AbstractIntegrationTest {

    /**
     * Replaces the {@link KeyRingInitialiser} bean with a no-op mock during context startup,
     * allowing us to control exactly when {@code run()} is called.
     */
    @MockBean
    @SuppressWarnings("unused")
    private KeyRingInitialiser suppressedAutoRun;

    @Autowired
    private KmsProvider kmsProvider;

    @Autowired
    private KeyVersionRepository keyVersionRepository;

    @Autowired
    private InMemoryKeyRing keyRing;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void cleanDatabase() {
        jdbcTemplate.execute("DELETE FROM token_vault");
        jdbcTemplate.execute("DELETE FROM token_audit_log");
        jdbcTemplate.execute("DELETE FROM key_versions");
    }

    @AfterEach
    void restoreSeedKeyVersion() {
        // Clear all key_versions left by the test (may include ACTIVE rows with random UUIDs),
        // then re-insert the fixed seed ACTIVE row so subsequent test classes can load their context.
        // The unique constraint idx_key_versions_single_active allows only one ACTIVE row, so we must
        // remove test rows before inserting the seed — not just rely on ON CONFLICT DO NOTHING.
        jdbcTemplate.execute("DELETE FROM key_versions");
        jdbcTemplate.update("""
                INSERT INTO key_versions (id, kms_key_id, kms_provider, key_alias, encrypted_kek_blob,
                    status, activated_at, rotate_by, created_by, checksum)
                VALUES (?::uuid, ?, ?, ?, ?, ?, now(), ?, ?, ?)
                """,
                SEED_KEY_VERSION_ID,
                "local-dev-key",
                "LOCAL_DEV",
                "integration-test-seed-key",
                "ignored",
                "ACTIVE",
                Timestamp.from(Instant.now().plusSeconds(365L * 24 * 60 * 60)),
                "test-seeder",
                "seed-checksum"
        );
    }

    @Test
    void run_activeKeyVersionInDatabase_isLoadedAndPromotedAsActive() throws Exception {
        String activeVersionId = insertKeyVersion(KeyStatus.ACTIVE, "active-key");
        KeyRingInitialiser initialiserUnderTest = buildInitialiser();

        initialiserUnderTest.run(null);

        // Verify the ACTIVE version is accessible via the Spring-managed ring
        assertThat(keyRing.contains(activeVersionId)).isTrue();
        KeyMaterial activeMaterial = keyRing.getActive();
        assertThat(activeMaterial.keyVersionId()).isEqualTo(activeVersionId);
        assertThat(activeMaterial.status()).isEqualTo(KeyStatus.ACTIVE);
    }

    @Test
    void run_rotatingKeyVersionInDatabase_isLoadedButActiveVersionPromoted() throws Exception {
        String activeVersionId = insertKeyVersion(KeyStatus.ACTIVE, "active-key");
        String rotatingVersionId = insertKeyVersion(KeyStatus.ROTATING, "rotating-key");
        KeyRingInitialiser initialiserUnderTest = buildInitialiser();

        initialiserUnderTest.run(null);

        // Both versions must be in the ring for concurrent detokenisation during rotation
        assertThat(keyRing.contains(activeVersionId)).isTrue();
        assertThat(keyRing.contains(rotatingVersionId)).isTrue();
        // Only the ACTIVE version must be promoted — ROTATING is loaded for decryption only
        assertThat(keyRing.getActive().keyVersionId()).isEqualTo(activeVersionId);
    }

    @Test
    void run_retiredKeyVersionInDatabase_isNotLoadedIntoKeyRing() throws Exception {
        insertKeyVersion(KeyStatus.ACTIVE, "active-key");
        String retiredVersionId = insertKeyVersion(KeyStatus.RETIRED, "retired-key");
        KeyRingInitialiser initialiserUnderTest = buildInitialiser();

        initialiserUnderTest.run(null);

        // RETIRED versions are not loaded — they are historical, not needed for crypto operations
        assertThat(keyRing.contains(retiredVersionId)).isFalse();
    }

    @Test
    void run_kekBytesLoadedFromLocalDevAdapter_are32Bytes() throws Exception {
        String activeVersionId = insertKeyVersion(KeyStatus.ACTIVE, "kek-size-test");
        KeyRingInitialiser initialiserUnderTest = buildInitialiser();

        initialiserUnderTest.run(null);

        byte[] kek = keyRing.getByVersion(activeVersionId).copyKek();
        assertThat(kek).hasSize(32);
    }

    @Test
    void run_noActiveKeyVersionInDatabase_throwsIllegalState() {
        // A ROTATING-only database (mid-rotation crash scenario) has no ACTIVE version
        insertKeyVersion(KeyStatus.ROTATING, "rotating-only");
        KeyRingInitialiser initialiserUnderTest = buildInitialiser();

        // Spring Data JPA's exception translator wraps IllegalStateException thrown from
        // default repository methods into InvalidDataAccessApiUsageException.
        // We verify the translated exception type and the preserved root message.
        assertThatThrownBy(() -> initialiserUnderTest.run(null))
                .isInstanceOf(InvalidDataAccessApiUsageException.class)
                .hasMessageContaining("ACTIVE key version");
    }

    /**
     * Builds a real {@link KeyRingInitialiser} instance using the Spring-managed collaborators.
     *
     * <p>This ensures the initialiser under test uses the same key ring, repository, and KMS
     * provider beans as production code — only the invocation timing is controlled.
     *
     * @return a configured but not yet executed initialiser
     */
    private KeyRingInitialiser buildInitialiser() {
        return new KeyRingInitialiser(kmsProvider, keyVersionRepository, keyRing);
    }

    /**
     * Inserts a key version row into the {@code key_versions} table for testing.
     *
     * <p>{@code encrypted_kek_blob} is set to {@code "ignored"} because
     * {@code LocalDevKmsAdapter.unwrapKek()} ignores the blob value and always returns
     * the fixed local KEK configured in {@code kms.local-dev.kek-hex}.
     *
     * @param status   the lifecycle status to assign to the key version
     * @param keyAlias a human-readable alias used in test output and logging
     * @return the UUID string of the inserted key version row
     */
    private String insertKeyVersion(KeyStatus status, String keyAlias) {
        String versionId = UUID.randomUUID().toString();
        Timestamp rotateBy = Timestamp.from(Instant.now().plusSeconds(365L * 24 * 60 * 60));
        jdbcTemplate.update("""
                INSERT INTO key_versions (id, kms_key_id, kms_provider, key_alias, encrypted_kek_blob,
                    status, activated_at, rotate_by, created_by, checksum)
                VALUES (?::uuid, ?, ?, ?, ?, ?, now(), ?, ?, ?)
                """,
                versionId,
                "local-dev-key",
                "LOCAL_DEV",
                keyAlias,
                "ignored",
                status.name(),
                rotateBy,
                "integration-test",
                "placeholder-checksum"
        );
        return versionId;
    }
}
