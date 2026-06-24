package com.yourorg.tokenisation.crypto;

import com.yourorg.tokenisation.AbstractIntegrationTest;
import com.yourorg.tokenisation.domain.KeyStatus;
import com.yourorg.tokenisation.kms.DataKey;
import com.yourorg.tokenisation.kms.KmsProvider;
import com.yourorg.tokenisation.repository.KeyVersionRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.dao.InvalidDataAccessApiUsageException;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Integration test for {@link KeyRingInitialiser}.
 *
 * <p>{@link KeyRingInitialiser} is mocked out of the Spring context (via {@link MockBean})
 * to prevent it from auto-running during context startup. Each test seeds the
 * {@code key_versions} table, then constructs and invokes the real initialiser manually.
 * The Spring-managed {@link InMemoryDekKeyRing} bean is used as the assertion target
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
    private InMemoryDekKeyRing dekRing;

    @Autowired
    private InMemoryHmacKeyRing hmacKeyRing;

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
        // Clear all key_versions left by the test, then re-insert the fixed seed ACTIVE row
        // so subsequent test classes can load their context.
        // The unique constraint allows only one ACTIVE row per type, so we must remove test rows
        // before inserting the seed — not just rely on ON CONFLICT DO NOTHING.
        jdbcTemplate.execute("DELETE FROM key_versions");

        DataKey dataKey = kmsProvider.generateDataKey();
        byte[] encryptedDekBlob = dataKey.encryptedDekBlob().clone();
        Arrays.fill(dataKey.plaintextDek(), (byte) 0);

        jdbcTemplate.update("""
                INSERT INTO key_versions (id, kms_key_id, kms_provider, key_alias, encrypted_dek_blob,
                    key_type, status, activated_at, rotate_by, created_by)
                VALUES (?::uuid, ?, ?, ?, ?, ?, ?, now(), ?, ?)
                """,
                SEED_KEY_VERSION_ID,
                "local-dev-key",
                "LOCAL_DEV",
                "integration-test-seed-key",
                encryptedDekBlob,
                "DEK",
                "ACTIVE",
                Timestamp.from(Instant.now().plusSeconds(365L * 24 * 60 * 60)),
                "test-seeder"
        );
    }

    @Test
    void run_activeKeyVersionInDatabase_isLoadedAndPromotedAsActive() {
        String activeVersionId = insertKeyVersion(KeyStatus.ACTIVE, "active-key");
        KeyRingInitialiser initialiserUnderTest = buildInitialiser();

        initialiserUnderTest.run(null);

        assertThat(dekRing.contains(activeVersionId)).isTrue();
        KeyMaterial activeMaterial = dekRing.getActive();
        assertThat(activeMaterial.keyVersionId()).isEqualTo(activeVersionId);
        assertThat(activeMaterial.status()).isEqualTo(KeyStatus.ACTIVE);
    }

    @Test
    void run_rotatingKeyVersionInDatabase_isLoadedButActiveVersionPromoted() {
        String activeVersionId = insertKeyVersion(KeyStatus.ACTIVE, "active-key");
        String rotatingVersionId = insertKeyVersion(KeyStatus.ROTATING, "rotating-key");
        KeyRingInitialiser initialiserUnderTest = buildInitialiser();

        initialiserUnderTest.run(null);

        // Both versions must be in the ring for concurrent detokenisation during rotation
        assertThat(dekRing.contains(activeVersionId)).isTrue();
        assertThat(dekRing.contains(rotatingVersionId)).isTrue();
        // Only the ACTIVE version must be promoted — ROTATING is loaded for decryption only
        assertThat(dekRing.getActive().keyVersionId()).isEqualTo(activeVersionId);
    }

    @Test
    void run_retiredKeyVersionInDatabase_isNotLoadedIntoKeyRing() {
        insertKeyVersion(KeyStatus.ACTIVE, "active-key");
        String retiredVersionId = insertKeyVersion(KeyStatus.RETIRED, "retired-key");
        KeyRingInitialiser initialiserUnderTest = buildInitialiser();

        initialiserUnderTest.run(null);

        // RETIRED versions are not loaded — they are historical, not needed for crypto operations
        assertThat(dekRing.contains(retiredVersionId)).isFalse();
    }

    @Test
    void run_dekBytesLoadedFromLocalDevAdapter_are32Bytes() {
        String activeVersionId = insertKeyVersion(KeyStatus.ACTIVE, "dek-size-test");
        KeyRingInitialiser initialiserUnderTest = buildInitialiser();

        initialiserUnderTest.run(null);

        byte[] dek = dekRing.getByVersion(activeVersionId).copyDek();
        assertThat(dek).hasSize(32);
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
                .hasMessageContaining("ACTIVE DEK version");
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
        return new KeyRingInitialiser(kmsProvider, keyVersionRepository, dekRing, hmacKeyRing);
    }

    /**
     * Inserts a DEK key version row into {@code key_versions} for testing.
     *
     * <p>Calls {@link KmsProvider#generateDataKey()} to generate a real AES-GCM encrypted blob
     * so that {@code LocalDevKmsAdapter.decryptDataKey()} can successfully decrypt it when
     * {@link KeyRingInitialiser} loads the ring.
     *
     * @param status   the lifecycle status to assign to the key version
     * @param keyAlias a human-readable alias used in test output and logging
     * @return the UUID string of the inserted key version row
     */
    private String insertKeyVersion(KeyStatus status, String keyAlias) {
        String versionId = UUID.randomUUID().toString();
        Timestamp rotateBy = Timestamp.from(Instant.now().plusSeconds(365L * 24 * 60 * 60));

        DataKey dataKey = kmsProvider.generateDataKey();
        byte[] encryptedDekBlob = dataKey.encryptedDekBlob().clone();
        Arrays.fill(dataKey.plaintextDek(), (byte) 0);

        jdbcTemplate.update("""
                INSERT INTO key_versions (id, kms_key_id, kms_provider, key_alias, encrypted_dek_blob,
                    key_type, status, activated_at, rotate_by, created_by)
                VALUES (?::uuid, ?, ?, ?, ?, ?, ?, now(), ?, ?)
                """,
                versionId,
                "local-dev-key",
                "LOCAL_DEV",
                keyAlias,
                encryptedDekBlob,
                "DEK",
                status.name(),
                rotateBy,
                "integration-test"
        );
        return versionId;
    }
}
