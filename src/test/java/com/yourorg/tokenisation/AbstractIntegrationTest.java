package com.yourorg.tokenisation;

import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;

import java.sql.Timestamp;
import java.time.Instant;

/**
 * Base class for all functional integration tests.
 *
 * <p>Provides a real PostgreSQL instance via Testcontainers. The container is started
 * once per JVM using a static initialiser block — not via {@code @Testcontainers} /
 * {@code @Container}. This is intentional: the JUnit 5 {@code @Container} lifecycle
 * stops the container after each test class finishes. Because Spring's test context
 * cache retains the datasource URL (including the mapped port) for the lifetime of the
 * JVM, stopping and restarting the container between classes yields a new port that the
 * cached context does not know about, causing connection failures. Using a static
 * initialiser keeps the container alive for the entire test run; Testcontainers' Ryuk
 * resource reaper handles cleanup when the JVM exits.
 *
 * <p>All subclasses use {@code LocalDevKmsAdapter} ({@code kms.provider=local-dev})
 * so that no cloud credentials or network access are required during the test run.
 *
 * <p>The {@code application-test.yml} profile provides conservative rate-limiting
 * thresholds and disables the rotation {@code @Scheduled} cron so that rotation
 * tests can trigger the job explicitly and deterministically.
 *
 * <p>A {@link TestDataSeederConfig} provides a high-priority {@link ApplicationRunner}
 * that inserts a fixed-UUID ACTIVE key version ({@link #SEED_KEY_VERSION_ID}) before
 * {@code KeyRingInitialiser.run()} executes. This ensures the key ring can always
 * initialise successfully at test context startup, regardless of the order in which
 * test classes run or what state a previous test class left in the shared container.
 *
 * <p>Usage:
 * <pre>{@code
 * class TokenisationIntegrationTest extends AbstractIntegrationTest {
 *
 *     @Autowired
 *     private TestRestTemplate restTemplate;
 *
 *     @Test
 *     void tokenise_validRequest_returns201() { ... }
 * }
 * }</pre>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@Import(AbstractIntegrationTest.TestDataSeederConfig.class)
public abstract class AbstractIntegrationTest {

    /**
     * Fixed UUID for the seed ACTIVE key version inserted by {@link TestDataSeederConfig}.
     *
     * <p>Tests that need to reference the seed key version (e.g. to restore it after
     * cleanup or to verify a vault record's key version) should use this constant.
     */
    public static final String SEED_KEY_VERSION_ID = "00000000-0000-0000-0000-000000000001";

    /**
     * Shared PostgreSQL container, started once per JVM via static initialiser.
     *
     * <p>This container is intentionally NOT annotated with {@code @Container}.
     * The JUnit 5 Testcontainers extension stops containers after each test class;
     * since Spring's test context cache retains the mapped port for the JVM lifetime,
     * a port change after a container restart causes connection failures in cached contexts.
     * Starting the container in a static block keeps it alive for the full suite.
     * Individual tests that need a clean state must truncate the relevant tables themselves.
     */
    static final PostgreSQLContainer<?> POSTGRES;

    static {
        POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine")
                .withDatabaseName("tokenisation_test")
                .withUsername("test")
                .withPassword("test")
                // Raise server-side connection limit so the load-test HikariCP pool
                // (maximum-pool-size=100) fits with headroom. Default alpine image is 100.
                .withCommand("postgres", "-c", "max_connections=300");
        POSTGRES.start();
    }

    /**
     * Overrides Spring datasource properties with the Testcontainers-assigned
     * host, port, and JDBC URL so that Flyway and JPA connect to the real container.
     *
     * <p>Also pins {@code kms.provider} to {@code local-dev} so that
     * {@code LocalDevKmsAdapter} is activated regardless of any environment variable.
     *
     * @param registry the dynamic property registry provided by the Spring test framework
     */
    @DynamicPropertySource
    static void overrideProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("kms.provider", () -> "local-dev");
    }

    /**
     * Test configuration that provides a database seeder bean.
     *
     * <p>The seeder runs at application startup (with highest precedence, before
     * {@code KeyRingInitialiser}) and ensures the seed ACTIVE key version is present
     * in {@code key_versions}. Uses {@code ON CONFLICT DO NOTHING} so it is safe to
     * call multiple times without causing duplicate-key errors.
     */
    @TestConfiguration
    static class TestDataSeederConfig {

        /**
         * Inserts the seed ACTIVE key version ({@link #SEED_KEY_VERSION_ID}) into
         * {@code key_versions} before {@code KeyRingInitialiser.run()} executes.
         *
         * <p>Runs with {@code @Order(Ordered.HIGHEST_PRECEDENCE)} to guarantee it
         * precedes the standard {@code KeyRingInitialiser} {@code ApplicationRunner}.
         *
         * @param jdbcTemplate used to execute the seed insertion; must not be null
         * @return the seeder {@link ApplicationRunner}
         */
        @Bean
        @Order(Ordered.HIGHEST_PRECEDENCE)
        public ApplicationRunner testKeyVersionSeeder(JdbcTemplate jdbcTemplate) {
            return args -> {
                Timestamp rotateBy = Timestamp.from(Instant.now().plusSeconds(365L * 24 * 60 * 60));
                jdbcTemplate.update("""
                        INSERT INTO key_versions (id, kms_key_id, kms_provider, key_alias,
                            encrypted_kek_blob, status, activated_at, rotate_by, created_by, checksum)
                        VALUES (?::uuid, ?, ?, ?, ?, ?, now(), ?, ?, ?)
                        ON CONFLICT (id) DO NOTHING
                        """,
                        SEED_KEY_VERSION_ID,
                        "local-dev-key",
                        "LOCAL_DEV",
                        "integration-test-seed-key",
                        "ignored",
                        "ACTIVE",
                        rotateBy,
                        "test-seeder",
                        "seed-checksum"
                );
            };
        }
    }
}
