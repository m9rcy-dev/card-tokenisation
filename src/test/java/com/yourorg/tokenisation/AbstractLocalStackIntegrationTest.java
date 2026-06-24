package com.yourorg.tokenisation;

import com.yourorg.tokenisation.kms.DataKey;
import com.yourorg.tokenisation.kms.KmsProvider;
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
import org.testcontainers.containers.localstack.LocalStackContainer;
import org.testcontainers.utility.DockerImageName;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.CreateKeyRequest;
import software.amazon.awssdk.services.kms.model.KeyUsageType;

import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Arrays;

/**
 * Base class for integration tests that require a real AWS KMS API via LocalStack.
 *
 * <p>Provides two static containers started once per JVM:
 * <ul>
 *   <li>A {@code PostgreSQLContainer} for the application database.
 *   <li>A {@code LocalStackContainer} running only the KMS service.
 * </ul>
 *
 * <p>A single KMS master key is created in LocalStack during static initialisation and
 * its ARN is registered as {@code kms.aws.master-key-arn} via {@link DynamicPropertySource}.
 * The {@link LocalStackSeedConfig} then seeds an ACTIVE DEK row (encrypted by the LocalStack
 * KMS key via {@code GenerateDataKey}) and an ACTIVE HMAC row (encrypted by the LocalStack
 * KMS key via {@code Encrypt}) before {@code KeyRingInitialiser} runs — matching the seeding
 * pattern in {@link AbstractIntegrationTest}.
 *
 * <p>AWS SDK system-property credentials ({@code aws.accessKeyId=test},
 * {@code aws.secretAccessKey=test}) are set in the static block so the production
 * {@code KmsConfig.kmsClient()} bean picks up LocalStack credentials without modification.
 *
 * <p>Subclasses should be annotated with {@code @Tag("localstack")} so they are excluded
 * from the standard {@code mvn test} run and can be run explicitly with
 * {@code mvn test -P localstack-tests} or {@code make localstack-test}.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@Import(AbstractLocalStackIntegrationTest.LocalStackSeedConfig.class)
public abstract class AbstractLocalStackIntegrationTest {

    /** Key alias used to discover the seed DEK row in assertions and @BeforeEach resets. */
    protected static final String SEED_DEK_ALIAS  = "ls-dek-seed";

    /** Key alias used to discover the seed HMAC row in assertions and @BeforeEach resets. */
    protected static final String SEED_HMAC_ALIAS = "ls-hmac-seed";

    static final PostgreSQLContainer<?> POSTGRES;
    static final LocalStackContainer    LOCALSTACK;
    static final String                 KMS_KEY_ARN;

    static {
        // AWS SDK v2 SystemPropertyCredentialsProvider reads these two properties
        // so the production KmsConfig.kmsClient() works against LocalStack without modification.
        System.setProperty("aws.accessKeyId",     "test");
        System.setProperty("aws.secretAccessKey", "test");

        POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine")
                .withDatabaseName("tokenisation_ls")
                .withUsername("ls_test")
                .withPassword("ls_test")
                .withCommand("postgres", "-c", "max_connections=300");
        POSTGRES.start();

        LOCALSTACK = new LocalStackContainer(
                DockerImageName.parse("localstack/localstack:3.8.1"))
                .withServices(LocalStackContainer.Service.KMS);
        LOCALSTACK.start();

        // Create the single master key; HMAC secrets and DEKs are both protected by this key
        try (KmsClient setup = KmsClient.builder()
                .region(Region.US_EAST_1)
                .endpointOverride(LOCALSTACK.getEndpointOverride(LocalStackContainer.Service.KMS))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create("test", "test")))
                .build()) {
            KMS_KEY_ARN = setup.createKey(CreateKeyRequest.builder()
                    .description("card-tokenisation-localstack-test")
                    .keyUsage(KeyUsageType.ENCRYPT_DECRYPT)
                    .build())
                    .keyMetadata().arn();
        }
    }

    @DynamicPropertySource
    static void configureLocalStack(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url",      POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("kms.provider",               () -> "aws");
        registry.add("kms.aws.region",             () -> "us-east-1");
        registry.add("kms.aws.master-key-arn",     () -> KMS_KEY_ARN);
        registry.add("kms.aws.endpoint-override",
                () -> LOCALSTACK.getEndpointOverride(LocalStackContainer.Service.KMS).toString());
    }

    /**
     * Seeds an ACTIVE DEK row and an ACTIVE HMAC row before {@code KeyRingInitialiser} runs.
     *
     * <p>The DEK is generated atomically via LocalStack KMS {@code GenerateDataKey}
     * (matching {@link com.yourorg.tokenisation.kms.AwsKmsAdapter#generateDataKey}).
     * The HMAC secret is generated locally and encrypted via LocalStack KMS
     * {@code Encrypt} with {@code purpose=hmac-key} context
     * (matching {@link com.yourorg.tokenisation.kms.AwsKmsAdapter#wrapNewHmacKey}).
     *
     * <p>Both insertions are idempotent — the runner checks for existing rows by alias
     * and skips if already present (safe for repeated context loads within the same JVM).
     */
    @TestConfiguration
    static class LocalStackSeedConfig {

        @Bean
        @Order(Ordered.HIGHEST_PRECEDENCE)
        public ApplicationRunner localStackSeeder(
                KmsProvider kmsProvider,
                JdbcTemplate jdbc) {
            return args -> {
                Boolean hasDek = jdbc.queryForObject(
                        "SELECT EXISTS(SELECT 1 FROM key_versions WHERE key_type='DEK' AND key_alias=?)",
                        Boolean.class, SEED_DEK_ALIAS);
                if (Boolean.TRUE.equals(hasDek)) return;

                // Generate DEK via LocalStack KMS GenerateDataKey — returns encrypted blob atomically
                DataKey dataKey = kmsProvider.generateDataKey();
                byte[] encryptedDekBlob = dataKey.encryptedDekBlob().clone();
                Arrays.fill(dataKey.plaintextDek(), (byte) 0);

                // Wrap HMAC secret directly via LocalStack KMS (purpose=hmac-key)
                SecureRandom rng = new SecureRandom();
                byte[] hmacBytes = new byte[32];
                rng.nextBytes(hmacBytes);
                byte[] encryptedSecret;
                try {
                    encryptedSecret = kmsProvider.wrapNewHmacKey(hmacBytes);
                } finally {
                    Arrays.fill(hmacBytes, (byte) 0);
                }

                Timestamp rotateBy = Timestamp.from(Instant.now().plusSeconds(365L * 24 * 3600));
                jdbc.update("""
                        INSERT INTO key_versions (kms_key_id, kms_provider, key_alias,
                            encrypted_dek_blob, key_type, status, activated_at, rotate_by, created_by)
                        VALUES (?, 'AWS_KMS', ?, ?, 'DEK', 'ACTIVE', now(), ?, ?)
                        """,
                        KMS_KEY_ARN, SEED_DEK_ALIAS, encryptedDekBlob, rotateBy, "localstack-seeder");

                jdbc.update("""
                        INSERT INTO key_versions (kms_key_id, kms_provider, key_alias,
                            encrypted_secret, key_type, status, activated_at, rotate_by, created_by)
                        VALUES (?, 'AWS_KMS', ?, ?, 'HMAC', 'ACTIVE', now(), ?, ?)
                        """,
                        KMS_KEY_ARN, SEED_HMAC_ALIAS, encryptedSecret, rotateBy, "localstack-seeder");
            };
        }
    }
}
