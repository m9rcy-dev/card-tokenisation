package com.yourorg.tokenisation.kms;

import com.yourorg.tokenisation.crypto.TamperDetector;
import com.yourorg.tokenisation.domain.KeyStatus;
import com.yourorg.tokenisation.domain.KeyVersion;
import com.yourorg.tokenisation.repository.KeyVersionRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Seeds an initial {@code ACTIVE} key version into {@code key_versions} when running
 * with the {@code local-dev} KMS provider and the table is empty.
 *
 * <p>This bean is only active when {@code kms.provider=local-dev}. It runs before
 * {@link com.yourorg.tokenisation.crypto.KeyRingInitialiser} via {@link Order}{@code (1)}
 * (the initialiser has no explicit order, so it runs at
 * {@link org.springframework.core.Ordered#LOWEST_PRECEDENCE}).
 *
 * <p><strong>This class must never be used in production.</strong> Production key versions
 * are created through the key rotation API and backed by real KMS credentials.
 */
@Component
@ConditionalOnProperty(name = "kms.provider", havingValue = "local-dev")
@Order(1)
@Slf4j
public class LocalDevKeySeeder implements ApplicationRunner {

    private static final String SEED_KEY_ALIAS    = "local-dev-seed-key";
    private static final String SEED_KMS_KEY_ID   = "local-dev-key";
    private static final String SEED_KMS_PROVIDER = "LOCAL_DEV";
    /** Placeholder blob — LocalDevKmsAdapter.unwrapKek() ignores its contents. */
    private static final String SEED_KEK_BLOB     = "local-dev-no-kms-blob";
    private static final int    ROTATE_BY_DAYS    = 365;

    private final KeyVersionRepository keyVersionRepository;
    private final TamperDetector tamperDetector;

    /**
     * Constructs the seeder with the repository and tamper-detector needed to persist
     * a valid key version row.
     *
     * @param keyVersionRepository used to check for an existing active key and to save the seed row
     * @param tamperDetector       used to compute the HMAC-SHA256 checksum after the UUID is assigned
     */
    public LocalDevKeySeeder(KeyVersionRepository keyVersionRepository,
                             TamperDetector tamperDetector) {
        this.keyVersionRepository = keyVersionRepository;
        this.tamperDetector = tamperDetector;
    }

    /**
     * Inserts a seed key version if no {@code ACTIVE} key exists yet.
     *
     * <p>Uses the two-step checksum pattern: save with {@code "pending"} to get the
     * JPA-generated UUID, then compute the real HMAC and save again.
     *
     * @param args not used
     */
    @Override
    public void run(ApplicationArguments args) {
        if (keyVersionRepository.findActive().isPresent()) {
            log.debug("LocalDevKeySeeder: ACTIVE key version already exists — skipping seed");
            return;
        }

        log.warn("LocalDevKeySeeder: no ACTIVE key found — seeding initial local-dev key. "
                + "This must never happen in production.");

        Instant now = Instant.now();
        KeyVersion seed = KeyVersion.builder()
                .kmsKeyId(SEED_KMS_KEY_ID)
                .kmsProvider(SEED_KMS_PROVIDER)
                .keyAlias(SEED_KEY_ALIAS)
                .encryptedKekBlob(SEED_KEK_BLOB)
                .status(KeyStatus.ACTIVE)
                .activatedAt(now)
                .rotateBy(now.plus(ROTATE_BY_DAYS, ChronoUnit.DAYS))
                .createdBy("local-dev-seeder")
                .checksum("pending")
                .build();

        // Step 1 — persist to obtain the JPA-generated UUID
        keyVersionRepository.saveAndFlush(seed);

        // Step 2 — compute real HMAC now that id is assigned, then persist again
        seed.initializeChecksum(tamperDetector.computeChecksum(seed));
        keyVersionRepository.saveAndFlush(seed);

        log.info("LocalDevKeySeeder: seeded ACTIVE key version [{}] (alias: {})",
                seed.getId(), SEED_KEY_ALIAS);
    }
}
