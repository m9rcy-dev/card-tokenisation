package com.yourorg.tokenisation.kms;

import com.yourorg.tokenisation.domain.KeyStatus;
import com.yourorg.tokenisation.domain.KeyType;
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
import java.util.Arrays;

/**
 * Seeds an initial ACTIVE DEK version into {@code key_versions} when running with the
 * {@code local-dev} KMS provider and the table has no active DEK.
 *
 * <p><strong>This class must never be used in production.</strong>
 */
@Component
@ConditionalOnProperty(name = "kms.provider", havingValue = "local-dev")
@Order(1)
@Slf4j
public class LocalDevKeySeeder implements ApplicationRunner {

    private static final String SEED_KEY_ALIAS    = "local-dev-seed-key";
    private static final String SEED_KMS_KEY_ID   = "local-dev-key";
    private static final String SEED_KMS_PROVIDER = "LOCAL_DEV";
    private static final int    ROTATE_BY_DAYS    = 365;

    private final KeyVersionRepository keyVersionRepository;
    private final KmsProvider kmsProvider;

    public LocalDevKeySeeder(KeyVersionRepository keyVersionRepository, KmsProvider kmsProvider) {
        this.keyVersionRepository = keyVersionRepository;
        this.kmsProvider = kmsProvider;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (keyVersionRepository.findActiveDek().isPresent()) {
            log.debug("LocalDevKeySeeder: ACTIVE DEK already exists — skipping seed");
            return;
        }

        log.warn("LocalDevKeySeeder: no ACTIVE DEK found — seeding initial local-dev key. "
                + "This must never happen in production.");

        DataKey dataKey = kmsProvider.generateDataKey();
        byte[] encryptedDekBlob = dataKey.encryptedDekBlob().clone();
        Arrays.fill(dataKey.plaintextDek(), (byte) 0);

        Instant now = Instant.now();
        KeyVersion seed = KeyVersion.builder()
                .keyType(KeyType.DEK)
                .kmsKeyId(SEED_KMS_KEY_ID)
                .kmsProvider(SEED_KMS_PROVIDER)
                .keyAlias(SEED_KEY_ALIAS)
                .encryptedDekBlob(encryptedDekBlob)
                .status(KeyStatus.ACTIVE)
                .activatedAt(now)
                .rotateBy(now.plus(ROTATE_BY_DAYS, ChronoUnit.DAYS))
                .createdBy("local-dev-seeder")
                .build();

        keyVersionRepository.saveAndFlush(seed);

        log.info("LocalDevKeySeeder: seeded ACTIVE DEK [{}] (alias: {})",
                seed.getId(), SEED_KEY_ALIAS);
    }
}
