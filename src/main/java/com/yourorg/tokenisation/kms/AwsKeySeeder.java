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

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;

/**
 * Seeds an initial ACTIVE KEK and HMAC key version on first boot when
 * {@code kms.aws.seed-on-startup=true} is set.
 *
 * <p>Activated for any environment that uses {@code kms.provider=aws} but starts
 * against a fresh (empty) database — LocalStack, real AWS KMS for local dev, or
 * an ephemeral test environment. Production deployments should pre-populate
 * {@code key_versions} via a controlled provisioning step and must NOT set this property.
 *
 * <p>Both seeds are idempotent — existing ACTIVE rows are left untouched, so
 * restarting the application against the same database is safe.
 *
 * <p>Runs at {@code @Order(1)} so that {@code KeyRingInitialiser} ({@code @Order(10)})
 * always finds at least one ACTIVE KEK row and one ACTIVE HMAC row on startup.
 */
@Component
@ConditionalOnProperty(name = "kms.aws.seed-on-startup", havingValue = "true")
@Order(1)
@Slf4j
public class AwsKeySeeder implements ApplicationRunner {

    private static final String KEK_ALIAS      = "aws-kek-seed";
    private static final String HMAC_ALIAS     = "aws-hmac-seed";
    private static final int    ROTATE_BY_DAYS = 365;

    private final KeyVersionRepository keyVersionRepository;
    private final KmsProvider          kmsProvider;

    public AwsKeySeeder(KeyVersionRepository keyVersionRepository,
                        KmsProvider kmsProvider) {
        this.keyVersionRepository = keyVersionRepository;
        this.kmsProvider          = kmsProvider;
    }

    @Override
    public void run(ApplicationArguments args) {
        seedKek();
        seedHmac();
    }

    private void seedKek() {
        if (keyVersionRepository.findActiveKek().isPresent()) {
            log.debug("AwsKeySeeder: ACTIVE KEK already present — skipping");
            return;
        }
        log.info("AwsKeySeeder: seeding initial KEK via AWS KMS");

        byte[] kekBytes = new byte[32];
        new SecureRandom().nextBytes(kekBytes);
        String b64Blob;
        try {
            b64Blob = kmsProvider.wrapNewKek(kekBytes);
        } finally {
            Arrays.fill(kekBytes, (byte) 0);
        }

        Instant now = Instant.now();
        KeyVersion kek = KeyVersion.builder()
                .keyType(KeyType.KEK)
                .kmsKeyId("aws-kms")
                .kmsProvider("AWS_KMS")
                .keyAlias(KEK_ALIAS)
                .encryptedKekBlob(b64Blob)
                .status(KeyStatus.ACTIVE)
                .activatedAt(now)
                .rotateBy(now.plus(ROTATE_BY_DAYS, ChronoUnit.DAYS))
                .createdBy("aws-key-seeder")
                .build();
        keyVersionRepository.saveAndFlush(kek);

        log.info("AwsKeySeeder: seeded ACTIVE KEK [{}]", kek.getId());
    }

    private void seedHmac() {
        if (keyVersionRepository.findActiveHmac().isPresent()) {
            log.debug("AwsKeySeeder: ACTIVE HMAC already present — skipping");
            return;
        }
        log.info("AwsKeySeeder: seeding initial HMAC key via KMS direct protection");

        byte[] hmacBytes = new byte[32];
        new SecureRandom().nextBytes(hmacBytes);
        byte[] encryptedSecret;
        try {
            encryptedSecret = kmsProvider.wrapNewHmacKey(hmacBytes);
        } finally {
            Arrays.fill(hmacBytes, (byte) 0);
        }

        Instant rotateBy = Instant.now().plus(ROTATE_BY_DAYS, ChronoUnit.DAYS);
        KeyVersion hmac = KeyVersion.forHmac(encryptedSecret, "aws-kms", "AWS_KMS", HMAC_ALIAS, rotateBy, "aws-key-seeder");
        keyVersionRepository.saveAndFlush(hmac);

        log.info("AwsKeySeeder: seeded ACTIVE HMAC [{}] (KMS-protected)", hmac.getId());
    }
}
