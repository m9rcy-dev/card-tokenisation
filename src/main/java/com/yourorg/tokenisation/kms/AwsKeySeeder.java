package com.yourorg.tokenisation.kms;

import com.yourorg.tokenisation.domain.KeyStatus;
import com.yourorg.tokenisation.domain.KeyType;
import com.yourorg.tokenisation.domain.KeyVersion;
import com.yourorg.tokenisation.repository.KeyVersionRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;

/**
 * Seeds an initial ACTIVE DEK and HMAC key version on first boot when both
 * {@code kms.provider=aws} and {@code kms.aws.seed-on-startup=true} are set.
 *
 * <p>Both seeds are idempotent — existing ACTIVE rows are left untouched.
 * Runs at {@code @Order(1)} so that {@code KeyRingInitialiser} ({@code @Order(10)})
 * always finds at least one ACTIVE DEK row and one ACTIVE HMAC row on startup.
 */
@Component
@ConditionalOnExpression("'${kms.provider:}' == 'aws' && '${kms.aws.seed-on-startup:false}' == 'true'")
@Order(1)
@Slf4j
public class AwsKeySeeder implements ApplicationRunner {

    private static final String DEK_ALIAS      = "aws-dek-seed";
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
        seedDek();
        seedHmac();
    }

    private void seedDek() {
        if (keyVersionRepository.findActiveDek().isPresent()) {
            log.debug("AwsKeySeeder: ACTIVE DEK already present — skipping");
            return;
        }
        log.info("AwsKeySeeder: seeding initial DEK via AWS KMS GenerateDataKey");

        DataKey dataKey = kmsProvider.generateDataKey();
        byte[] encryptedDekBlob = dataKey.encryptedDekBlob().clone();
        Arrays.fill(dataKey.plaintextDek(), (byte) 0);

        Instant now = Instant.now();
        KeyVersion dek = KeyVersion.builder()
                .keyType(KeyType.DEK)
                .kmsKeyId("aws-kms")
                .kmsProvider("AWS_KMS")
                .keyAlias(DEK_ALIAS)
                .encryptedDekBlob(encryptedDekBlob)
                .status(KeyStatus.ACTIVE)
                .activatedAt(now)
                .rotateBy(now.plus(ROTATE_BY_DAYS, ChronoUnit.DAYS))
                .createdBy("aws-key-seeder")
                .build();
        keyVersionRepository.saveAndFlush(dek);

        log.info("AwsKeySeeder: seeded ACTIVE DEK [{}]", dek.getId());
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
