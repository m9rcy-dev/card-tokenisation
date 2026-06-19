package com.yourorg.tokenisation.kms;

import com.yourorg.tokenisation.crypto.AesGcmCipher;
import com.yourorg.tokenisation.domain.KeyStatus;
import com.yourorg.tokenisation.domain.KeyType;
import com.yourorg.tokenisation.domain.KeyVersion;
import com.yourorg.tokenisation.repository.KeyVersionRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptRequest;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

/**
 * Seeds an initial ACTIVE KEK and HMAC key version when running with the {@code localstack}
 * Spring profile, so that {@code make run-localstack} works against a fresh database.
 *
 * <p>The KEK bytes are generated locally via {@link SecureRandom}, encrypted by the LocalStack
 * KMS master key, and stored as a Base64 blob in {@code key_versions}. The HMAC secret is
 * generated separately and encrypted at application level under the KEK using AES-256-GCM
 * (matching how {@link LocalDevHmacKeySeeder} works in local-dev mode).
 *
 * <p>Both seeds are idempotent — existing ACTIVE rows are left untouched so that restarting
 * the application against the same running LocalStack + PostgreSQL containers does not
 * create duplicate key versions.
 *
 * <p>Runs at {@code @Order(1)} so that {@code KeyRingInitialiser} ({@code @Order(10)}) always
 * finds at least one ACTIVE KEK row and one ACTIVE HMAC row on startup.
 *
 * <p><strong>For local development against LocalStack only. Never deploy to production.</strong>
 */
@Component
@Profile("localstack")
@Order(1)
@Slf4j
public class LocalStackKeySeeder implements ApplicationRunner {

    private static final String KEK_ALIAS      = "localstack-kek-seed";
    private static final String HMAC_ALIAS     = "localstack-hmac-seed";
    private static final int    ROTATE_BY_DAYS = 365;

    private final KeyVersionRepository keyVersionRepository;
    private final KmsClient            kmsClient;
    private final AesGcmCipher         cipher;
    private final String               masterKeyArn;

    public LocalStackKeySeeder(KeyVersionRepository keyVersionRepository,
                               KmsClient kmsClient,
                               AesGcmCipher cipher,
                               @Value("${kms.aws.master-key-arn}") String masterKeyArn) {
        this.keyVersionRepository = keyVersionRepository;
        this.kmsClient            = kmsClient;
        this.cipher               = cipher;
        this.masterKeyArn         = masterKeyArn;
    }

    @Override
    public void run(ApplicationArguments args) {
        seedKek();
        seedHmac();
    }

    private void seedKek() {
        if (keyVersionRepository.findActiveKek().isPresent()) {
            log.debug("LocalStackKeySeeder: ACTIVE KEK already present — skipping");
            return;
        }
        log.info("LocalStackKeySeeder: seeding initial KEK via LocalStack KMS");

        byte[] kekBytes = new byte[32];
        new SecureRandom().nextBytes(kekBytes);
        byte[] encryptedKekRaw = kmsClient.encrypt(EncryptRequest.builder()
                .keyId(masterKeyArn)
                .plaintext(SdkBytes.fromByteArray(kekBytes))
                .encryptionContext(Map.of("purpose", "kek-unwrap"))
                .build())
                .ciphertextBlob().asByteArray();
        Arrays.fill(kekBytes, (byte) 0);

        String b64Blob = Base64.getEncoder().encodeToString(encryptedKekRaw);
        Instant now = Instant.now();
        KeyVersion kek = KeyVersion.builder()
                .keyType(KeyType.KEK)
                .kmsKeyId(masterKeyArn)
                .kmsProvider("AWS_KMS")
                .keyAlias(KEK_ALIAS)
                .encryptedKekBlob(b64Blob)
                .status(KeyStatus.ACTIVE)
                .activatedAt(now)
                .rotateBy(now.plus(ROTATE_BY_DAYS, ChronoUnit.DAYS))
                .createdBy("localstack-seeder")
                .build();
        keyVersionRepository.saveAndFlush(kek);

        log.info("LocalStackKeySeeder: seeded ACTIVE KEK [{}]", kek.getId());
    }

    private void seedHmac() {
        if (keyVersionRepository.findActiveHmac().isPresent()) {
            log.debug("LocalStackKeySeeder: ACTIVE HMAC already present — skipping");
            return;
        }
        log.info("LocalStackKeySeeder: seeding initial HMAC key");

        KeyVersion activeKek = keyVersionRepository.findActiveKekOrThrow();
        byte[] encryptedKekBlob = Base64.getDecoder().decode(activeKek.getEncryptedKekBlob());

        // Unwrap KEK via LocalStack KMS to encrypt the HMAC secret at app level
        byte[] kekBytes = kmsClient.decrypt(DecryptRequest.builder()
                .ciphertextBlob(SdkBytes.fromByteArray(encryptedKekBlob))
                .keyId(masterKeyArn)
                .encryptionContext(Map.of("purpose", "kek-unwrap"))
                .build())
                .plaintext().asByteArray();

        byte[] hmacBytes = new byte[32];
        new SecureRandom().nextBytes(hmacBytes);
        byte[] encryptedSecret;
        try {
            encryptedSecret = cipher.encryptBytes(hmacBytes, kekBytes);
        } finally {
            Arrays.fill(kekBytes,  (byte) 0);
            Arrays.fill(hmacBytes, (byte) 0);
        }

        Instant rotateBy = Instant.now().plus(ROTATE_BY_DAYS, ChronoUnit.DAYS);
        KeyVersion hmac = KeyVersion.forHmac(
                encryptedSecret, activeKek.getId(), HMAC_ALIAS, rotateBy, "localstack-seeder");
        keyVersionRepository.saveAndFlush(hmac);

        log.info("LocalStackKeySeeder: seeded ACTIVE HMAC [{}]", hmac.getId());
    }
}
