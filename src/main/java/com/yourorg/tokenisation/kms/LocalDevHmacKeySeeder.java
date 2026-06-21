package com.yourorg.tokenisation.kms;

import com.yourorg.tokenisation.domain.KeyVersion;
import com.yourorg.tokenisation.repository.KeyVersionRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.UUID;

/**
 * Seeds an initial ACTIVE HMAC key version into {@code key_versions} when running with the
 * {@code local-dev} KMS provider and no ACTIVE HMAC row exists.
 *
 * <p>Uses a fixed 32-byte HMAC secret encoded as UTF-8. The secret is encrypted via
 * {@link KmsProvider#wrapNewHmacKey} (local AES-GCM in the local-dev adapter) and stored
 * in the HMAC row directly — without a KEK intermediary.
 *
 * <p>The HMAC row is inserted with a well-known fixed UUID ({@link #SEED_HMAC_VERSION_ID})
 * so integration tests can reference it in SQL assertions without additional queries.
 *
 * <p><strong>This class must never be used in production.</strong>
 */
@Component
@ConditionalOnProperty(name = "kms.provider", havingValue = "local-dev")
@Order(2)
@Slf4j
public class LocalDevHmacKeySeeder implements ApplicationRunner {

    /**
     * Fixed UUID for the seeded HMAC key version.
     * Integration tests that reference the HMAC seed row should use this constant.
     */
    public static final String SEED_HMAC_VERSION_ID = "00000000-0000-0000-0000-000000000002";

    private static final String SEED_HMAC_SECRET = "local-dev-pan-hash-secret-32byte";
    private static final int ROTATE_BY_DAYS = 365;

    private final KeyVersionRepository keyVersionRepository;
    private final KmsProvider kmsProvider;

    public LocalDevHmacKeySeeder(KeyVersionRepository keyVersionRepository,
                                  KmsProvider kmsProvider) {
        this.keyVersionRepository = keyVersionRepository;
        this.kmsProvider = kmsProvider;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (keyVersionRepository.findActiveHmac().isPresent()) {
            log.debug("LocalDevHmacKeySeeder: ACTIVE HMAC key already exists — skipping seed");
            return;
        }

        log.warn("LocalDevHmacKeySeeder: no ACTIVE HMAC key found — seeding initial local-dev HMAC key. "
                + "This must never happen in production.");

        byte[] secretBytes = SEED_HMAC_SECRET.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedSecret;
        try {
            encryptedSecret = kmsProvider.wrapNewHmacKey(secretBytes);
        } finally {
            Arrays.fill(secretBytes, (byte) 0);
        }

        Instant now = Instant.now();
        KeyVersion hmacVersion = KeyVersion.forHmac(
                encryptedSecret,
                "local-dev-key",
                "LOCAL_DEV",
                "local-dev-hmac-seed",
                now.plus(ROTATE_BY_DAYS, ChronoUnit.DAYS),
                "local-dev-hmac-seeder");

        forceId(hmacVersion, UUID.fromString(SEED_HMAC_VERSION_ID));
        keyVersionRepository.saveAndFlush(hmacVersion);

        log.info("LocalDevHmacKeySeeder: seeded ACTIVE HMAC key version [{}]", SEED_HMAC_VERSION_ID);
    }

    private static void forceId(KeyVersion kv, UUID id) {
        try {
            Field idField = KeyVersion.class.getDeclaredField("id");
            idField.setAccessible(true);
            idField.set(kv, id);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Failed to set fixed UUID on HMAC seed row", e);
        }
    }
}
