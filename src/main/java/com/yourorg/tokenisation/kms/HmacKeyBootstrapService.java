package com.yourorg.tokenisation.kms;

import com.yourorg.tokenisation.crypto.AesGcmCipher;
import com.yourorg.tokenisation.domain.KeyVersion;
import com.yourorg.tokenisation.repository.KeyVersionRepository;
import com.yourorg.tokenisation.repository.TokenVaultRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;

/**
 * Migrates the legacy {@code PAN_HASH_SECRET} environment variable into a versioned
 * HMAC key row in {@code key_versions} on first boot.
 *
 * <p>This service runs at {@code @Order(5)} — after seeders ({@code @Order(1)}) that may
 * create the initial KEK row, but before {@code KeyRingInitialiser} ({@code @Order(10)})
 * which needs the HMAC row to be present before it can load the HMAC ring.
 *
 * <p>If an ACTIVE HMAC row already exists, this service is a no-op (idempotent).
 * On first boot it:
 * <ol>
 *   <li>Reads the HMAC secret from {@code tokenisation.pan-hash-secret}.</li>
 *   <li>Encrypts the secret bytes under the active KEK using {@link AesGcmCipher#encryptBytes}.</li>
 *   <li>Persists a new HMAC key version row with status {@code ACTIVE}.</li>
 *   <li>Backfills {@code token_vault.hmac_key_version_id} for all active rows that have
 *       no version yet (rows created before HMAC versioning was introduced).</li>
 * </ol>
 *
 * <p>The {@code pan-hash-secret} config property is nullable after first boot — once the
 * HMAC row is seeded it is never read again. Remove the env var after HMAC rotation completes
 * to enforce this.
 */
@Component
@Order(5)
@Slf4j
public class HmacKeyBootstrapService implements ApplicationRunner {

    private static final int ROTATE_BY_DAYS = 365;

    private final KeyVersionRepository keyVersionRepository;
    private final TokenVaultRepository tokenVaultRepository;
    private final KmsProvider kmsProvider;
    private final AesGcmCipher cipher;
    private final String panHashSecret;

    public HmacKeyBootstrapService(KeyVersionRepository keyVersionRepository,
                                    TokenVaultRepository tokenVaultRepository,
                                    KmsProvider kmsProvider,
                                    AesGcmCipher cipher,
                                    @Value("${tokenisation.pan-hash-secret:#{null}}") String panHashSecret) {
        this.keyVersionRepository = keyVersionRepository;
        this.tokenVaultRepository = tokenVaultRepository;
        this.kmsProvider = kmsProvider;
        this.cipher = cipher;
        this.panHashSecret = panHashSecret;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        if (keyVersionRepository.findActiveHmac().isPresent()) {
            log.debug("HmacKeyBootstrapService: ACTIVE HMAC key already exists — skipping bootstrap");
            return;
        }

        if (panHashSecret == null || panHashSecret.isBlank()) {
            log.warn("HmacKeyBootstrapService: no ACTIVE HMAC key exists and "
                    + "tokenisation.pan-hash-secret is not set — skipping bootstrap. "
                    + "Tokenisation will fail until an HMAC key is seeded.");
            return;
        }

        log.info("HmacKeyBootstrapService: bootstrapping HMAC key from legacy PAN_HASH_SECRET env var");

        KeyVersion activeKek = keyVersionRepository.findActiveKekOrThrow();
        byte[] kek = kmsProvider.unwrapKek(activeKek.getEncryptedKekBlob());
        byte[] secretBytes = panHashSecret.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedSecret;
        try {
            encryptedSecret = cipher.encryptBytes(secretBytes, kek);
        } finally {
            Arrays.fill(kek, (byte) 0);
            Arrays.fill(secretBytes, (byte) 0);
        }

        Instant now = Instant.now();
        KeyVersion hmacVersion = KeyVersion.forHmac(
                encryptedSecret,
                activeKek.getId(),
                "bootstrap-hmac-from-env",
                now.plus(ROTATE_BY_DAYS, ChronoUnit.DAYS),
                "hmac-bootstrap-service");

        keyVersionRepository.saveAndFlush(hmacVersion);

        // Backfill all active vault rows that have no HMAC version yet
        int backfilled = tokenVaultRepository.bulkSetHmacVersionId(hmacVersion.getId());
        log.info("HmacKeyBootstrapService: bootstrapped HMAC key version [{}], backfilled {} vault rows",
                hmacVersion.getId(), backfilled);
    }
}
