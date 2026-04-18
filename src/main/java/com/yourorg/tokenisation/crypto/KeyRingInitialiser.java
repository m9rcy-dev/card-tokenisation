package com.yourorg.tokenisation.crypto;

import com.yourorg.tokenisation.domain.KeyStatus;
import com.yourorg.tokenisation.domain.KeyVersion;
import com.yourorg.tokenisation.kms.KmsProvider;
import com.yourorg.tokenisation.repository.KeyVersionRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;

/**
 * Loads all active and rotating KEK versions from KMS into the {@link InMemoryKeyRing}
 * once at application startup.
 *
 * <p>By loading keys at startup (rather than per-request), we minimise runtime KMS
 * dependency: a KMS outage after startup does not affect tokenisation or detokenisation
 * of existing records. Only a restart would be blocked if KMS is unreachable.
 *
 * <p>Startup sequence:
 * <ol>
 *   <li>Query {@code key_versions} for all {@code ACTIVE} and {@code ROTATING} versions
 *       (ordered by {@code activatedAt} ascending).
 *   <li>For each version, call {@code KmsProvider.unwrapKek()} to obtain the raw KEK bytes.
 *   <li>Load each KEK into the {@link InMemoryKeyRing}.
 *   <li>Promote the single {@code ACTIVE} version as the current key.
 *   <li>Zero the local KEK byte array immediately after loading.
 * </ol>
 *
 * <p>If no {@code ACTIVE} key version exists, startup fails fast — the application
 * cannot serve requests without a current encryption key.
 */
@Component
@Slf4j
public class KeyRingInitialiser implements ApplicationRunner {

    private final KmsProvider kmsProvider;
    private final KeyVersionRepository keyVersionRepository;
    private final InMemoryKeyRing keyRing;

    /**
     * Constructs the initialiser with its required collaborators.
     *
     * @param kmsProvider          the KMS adapter used to unwrap KEK blobs; must not be null
     * @param keyVersionRepository the repository for reading key version records; must not be null
     * @param keyRing              the in-memory key ring to populate; must not be null
     */
    public KeyRingInitialiser(KmsProvider kmsProvider,
                              KeyVersionRepository keyVersionRepository,
                              InMemoryKeyRing keyRing) {
        this.kmsProvider = kmsProvider;
        this.keyVersionRepository = keyVersionRepository;
        this.keyRing = keyRing;
    }

    /**
     * Initialises the key ring from the database and KMS.
     *
     * <p>Called automatically by Spring Boot after the application context is fully started
     * but before it begins accepting traffic (because this implements {@link ApplicationRunner}).
     *
     * @param args Spring Boot application arguments — not used
     * @throws IllegalStateException if no {@code ACTIVE} key version is found in the database
     */
    @Override
    public void run(ApplicationArguments args) {
        log.info("Initialising key ring — loading ACTIVE and ROTATING key versions from KMS");

        List<KeyVersion> versionsToLoad = keyVersionRepository
                .findByStatusIn(List.of(KeyStatus.ACTIVE, KeyStatus.ROTATING));

        for (KeyVersion keyVersion : versionsToLoad) {
            loadKeyVersion(keyVersion);
        }

        KeyVersion activeVersion = keyVersionRepository.findActiveOrThrow();
        keyRing.promoteActive(activeVersion.getId().toString());

        log.info("Key ring initialised successfully. Active key version: {}", activeVersion.getId());
    }

    /**
     * Loads a single key version into the ring by unwrapping its KEK blob from KMS.
     *
     * <p>The KEK bytes are zeroed from local scope immediately after being passed to
     * the key ring (which takes its own defensive copy).
     *
     * @param keyVersion the key version entity to load; must not be null
     */
    private void loadKeyVersion(KeyVersion keyVersion) {
        byte[] kek = kmsProvider.unwrapKek(keyVersion.getEncryptedKekBlob());
        try {
            keyRing.load(
                    keyVersion.getId().toString(),
                    kek,
                    keyVersion.getRotateBy()
            );
            log.info("Loaded key version {} (status: {}) into ring", keyVersion.getId(), keyVersion.getStatus());
        } finally {
            // Zero KEK bytes from this stack frame — the ring holds its own copy
            Arrays.fill(kek, (byte) 0);
        }
    }
}
