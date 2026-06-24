package com.yourorg.tokenisation.crypto;

import com.yourorg.tokenisation.domain.KeyStatus;
import com.yourorg.tokenisation.domain.KeyVersion;
import com.yourorg.tokenisation.kms.KmsProvider;
import com.yourorg.tokenisation.repository.KeyVersionRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;

/**
 * Loads all active and rotating DEK versions from KMS into the {@link InMemoryDekKeyRing},
 * then decrypts and loads all active and rotating HMAC versions into the {@link InMemoryHmacKeyRing}.
 *
 * <p>Runs at {@code @Order(10)} — after seeders ({@code @Order(1)}) which ensure DEK rows exist
 * before Phase 1 of this initialiser runs.
 *
 * <p>Startup sequence:
 * <ol>
 *   <li><b>Phase 1 — DEK ring</b>: query {@code key_versions WHERE key_type='DEK'} for ACTIVE/ROTATING,
 *       call {@code decryptDataKey(encryptedDekBlob)} per version, load into {@link InMemoryDekKeyRing},
 *       promote the ACTIVE version.
 *   <li><b>Phase 2 — HMAC ring</b>: query {@code key_versions WHERE key_type='HMAC'} for ACTIVE/ROTATING,
 *       decrypt each HMAC secret, load into {@link InMemoryHmacKeyRing}, promote the ACTIVE version.
 * </ol>
 *
 * <p>If no ACTIVE DEK or no ACTIVE HMAC key is found, startup fails fast.
 */
@Component
@Order(10)
@Slf4j
public class KeyRingInitialiser implements ApplicationRunner {

    private final KmsProvider kmsProvider;
    private final KeyVersionRepository keyVersionRepository;
    private final InMemoryDekKeyRing dekRing;
    private final InMemoryHmacKeyRing hmacKeyRing;

    public KeyRingInitialiser(KmsProvider kmsProvider,
                              KeyVersionRepository keyVersionRepository,
                              InMemoryDekKeyRing dekRing,
                              InMemoryHmacKeyRing hmacKeyRing) {
        this.kmsProvider = kmsProvider;
        this.keyVersionRepository = keyVersionRepository;
        this.dekRing = dekRing;
        this.hmacKeyRing = hmacKeyRing;
    }

    @Override
    public void run(ApplicationArguments args) {
        loadDekRing();
        loadHmacRing();
    }

    // ── Phase 1: DEK ring ─────────────────────────────────────────────────────

    private void loadDekRing() {
        log.info("KeyRingInitialiser phase 1 — loading DEK versions");
        List<KeyVersion> dekVersions = keyVersionRepository
                .findDekByStatusIn(List.of(KeyStatus.ACTIVE, KeyStatus.ROTATING));

        for (KeyVersion kv : dekVersions) {
            loadDekVersion(kv);
        }

        KeyVersion activeDek = keyVersionRepository.findActiveDekOrThrow();
        dekRing.promoteActive(activeDek.getId().toString());
        log.info("DEK ring initialised. Active version: {}", activeDek.getId());
    }

    private void loadDekVersion(KeyVersion kv) {
        byte[] dek = kmsProvider.decryptDataKey(kv.getEncryptedDekBlob());
        try {
            dekRing.load(kv.getId().toString(), dek, kv.getRotateBy());
            log.info("Loaded DEK version {} (status: {}) into ring", kv.getId(), kv.getStatus());
        } finally {
            Arrays.fill(dek, (byte) 0);
        }
    }

    // ── Phase 2: HMAC ring ────────────────────────────────────────────────────

    private void loadHmacRing() {
        log.info("KeyRingInitialiser phase 2 — loading HMAC versions");
        List<KeyVersion> hmacVersions = keyVersionRepository
                .findHmacByStatusIn(List.of(KeyStatus.ACTIVE, KeyStatus.ROTATING));

        if (hmacVersions.isEmpty()) {
            log.warn("KeyRingInitialiser: no ACTIVE or ROTATING HMAC key found in key_versions. "
                    + "Tokenisation will fail until an HMAC key is seeded.");
            return;
        }

        for (KeyVersion hv : hmacVersions) {
            loadHmacVersion(hv);
        }

        keyVersionRepository.findActiveHmac().ifPresent(activeHmac -> {
            hmacKeyRing.promoteActive(activeHmac.getId().toString());
            log.info("HMAC ring initialised. Active version: {}", activeHmac.getId());
        });
    }

    private void loadHmacVersion(KeyVersion hv) {
        byte[] secret = null;
        try {
            secret = kmsProvider.unwrapHmacKey(hv.getEncryptedSecret());
            hmacKeyRing.load(hv.getId().toString(), secret, hv.getRotateBy());
            log.info("Loaded HMAC version {} (status: {}) into ring", hv.getId(), hv.getStatus());
        } finally {
            if (secret != null) {
                Arrays.fill(secret, (byte) 0);
            }
        }
    }
}
