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
 * Loads all active and rotating KEK versions from KMS into the {@link InMemoryKekKeyRing},
 * then decrypts and loads all active and rotating HMAC versions into the {@link InMemoryHmacKeyRing}.
 *
 * <p>Runs at {@code @Order(10)} — after seeders ({@code @Order(1)}) which ensure HMAC rows exist
 * before Phase 2 of this initialiser runs.
 *
 * <p>Startup sequence:
 * <ol>
 *   <li><b>Phase 1 — KEK ring</b>: query {@code key_versions WHERE key_type='KEK'} for ACTIVE/ROTATING,
 *       unwrap each KEK blob via KMS, load into {@link InMemoryKekKeyRing}, promote the ACTIVE version.
 *   <li><b>Phase 2 — HMAC ring</b>: query {@code key_versions WHERE key_type='HMAC'} for ACTIVE/ROTATING,
 *       decrypt each HMAC secret using the loaded KEK (from the now-populated ring), load into
 *       {@link InMemoryHmacKeyRing}, promote the ACTIVE version.
 * </ol>
 *
 * <p>If no ACTIVE KEK or no ACTIVE HMAC key is found, startup fails fast.
 */
@Component
@Order(10)
@Slf4j
public class KeyRingInitialiser implements ApplicationRunner {

    private final KmsProvider kmsProvider;
    private final KeyVersionRepository keyVersionRepository;
    private final InMemoryKekKeyRing keyRing;
    private final InMemoryHmacKeyRing hmacKeyRing;

    public KeyRingInitialiser(KmsProvider kmsProvider,
                              KeyVersionRepository keyVersionRepository,
                              InMemoryKekKeyRing keyRing,
                              InMemoryHmacKeyRing hmacKeyRing) {
        this.kmsProvider = kmsProvider;
        this.keyVersionRepository = keyVersionRepository;
        this.keyRing = keyRing;
        this.hmacKeyRing = hmacKeyRing;
    }

    @Override
    public void run(ApplicationArguments args) {
        loadKekRing();
        loadHmacRing();
    }

    // ── Phase 1: KEK ring ─────────────────────────────────────────────────────

    private void loadKekRing() {
        log.info("KeyRingInitialiser phase 1 — loading KEK versions");
        List<KeyVersion> kekVersions = keyVersionRepository
                .findKekByStatusIn(List.of(KeyStatus.ACTIVE, KeyStatus.ROTATING));

        for (KeyVersion kv : kekVersions) {
            loadKekVersion(kv);
        }

        KeyVersion activeKek = keyVersionRepository.findActiveKekOrThrow();
        keyRing.promoteActive(activeKek.getId().toString());
        log.info("KEK ring initialised. Active version: {}", activeKek.getId());
    }

    private void loadKekVersion(KeyVersion kv) {
        byte[] kek = kmsProvider.unwrapKek(kv.getEncryptedKekBlob());
        try {
            keyRing.load(kv.getId().toString(), kek, kv.getRotateBy());
            log.info("Loaded KEK version {} (status: {}) into ring", kv.getId(), kv.getStatus());
        } finally {
            Arrays.fill(kek, (byte) 0);
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
