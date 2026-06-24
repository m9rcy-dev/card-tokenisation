package com.yourorg.tokenisation.rotation;

import com.yourorg.tokenisation.crypto.InMemoryDekKeyRing;
import com.yourorg.tokenisation.crypto.InMemoryHmacKeyRing;
import com.yourorg.tokenisation.crypto.KeyMaterial;
import com.yourorg.tokenisation.crypto.KeyVersionNotFoundException;
import com.yourorg.tokenisation.domain.KeyStatus;
import com.yourorg.tokenisation.domain.KeyVersion;
import com.yourorg.tokenisation.kms.KmsProvider;
import com.yourorg.tokenisation.repository.KeyVersionRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;

/**
 * Periodically syncs each pod's in-memory key rings against the database.
 *
 * <p>In a multi-pod deployment, key rotation initiated on one pod updates the database
 * but leaves the other pods' rings stale. This job detects and corrects drift:
 * <ol>
 *   <li><b>Missing version</b> — a DEK or HMAC version is ACTIVE/ROTATING in DB but not in
 *       this pod's ring. Fix: call {@code decryptDataKey} and load.
 *   <li><b>Stale active pointer</b> — DB's ACTIVE version differs from the ring's current
 *       active pointer. Fix: promote the DB version.
 *   <li><b>Unpropagated COMPROMISED status</b> — emergency rotation marked a key COMPROMISED
 *       in DB but this pod's ring still shows it as ACTIVE. Fix: call {@code markCompromised}.
 * </ol>
 *
 * <p>This job intentionally does NOT use ShedLock. Each pod must independently refresh its
 * own in-memory ring — a distributed lock would prevent non-initiating pods from refreshing.
 */
@Component
@Slf4j
public class KeyRingRefreshJob {

    private final KeyVersionRepository keyVersionRepository;
    private final KmsProvider kmsProvider;
    private final InMemoryDekKeyRing dekRing;
    private final InMemoryHmacKeyRing hmacKeyRing;

    public KeyRingRefreshJob(KeyVersionRepository keyVersionRepository,
                             KmsProvider kmsProvider,
                             InMemoryDekKeyRing dekRing,
                             InMemoryHmacKeyRing hmacKeyRing) {
        this.keyVersionRepository = keyVersionRepository;
        this.kmsProvider = kmsProvider;
        this.dekRing = dekRing;
        this.hmacKeyRing = hmacKeyRing;
    }

    @Scheduled(cron = "${rotation.ring-refresh.cron:0 * * * * *}")
    public void refreshRings() {
        refreshDekRing();
        refreshHmacRing();
    }

    // ── DEK ring sync ─────────────────────────────────────────────────────────

    private void refreshDekRing() {
        List<KeyVersion> activeOrRotating = keyVersionRepository.findDekByStatusIn(
                List.of(KeyStatus.ACTIVE, KeyStatus.ROTATING));

        for (KeyVersion kv : activeOrRotating) {
            String id = kv.getId().toString();
            if (!dekRing.contains(id)) {
                byte[] dek = kmsProvider.decryptDataKey(kv.getEncryptedDekBlob());
                try {
                    dekRing.load(id, dek, kv.getRotateBy());
                    log.info("Ring refresh: loaded DEK version [{}] (status={})", id, kv.getStatus());
                } finally {
                    Arrays.fill(dek, (byte) 0);
                }
            }
        }

        keyVersionRepository.findActiveDek().ifPresent(dbActive -> {
            String dbActiveId = dbActive.getId().toString();
            try {
                String ringActiveId = dekRing.getActive().keyVersionId();
                if (!dbActiveId.equals(ringActiveId)) {
                    dekRing.promoteActive(dbActiveId);
                    log.info("Ring refresh: DEK active pointer updated [{}] → [{}]",
                            ringActiveId, dbActiveId);
                }
            } catch (IllegalStateException e) {
                // Ring not yet initialised — KeyRingInitialiser handles this at startup
            }
        });

        List<KeyVersion> compromised = keyVersionRepository.findDekByStatusIn(
                List.of(KeyStatus.COMPROMISED));
        for (KeyVersion kv : compromised) {
            String id = kv.getId().toString();
            if (dekRing.contains(id)) {
                try {
                    KeyMaterial m = dekRing.getByVersion(id);
                    if (m.status() != KeyStatus.COMPROMISED) {
                        dekRing.markCompromised(id);
                        log.warn("Ring refresh: propagated COMPROMISED status for DEK [{}]", id);
                    }
                } catch (KeyVersionNotFoundException ignored) {
                    // Already evicted from ring — no action needed
                }
            }
        }
    }

    // ── HMAC ring sync ────────────────────────────────────────────────────────

    private void refreshHmacRing() {
        List<KeyVersion> activeOrRotating = keyVersionRepository.findHmacByStatusIn(
                List.of(KeyStatus.ACTIVE, KeyStatus.ROTATING));

        for (KeyVersion hv : activeOrRotating) {
            String id = hv.getId().toString();
            if (!hmacKeyRing.contains(id)) {
                byte[] secret = kmsProvider.unwrapHmacKey(hv.getEncryptedSecret());
                try {
                    hmacKeyRing.load(id, secret, hv.getRotateBy());
                    log.info("Ring refresh: loaded HMAC version [{}] (status={})", id, hv.getStatus());
                } finally {
                    Arrays.fill(secret, (byte) 0);
                }
            }
        }

        keyVersionRepository.findActiveHmac().ifPresent(dbActive -> {
            String dbActiveId = dbActive.getId().toString();
            try {
                String ringActiveId = hmacKeyRing.getActiveVersionId();
                if (!dbActiveId.equals(ringActiveId)) {
                    hmacKeyRing.promoteActive(dbActiveId);
                    log.info("Ring refresh: HMAC active pointer updated [{}] → [{}]",
                            ringActiveId, dbActiveId);
                }
            } catch (IllegalStateException e) {
                // Ring not yet initialised — KeyRingInitialiser handles this at startup
            }
        });
    }
}
