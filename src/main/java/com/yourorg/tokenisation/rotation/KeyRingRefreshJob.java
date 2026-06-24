package com.yourorg.tokenisation.rotation;

import com.yourorg.tokenisation.crypto.InMemoryHmacKeyRing;
import com.yourorg.tokenisation.crypto.InMemoryKekKeyRing;
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
 * <p>In a multi-pod deployment (OpenShift, Kubernetes), key rotation initiated on one pod
 * updates the database but leaves the other pods' rings stale. This job detects and corrects
 * three forms of drift:
 * <ol>
 *   <li><b>Missing version</b> — a KEK or HMAC version is ACTIVE/ROTATING in DB but not in
 *       this pod's ring (rotation happened on a different pod). Fix: load from KMS and add.
 *   <li><b>Stale active pointer</b> — DB's ACTIVE version differs from the ring's current
 *       active pointer. Fix: promote the DB version.
 *   <li><b>Unpropagated COMPROMISED status</b> — emergency rotation marked a key COMPROMISED
 *       in DB and on the initiating pod, but this pod's ring still shows it as ACTIVE.
 *       Fix: call {@link InMemoryKekKeyRing#markCompromised} to immediately block detokenisation.
 * </ol>
 *
 * <p>This job intentionally does NOT use ShedLock. Each pod must independently refresh its
 * own in-memory ring — a distributed lock would prevent non-initiating pods from refreshing,
 * which is exactly the problem being solved.
 *
 * <p>The cron is controlled by {@code rotation.ring-refresh.cron} (default: every 60 seconds).
 * Set it to {@code "-"} in test profiles to disable automatic scheduling.
 */
@Component
@Slf4j
public class KeyRingRefreshJob {

    private final KeyVersionRepository keyVersionRepository;
    private final KmsProvider kmsProvider;
    private final InMemoryKekKeyRing keyRing;
    private final InMemoryHmacKeyRing hmacKeyRing;

    public KeyRingRefreshJob(KeyVersionRepository keyVersionRepository,
                             KmsProvider kmsProvider,
                             InMemoryKekKeyRing keyRing,
                             InMemoryHmacKeyRing hmacKeyRing) {
        this.keyVersionRepository = keyVersionRepository;
        this.kmsProvider = kmsProvider;
        this.keyRing = keyRing;
        this.hmacKeyRing = hmacKeyRing;
    }

    @Scheduled(cron = "${rotation.ring-refresh.cron:0 * * * * *}")
    public void refreshRings() {
        refreshKekRing();
        refreshHmacRing();
    }

    // ── KEK ring sync ─────────────────────────────────────────────────────────

    private void refreshKekRing() {
        // 1. Load any ACTIVE/ROTATING KEKs not yet present in this pod's ring
        List<KeyVersion> activeOrRotating = keyVersionRepository.findKekByStatusIn(
                List.of(KeyStatus.ACTIVE, KeyStatus.ROTATING));

        for (KeyVersion kv : activeOrRotating) {
            String id = kv.getId().toString();
            if (!keyRing.contains(id)) {
                byte[] kek = kmsProvider.unwrapKek(kv.getEncryptedKekBlob());
                try {
                    keyRing.load(id, kek, kv.getRotateBy());
                    log.info("Ring refresh: loaded KEK version [{}] (status={})", id, kv.getStatus());
                } finally {
                    Arrays.fill(kek, (byte) 0);
                }
            }
        }

        // 2. Promote the DB-active version if the ring's active pointer is stale
        keyVersionRepository.findActiveKek().ifPresent(dbActive -> {
            String dbActiveId = dbActive.getId().toString();
            try {
                String ringActiveId = keyRing.getActive().keyVersionId();
                if (!dbActiveId.equals(ringActiveId)) {
                    keyRing.promoteActive(dbActiveId);
                    log.info("Ring refresh: KEK active pointer updated [{}] → [{}]",
                            ringActiveId, dbActiveId);
                }
            } catch (IllegalStateException e) {
                // Ring not yet initialised — KeyRingInitialiser handles this at startup
            }
        });

        // 3. Propagate COMPROMISED status for emergency rotations that fired on other pods
        List<KeyVersion> compromised = keyVersionRepository.findKekByStatusIn(
                List.of(KeyStatus.COMPROMISED));
        for (KeyVersion kv : compromised) {
            String id = kv.getId().toString();
            if (keyRing.contains(id)) {
                try {
                    KeyMaterial m = keyRing.getByVersion(id);
                    if (m.status() != KeyStatus.COMPROMISED) {
                        keyRing.markCompromised(id);
                        log.warn("Ring refresh: propagated COMPROMISED status for KEK [{}] — " +
                                "detokenisation of affected tokens is now blocked", id);
                    }
                } catch (KeyVersionNotFoundException ignored) {
                    // Already evicted from ring — no action needed
                }
            }
        }
    }

    // ── HMAC ring sync ────────────────────────────────────────────────────────

    private void refreshHmacRing() {
        // 1. Load any ACTIVE/ROTATING HMAC versions not yet present in this pod's ring
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

        // 2. Promote the DB-active version if the ring's active pointer is stale
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
