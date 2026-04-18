package com.yourorg.tokenisation.crypto;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Versioned in-memory store for Key Encryption Key (KEK) material.
 *
 * <p>All active and rotating key versions are loaded into this ring at startup
 * by {@link KeyRingInitialiser}. During normal tokenisation, only the active version
 * is accessed. During key rotation, both the old (ROTATING) and new (ACTIVE) versions
 * are held simultaneously — the old version remains for detokenisation of existing tokens
 * while the re-encryption batch is in progress.
 *
 * <p>Thread safety: all map operations use {@code ConcurrentHashMap} with atomic
 * {@code compute*} methods. The {@code activeKeyVersionId} field is {@code volatile}
 * so that a promotion written by one thread is immediately visible to all others.
 *
 * <p>Key material bytes are held in {@link KeyMaterial#copyKek()} — the caller receives
 * a defensive copy and is responsible for zeroing it after use.
 */
@Component
@Slf4j
public class InMemoryKeyRing {

    private final ConcurrentHashMap<String, KeyMaterial> keyMaterials = new ConcurrentHashMap<>();
    private volatile String activeKeyVersionId;

    /**
     * Loads a key version into the ring.
     *
     * <p>If the key version is already present, the existing entry is replaced.
     * This supports TTL-based refresh where the startup initialiser reloads all versions
     * after the TTL window expires.
     *
     * @param keyVersionId the UUID string of the key version; must not be null
     * @param kek          the raw 32-byte KEK bytes; a defensive copy is taken by {@link KeyMaterial};
     *                     must be exactly 32 bytes
     * @param expiresAt    the TTL after which this entry must be refreshed; must not be null
     * @throws IllegalArgumentException if {@code kek} is not 32 bytes
     */
    public void load(String keyVersionId, byte[] kek, Instant expiresAt) {
        KeyMaterial keyMaterial = new KeyMaterial(keyVersionId, kek, expiresAt);
        keyMaterials.put(keyVersionId, keyMaterial);
        log.info("Loaded key version {} into ring (expires at {})", keyVersionId, expiresAt);
    }

    /**
     * Promotes a loaded key version to active status.
     *
     * <p>After this call, all new tokenisation operations use the promoted version's KEK.
     * The previously active version (if any) is not removed from the ring — it remains
     * available for detokenisation of tokens encrypted under it.
     *
     * @param keyVersionId the key version to promote; must already be loaded in the ring
     * @throws IllegalStateException if the key version has not been loaded
     */
    public void promoteActive(String keyVersionId) {
        if (!keyMaterials.containsKey(keyVersionId)) {
            throw new IllegalStateException("Cannot promote key version that is not loaded in the ring: " + keyVersionId);
        }
        this.activeKeyVersionId = keyVersionId;
        log.info("Promoted key version {} to active", keyVersionId);
    }

    /**
     * Returns the {@link KeyMaterial} for the currently active key version.
     *
     * <p>Used during tokenisation to obtain the KEK for DEK wrapping.
     *
     * @return the active key material
     * @throws IllegalStateException if no key version has been promoted to active
     */
    public KeyMaterial getActive() {
        String versionId = activeKeyVersionId;
        if (versionId == null) {
            throw new IllegalStateException("No active key version has been promoted in the key ring");
        }
        return Optional.ofNullable(keyMaterials.get(versionId))
                .orElseThrow(() -> new IllegalStateException(
                        "Active key version ID is set but not found in ring: " + versionId));
    }

    /**
     * Returns the {@link KeyMaterial} for the specified key version.
     *
     * <p>Used during detokenisation to retrieve the KEK for the specific version
     * that was used to encrypt a token's DEK.
     *
     * @param keyVersionId the key version UUID to look up; must not be null
     * @return the key material for the requested version
     * @throws KeyVersionNotFoundException if the version is not in the ring
     */
    public KeyMaterial getByVersion(String keyVersionId) {
        return Optional.ofNullable(keyMaterials.get(keyVersionId))
                .orElseThrow(() -> new KeyVersionNotFoundException(keyVersionId));
    }

    /**
     * Marks a key version as retired in the ring.
     *
     * <p>The version is NOT removed — retired key material remains in the ring so that
     * detokenisation of tokens created before rotation can still proceed.
     * New tokenisation will use the newly promoted active version.
     *
     * <p>If the key version is not in the ring, this method is a no-op (idempotent).
     *
     * @param keyVersionId the key version UUID to retire; must not be null
     */
    public void retire(String keyVersionId) {
        // computeIfPresent is atomic — no separate get/put race
        keyMaterials.computeIfPresent(keyVersionId, (id, existing) -> existing.asRetired());
        log.info("Retired key version {} in ring — still accessible for detokenisation of pre-rotation tokens", keyVersionId);
    }

    /**
     * Marks a key version as compromised in the ring by setting its status to {@code COMPROMISED}.
     *
     * <p>The detokenisation service checks this status before unwrapping any DEK.
     * A compromised status causes detokenisation to fail with a tamper alert audit event.
     *
     * <p>This is set synchronously during emergency rotation — before any other rotation
     * steps — to immediately block detokenisation of affected tokens.
     *
     * @param keyVersionId the key version UUID to mark as compromised; must not be null
     * @throws IllegalStateException if the key version is not in the ring
     */
    public void markCompromised(String keyVersionId) {
        if (!keyMaterials.containsKey(keyVersionId)) {
            throw new IllegalStateException("Cannot mark as compromised: key version not in ring: " + keyVersionId);
        }
        // computeIfPresent is atomic — no separate get/put race
        keyMaterials.computeIfPresent(keyVersionId, (id, existing) -> existing.asCompromised());
        log.warn("Key version {} marked as COMPROMISED in ring — detokenisation blocked for affected tokens", keyVersionId);
    }

    /**
     * Returns whether the given key version is currently in the ring.
     *
     * @param keyVersionId the key version UUID to check
     * @return {@code true} if the version is loaded in the ring
     */
    public boolean contains(String keyVersionId) {
        return keyMaterials.containsKey(keyVersionId);
    }
}
