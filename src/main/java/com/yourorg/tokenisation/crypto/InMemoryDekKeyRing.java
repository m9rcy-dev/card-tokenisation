package com.yourorg.tokenisation.crypto;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Versioned in-memory store for Data Encryption Key (DEK) material.
 *
 * <p>All active and rotating DEK versions are loaded into this ring at startup
 * by {@link KeyRingInitialiser}. During normal tokenisation, only the active version
 * is accessed. During key rotation, both the old (ROTATING) and new (ACTIVE) versions
 * are held simultaneously — the old version remains for detokenisation of existing tokens
 * while the re-encryption batch is in progress.
 *
 * <p>Thread safety: all map operations use {@code ConcurrentHashMap} with atomic
 * {@code compute*} methods. The {@code activeKeyVersionId} field is {@code volatile}
 * so that a promotion written by one thread is immediately visible to all others.
 *
 * <p>Key material bytes are held in {@link KeyMaterial#copyDek()} — the caller receives
 * a defensive copy and is responsible for zeroing it after use.
 *
 * @see InMemoryHmacKeyRing for the HMAC-specific ring
 * @see KeyRing for the shared lifecycle interface
 */
@Component
@Slf4j
public class InMemoryDekKeyRing implements KeyRing {

    private final ConcurrentHashMap<String, KeyMaterial> keyMaterials = new ConcurrentHashMap<>();
    private volatile String activeKeyVersionId;

    @Override
    public void load(String keyVersionId, byte[] dek, Instant expiresAt) {
        KeyMaterial keyMaterial = new KeyMaterial(keyVersionId, dek, expiresAt);
        keyMaterials.put(keyVersionId, keyMaterial);
        log.info("Loaded DEK version {} into ring (expires at {})", keyVersionId, expiresAt);
    }

    @Override
    public void promoteActive(String keyVersionId) {
        if (!keyMaterials.containsKey(keyVersionId)) {
            throw new IllegalStateException("Cannot promote DEK version that is not loaded in the ring: " + keyVersionId);
        }
        this.activeKeyVersionId = keyVersionId;
        log.info("Promoted DEK version {} to active", keyVersionId);
    }

    /**
     * Returns the {@link KeyMaterial} for the currently active DEK version.
     * Used during tokenisation to obtain the DEK for PAN encryption.
     */
    public KeyMaterial getActive() {
        String versionId = activeKeyVersionId;
        if (versionId == null) {
            throw new IllegalStateException("No active DEK version has been promoted in the key ring");
        }
        return Optional.ofNullable(keyMaterials.get(versionId))
                .orElseThrow(() -> new IllegalStateException(
                        "Active DEK version ID is set but not found in ring: " + versionId));
    }

    /**
     * Returns the {@link KeyMaterial} for the specified DEK version.
     * Used during detokenisation to retrieve the DEK for the specific version
     * that was used to encrypt a token's PAN.
     */
    public KeyMaterial getByVersion(String keyVersionId) {
        return Optional.ofNullable(keyMaterials.get(keyVersionId))
                .orElseThrow(() -> new KeyVersionNotFoundException(keyVersionId));
    }

    @Override
    public void retire(String keyVersionId) {
        keyMaterials.computeIfPresent(keyVersionId, (id, existing) -> existing.asRetired());
        log.info("Retired DEK version {} in ring — still accessible for detokenisation of pre-rotation tokens", keyVersionId);
    }

    /**
     * Marks a DEK version as compromised, immediately blocking detokenisation of affected tokens.
     */
    public void markCompromised(String keyVersionId) {
        if (!keyMaterials.containsKey(keyVersionId)) {
            throw new IllegalStateException("Cannot mark as compromised: DEK version not in ring: " + keyVersionId);
        }
        keyMaterials.computeIfPresent(keyVersionId, (id, existing) -> existing.asCompromised());
        log.warn("DEK version {} marked as COMPROMISED in ring — detokenisation blocked for affected tokens", keyVersionId);
    }

    @Override
    public boolean contains(String keyVersionId) {
        return keyMaterials.containsKey(keyVersionId);
    }
}
