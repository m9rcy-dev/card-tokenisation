package com.yourorg.tokenisation.crypto;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Versioned in-memory store for HMAC signing secrets used by {@link PanHasher}.
 *
 * <p>Mirrors {@link InMemoryDekKeyRing} for DEK material but holds arbitrary-length
 * HMAC secrets instead of 32-byte data encryption keys. A single active pointer is
 * maintained — HMAC rotation promotes the new version after all vault records are
 * re-hashed.
 *
 * <p>Unlike the DEK ring, retired versions are removed from the map and their secret bytes
 * are zeroed — there is no need to retain old HMAC secrets after the re-hash batch completes.
 *
 * <p>Thread safety: the map uses {@code ConcurrentHashMap}; the active pointer is
 * {@code volatile} so that a promotion is immediately visible to all threads.
 *
 * @see InMemoryDekKeyRing for the DEK-specific ring
 * @see KeyRing for the shared lifecycle interface
 */
@Component
@Slf4j
public class InMemoryHmacKeyRing implements KeyRing {

    private final ConcurrentHashMap<String, byte[]> secrets = new ConcurrentHashMap<>();
    private volatile String activeVersionId;

    /**
     * Loads an HMAC secret for the given version ID.
     * A defensive copy is taken — the caller may zero the original after this call.
     *
     * @param versionId UUID string of the HMAC key version row
     * @param secret    the raw HMAC secret bytes; must not be null or empty
     * @param expiresAt not stored, kept for API symmetry with {@link InMemoryDekKeyRing#load}
     */
    @Override
    public void load(String versionId, byte[] secret, Instant expiresAt) {
        if (secret == null || secret.length == 0) {
            throw new IllegalArgumentException("HMAC secret must not be null or empty");
        }
        secrets.put(versionId, secret.clone());
        log.info("Loaded HMAC key version {} into ring", versionId);
    }

    /**
     * Promotes the given version to active. Must already be loaded.
     *
     * @param versionId UUID string of the version to promote
     * @throws IllegalStateException if the version has not been loaded
     */
    @Override
    public void promoteActive(String versionId) {
        if (!secrets.containsKey(versionId)) {
            throw new IllegalStateException(
                    "Cannot promote HMAC key version that is not loaded in the ring: " + versionId);
        }
        this.activeVersionId = versionId;
        log.info("Promoted HMAC key version {} to active", versionId);
    }

    /**
     * Returns a defensive copy of the active HMAC secret.
     * The caller must zero the returned array after use.
     *
     * @return defensive copy of the active HMAC secret bytes
     * @throws IllegalStateException if no version has been promoted
     */
    public byte[] getActiveSecret() {
        String vId = activeVersionId;
        if (vId == null) {
            throw new IllegalStateException("No active HMAC key version has been promoted");
        }
        byte[] secret = secrets.get(vId);
        if (secret == null) {
            throw new IllegalStateException(
                    "Active HMAC version ID is set but not found in ring: " + vId);
        }
        return secret.clone();
    }

    /**
     * Returns the version ID that is currently active.
     *
     * @throws IllegalStateException if no version has been promoted
     */
    public String getActiveVersionId() {
        String vId = activeVersionId;
        if (vId == null) {
            throw new IllegalStateException("No active HMAC key version has been promoted");
        }
        return vId;
    }

    /**
     * Returns a defensive copy of the HMAC secret for the given version.
     * The caller must zero the returned array after use.
     *
     * @param versionId UUID string of the version to look up
     * @return defensive copy of the HMAC secret bytes
     * @throws KeyVersionNotFoundException if the version is not in the ring
     */
    public byte[] getSecretByVersion(String versionId) {
        byte[] secret = secrets.get(versionId);
        if (secret == null) {
            throw new KeyVersionNotFoundException(versionId);
        }
        return secret.clone();
    }

    /**
     * Returns whether the given version is currently loaded in the ring.
     */
    @Override
    public boolean contains(String versionId) {
        return secrets.containsKey(versionId);
    }

    /**
     * Removes a retired version from the ring and zeros its secret bytes.
     * Safe to call after the HMAC rotation batch has completed.
     */
    @Override
    public void retire(String versionId) {
        byte[] removed = secrets.remove(versionId);
        if (removed != null) {
            Arrays.fill(removed, (byte) 0);
            log.info("Retired HMAC key version {} from ring", versionId);
        }
    }

    /**
     * Returns the active version ID if known, for use by the HMAC rotation batch
     * to detect mid-rotation dual-lookup scenarios.
     */
    public Optional<String> findRotatingVersionId() {
        String active = activeVersionId;
        return secrets.keySet().stream()
                .filter(id -> !id.equals(active))
                .findFirst();
    }
}
