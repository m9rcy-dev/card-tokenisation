package com.yourorg.tokenisation.crypto;

import java.time.Instant;

/**
 * Common lifecycle contract shared by all versioned in-memory key rings.
 *
 * <p>Both the KEK ring ({@link InMemoryKekKeyRing}) and the HMAC ring
 * ({@link InMemoryHmacKeyRing}) support loading, promoting, querying, and
 * retiring key versions. Ring-type-specific accessors (e.g. {@code getActive()}
 * returning {@link KeyMaterial}, or {@code getActiveSecret()} returning {@code byte[]})
 * are defined on the concrete class.
 *
 * <p>Implementations must be thread-safe.
 */
public interface KeyRing {

    /**
     * Loads a key version into the ring.
     * A defensive copy of {@code material} must be taken; the caller may zero the original after this call.
     *
     * @param versionId UUID string of the key version
     * @param material  raw key bytes (KEK or HMAC secret); must not be null or empty
     * @param expiresAt TTL after which the entry must be refreshed
     */
    void load(String versionId, byte[] material, Instant expiresAt);

    /**
     * Promotes the given version to active. Must already be loaded in the ring.
     *
     * @param versionId UUID string of the version to promote
     * @throws IllegalStateException if the version is not loaded
     */
    void promoteActive(String versionId);

    /**
     * Returns whether the given version is currently loaded in the ring.
     *
     * @param versionId UUID string of the version to check
     * @return {@code true} if the version is loaded
     */
    boolean contains(String versionId);

    /**
     * Retires a key version.
     *
     * <p>KEK ring implementations keep the version in the ring (needed for detokenisation).
     * HMAC ring implementations remove the version and zero its secret bytes.
     *
     * @param versionId UUID string of the version to retire
     */
    void retire(String versionId);
}
