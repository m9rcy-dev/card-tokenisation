package com.yourorg.tokenisation.crypto;

import com.yourorg.tokenisation.exception.TokenisationException;

/**
 * Thrown when a requested key version is not found in the {@link InMemoryKeyRing}.
 *
 * <p>This exception indicates a programming error or an unexpected state:
 * the key version was not loaded at startup (e.g. it was already retired before the
 * application started, or the token references a version that was never in the ring).
 *
 * <p>The key version ID is included in the message to aid diagnosis —
 * it is a UUID, not sensitive material.
 */
public class KeyVersionNotFoundException extends TokenisationException {

    /**
     * Constructs a {@code KeyVersionNotFoundException} for the given key version ID.
     *
     * @param keyVersionId the key version UUID that was not found in the key ring
     */
    public KeyVersionNotFoundException(String keyVersionId) {
        super("Key version not found in key ring: " + keyVersionId);
    }
}
