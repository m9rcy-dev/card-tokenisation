package com.yourorg.tokenisation.crypto;

import com.yourorg.tokenisation.domain.KeyStatus;

import java.time.Instant;
import java.util.Arrays;

/**
 * Holds the in-memory representation of a loaded Key Encryption Key (KEK).
 *
 * <p>Instances of this class are stored in {@link InMemoryKeyRing} and are created
 * once at startup (or during rotation) when the KEK bytes are unwrapped from KMS.
 *
 * <p>The raw KEK bytes are held in a private {@code byte[]} field. Access is provided
 * only through {@link #copyKek()}, which returns a defensive copy — callers are
 * responsible for zeroing the returned array after use.
 *
 * <p>This class is immutable except for the {@code status} field, which is set to
 * {@code RETIRED} by {@link #asRetired()}. All other fields are final.
 */
public final class KeyMaterial {

    private final String keyVersionId;
    private final byte[] kek;
    private final Instant expiresAt;
    private volatile KeyStatus status;

    /**
     * Constructs a {@code KeyMaterial} for an active key version.
     *
     * @param keyVersionId the key version UUID string from {@code key_versions.id}; must not be null
     * @param kek          the raw 32-byte KEK bytes; a defensive copy is taken; must be exactly 32 bytes
     * @param expiresAt    the TTL after which this key ring entry must be refreshed from KMS; must not be null
     * @throws IllegalArgumentException if {@code kek} is null or not exactly 32 bytes
     */
    public KeyMaterial(String keyVersionId, byte[] kek, Instant expiresAt) {
        if (kek == null || kek.length != 32) {
            throw new IllegalArgumentException(
                    "KEK must be exactly 32 bytes; got: " + (kek == null ? "null" : kek.length));
        }
        this.keyVersionId = keyVersionId;
        this.kek = kek.clone();
        this.expiresAt = expiresAt;
        this.status = KeyStatus.ACTIVE;
    }

    /**
     * Returns the key version UUID this material belongs to.
     *
     * @return the key version ID string
     */
    public String keyVersionId() {
        return keyVersionId;
    }

    /**
     * Returns a defensive copy of the raw KEK bytes.
     *
     * <p>The caller is responsible for zeroing the returned array after use:
     * <pre>{@code
     * byte[] kek = keyMaterial.copyKek();
     * try {
     *     // use kek
     * } finally {
     *     Arrays.fill(kek, (byte) 0);
     * }
     * }</pre>
     *
     * @return copy of the 32-byte KEK
     */
    public byte[] copyKek() {
        return kek.clone();
    }

    /**
     * Returns the TTL instant after which the KEK must be refreshed from KMS.
     *
     * @return the expiry instant
     */
    public Instant expiresAt() {
        return expiresAt;
    }

    /**
     * Returns the current lifecycle status of this key material.
     *
     * @return current status ({@code ACTIVE}, {@code ROTATING}, or {@code RETIRED})
     */
    public KeyStatus status() {
        return status;
    }

    /**
     * Returns a copy of this {@code KeyMaterial} with status set to {@code RETIRED}.
     *
     * <p>The original instance is unchanged. The retired copy shares the same KEK bytes
     * (via its own defensive copy) so that detokenisation of old records remains possible
     * after rotation completes.
     *
     * @return a new {@code KeyMaterial} with {@code status = RETIRED} and the same KEK and expiry
     */
    public KeyMaterial asRetired() {
        KeyMaterial retired = new KeyMaterial(keyVersionId, kek, expiresAt);
        retired.status = KeyStatus.RETIRED;
        return retired;
    }

    /**
     * Returns a copy of this {@code KeyMaterial} with status set to {@code COMPROMISED}.
     *
     * <p>The original instance is unchanged. The compromised copy retains its KEK bytes
     * so that the rotation batch can still unwrap existing DEKs for re-encryption under
     * the new key — but the detokenisation service will reject it immediately.
     *
     * @return a new {@code KeyMaterial} with {@code status = COMPROMISED} and the same KEK and expiry
     */
    public KeyMaterial asCompromised() {
        KeyMaterial compromised = new KeyMaterial(keyVersionId, kek, expiresAt);
        compromised.status = KeyStatus.COMPROMISED;
        return compromised;
    }

    /**
     * Zeros the KEK bytes held by this instance.
     *
     * <p>Call this only when the key version is fully decommissioned and no further
     * operations will need this key material. After calling this method the instance
     * must not be used for any cryptographic operation.
     */
    public void zero() {
        Arrays.fill(kek, (byte) 0);
    }
}
