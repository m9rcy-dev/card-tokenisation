package com.yourorg.tokenisation.crypto;

import com.yourorg.tokenisation.domain.KeyStatus;

import java.time.Instant;
import java.util.Arrays;

/**
 * Holds the in-memory representation of a loaded Data Encryption Key (DEK).
 *
 * <p>Instances of this class are stored in {@link InMemoryDekKeyRing} and are created
 * once at startup (or during rotation) when the DEK bytes are decrypted from KMS.
 *
 * <p>The raw DEK bytes are held in a private {@code byte[]} field. Access is provided
 * only through {@link #copyDek()}, which returns a defensive copy — callers are
 * responsible for zeroing the returned array after use.
 *
 * <p>This class is immutable except for the {@code status} field, which is set to
 * {@code RETIRED} by {@link #asRetired()}. All other fields are final.
 */
public final class KeyMaterial {

    private final String keyVersionId;
    private final byte[] dek;
    private final Instant expiresAt;
    private volatile KeyStatus status;

    /**
     * Constructs a {@code KeyMaterial} for an active key version.
     *
     * @param keyVersionId the key version UUID string from {@code key_versions.id}; must not be null
     * @param dek          the raw 32-byte DEK bytes; a defensive copy is taken; must be exactly 32 bytes
     * @param expiresAt    the TTL after which this key ring entry must be refreshed from KMS; must not be null
     * @throws IllegalArgumentException if {@code dek} is null or not exactly 32 bytes
     */
    public KeyMaterial(String keyVersionId, byte[] dek, Instant expiresAt) {
        if (dek == null || dek.length != 32) {
            throw new IllegalArgumentException(
                    "DEK must be exactly 32 bytes; got: " + (dek == null ? "null" : dek.length));
        }
        this.keyVersionId = keyVersionId;
        this.dek = dek.clone();
        this.expiresAt = expiresAt;
        this.status = KeyStatus.ACTIVE;
    }

    public String keyVersionId() {
        return keyVersionId;
    }

    /**
     * Returns a defensive copy of the raw DEK bytes.
     *
     * <p>The caller is responsible for zeroing the returned array after use:
     * <pre>{@code
     * byte[] dek = keyMaterial.copyDek();
     * try {
     *     // use dek
     * } finally {
     *     Arrays.fill(dek, (byte) 0);
     * }
     * }</pre>
     *
     * @return copy of the 32-byte DEK
     */
    public byte[] copyDek() {
        return dek.clone();
    }

    public Instant expiresAt() {
        return expiresAt;
    }

    public KeyStatus status() {
        return status;
    }

    /**
     * Returns a copy of this {@code KeyMaterial} with status set to {@code RETIRED}.
     *
     * <p>The retired copy retains the DEK bytes so that detokenisation of old records
     * remains possible after rotation completes.
     */
    public KeyMaterial asRetired() {
        KeyMaterial retired = new KeyMaterial(keyVersionId, dek, expiresAt);
        retired.status = KeyStatus.RETIRED;
        return retired;
    }

    /**
     * Returns a copy of this {@code KeyMaterial} with status set to {@code COMPROMISED}.
     *
     * <p>The compromised copy retains its DEK bytes so that the rotation batch can still
     * decrypt existing PANs for re-encryption — but the detokenisation service will reject it.
     */
    public KeyMaterial asCompromised() {
        KeyMaterial compromised = new KeyMaterial(keyVersionId, dek, expiresAt);
        compromised.status = KeyStatus.COMPROMISED;
        return compromised;
    }

    /**
     * Zeros the DEK bytes held by this instance.
     *
     * <p>Call only when the key version is fully decommissioned. After calling this method
     * the instance must not be used for any cryptographic operation.
     */
    public void zero() {
        Arrays.fill(dek, (byte) 0);
    }
}
