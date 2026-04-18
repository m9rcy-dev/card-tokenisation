package com.yourorg.tokenisation.kms;

import java.util.Arrays;

/**
 * Holds the result of a Data Encryption Key (DEK) generation operation.
 *
 * <p>A DEK is generated fresh for each tokenisation call. The {@code plaintextDek}
 * is held in memory only for the duration of the encrypt operation and must be
 * zeroed immediately after use:
 *
 * <pre>{@code
 * GeneratedDek generatedDek = kmsProvider.generateDek(keyVersionId);
 * try {
 *     // use generatedDek.plaintextDek() for encryption
 * } finally {
 *     generatedDek.zero();
 * }
 * }</pre>
 *
 * <p>{@code encryptedDek} is the KEK-wrapped form safe for persistent storage in
 * the {@code token_vault.encrypted_dek} column.
 */
public final class GeneratedDek {

    private final byte[] plaintextDek;
    private final byte[] encryptedDek;

    /**
     * Constructs a {@code GeneratedDek} from a plaintext key and its encrypted counterpart.
     *
     * @param plaintextDek  the raw 256-bit DEK bytes; must be exactly 32 bytes; defensive copy is taken
     * @param encryptedDek  the KEK-wrapped DEK bytes for persistence; defensive copy is taken
     * @throws IllegalArgumentException if {@code plaintextDek} is not 32 bytes
     */
    public GeneratedDek(byte[] plaintextDek, byte[] encryptedDek) {
        if (plaintextDek == null || plaintextDek.length != 32) {
            throw new IllegalArgumentException("Plaintext DEK must be exactly 32 bytes (AES-256)");
        }
        if (encryptedDek == null || encryptedDek.length == 0) {
            throw new IllegalArgumentException("Encrypted DEK must not be null or empty");
        }
        this.plaintextDek = plaintextDek.clone();
        this.encryptedDek = encryptedDek.clone();
    }

    /**
     * Returns a defensive copy of the plaintext DEK bytes.
     *
     * <p>The caller is responsible for zeroing the returned array after use.
     *
     * @return copy of the 32-byte plaintext DEK
     */
    public byte[] plaintextDek() {
        return plaintextDek.clone();
    }

    /**
     * Returns a defensive copy of the KEK-wrapped DEK bytes, safe for persistence.
     *
     * @return copy of the encrypted DEK
     */
    public byte[] encryptedDek() {
        return encryptedDek.clone();
    }

    /**
     * Zeros the plaintext DEK bytes held by this object.
     *
     * <p>Call this in a {@code finally} block immediately after the plaintext DEK
     * is no longer needed. Has no effect on the encrypted DEK.
     */
    public void zero() {
        Arrays.fill(plaintextDek, (byte) 0);
    }
}
