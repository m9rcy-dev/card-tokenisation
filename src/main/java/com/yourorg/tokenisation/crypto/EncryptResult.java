package com.yourorg.tokenisation.crypto;

/**
 * Holds all fields produced by a single AES-256-GCM PAN encryption operation.
 *
 * <p>All three byte arrays are safe to persist — none contains plaintext material.
 * The caller does not need to zero any field of this record.
 *
 * @param ciphertext   GCM ciphertext of the PAN (variable length; equals PAN length for GCM NoPadding)
 * @param iv           12-byte (96-bit) GCM initialisation vector; unique per encryption operation
 * @param authTag      16-byte (128-bit) GCM authentication tag; required for tamper detection on decrypt
 * @param encryptedDek the per-record DEK wrapped by the active KEK; stored alongside the ciphertext
 */
public record EncryptResult(
        byte[] ciphertext,
        byte[] iv,
        byte[] authTag,
        byte[] encryptedDek
) {
    /**
     * Returns a new {@code EncryptResult} with defensive copies of all byte arrays.
     *
     * @param ciphertext   ciphertext bytes
     * @param iv           IV bytes; must be exactly 12 bytes
     * @param authTag      authentication tag bytes; must be exactly 16 bytes
     * @param encryptedDek KEK-wrapped DEK bytes
     * @throws IllegalArgumentException if {@code iv} is not 12 bytes or {@code authTag} is not 16 bytes
     */
    public EncryptResult {
        if (iv == null || iv.length != 12) {
            throw new IllegalArgumentException("IV must be exactly 12 bytes; got: " + (iv == null ? "null" : iv.length));
        }
        if (authTag == null || authTag.length != 16) {
            throw new IllegalArgumentException("Auth tag must be exactly 16 bytes; got: " + (authTag == null ? "null" : authTag.length));
        }
        // Defensive copies — records are immutable but arrays inside are not
        ciphertext = ciphertext.clone();
        iv = iv.clone();
        authTag = authTag.clone();
        encryptedDek = encryptedDek.clone();
    }
}
