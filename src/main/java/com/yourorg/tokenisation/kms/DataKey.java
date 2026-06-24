package com.yourorg.tokenisation.kms;

/**
 * Holds both forms of a freshly generated Data Encryption Key returned by {@link KmsProvider#generateDataKey}.
 *
 * <p>The plaintext DEK is for immediate in-memory use (loading into {@code InMemoryDekKeyRing}).
 * The encrypted blob is safe to persist in {@code key_versions.encrypted_dek_blob}.
 *
 * <p>Callers must zero {@code plaintextDek} with {@code Arrays.fill} immediately after
 * loading it into the key ring. The encrypted blob requires no special handling.
 *
 * @param plaintextDek      raw 32-byte (AES-256) DEK; must be zeroed by the caller after use
 * @param encryptedDekBlob  KMS ciphertext of the DEK; safe for BYTEA storage
 */
public record DataKey(byte[] plaintextDek, byte[] encryptedDekBlob) {}
