package com.yourorg.tokenisation.kms;

/**
 * Abstraction over all Key Management System (KMS) operations required by the
 * card tokenisation system.
 *
 * <p>Implementations are selected at startup via the {@code kms.provider} configuration
 * property using Spring's {@code @ConditionalOnProperty}:
 * <ul>
 *   <li>{@code aws}       — {@code AwsKmsAdapter} (production)
 *   <li>{@code local-dev} — {@code LocalDevKmsAdapter} (local development and all tests)
 * </ul>
 *
 * <p>All implementations must be thread-safe — the same bean instance is called
 * concurrently by the key ring initialiser and the rotation service.
 *
 * <p>KMS calls are intentionally minimised:
 * <ul>
 *   <li>{@link #unwrapKek} is called once per key version at startup only
 *   <li>{@link #generateDek} is not called — DEKs are generated locally using {@code SecureRandom}
 *       and wrapped in-process using the in-memory KEK
 *   <li>{@link #rewrapDek} is called only during key rotation, not during normal tokenisation
 * </ul>
 */
public interface KmsProvider {

    /**
     * Decrypts a stored KEK ciphertext blob and returns the raw KEK bytes.
     *
     * <p>Called once per key version at application startup by {@code KeyRingInitialiser}.
     * The returned bytes are held in the {@code InMemoryKeyRing} for the application's lifetime
     * (or until TTL refresh). The caller is responsible for not logging the returned bytes.
     *
     * @param encryptedKekBlob Base64-encoded KEK ciphertext as stored in {@code key_versions.encrypted_kek_blob};
     *                         must not be null or empty
     * @return the raw 32-byte (AES-256) KEK; the caller must zero this array after loading it into the key ring
     * @throws IllegalArgumentException if {@code encryptedKekBlob} is null or empty
     * @throws KmsOperationException    if the KMS call fails or the blob cannot be decrypted
     */
    byte[] unwrapKek(String encryptedKekBlob);

    /**
     * Wraps a locally generated DEK under the current KEK and returns the encrypted blob for storage.
     *
     * <p>This method is used during rotation to re-wrap an existing DEK under a new KEK.
     * It does NOT generate a new DEK — DEK generation is done locally in {@code AesGcmCipher}.
     *
     * @param plaintextDek   the raw 32-byte DEK to wrap; must not be null; must be exactly 32 bytes
     * @param keyVersionId   the key version whose KEK is used to wrap the DEK; used for encryption context
     * @return the KEK-wrapped DEK bytes, safe for storage in {@code token_vault.encrypted_dek}
     * @throws IllegalArgumentException if {@code plaintextDek} is not 32 bytes
     * @throws KmsOperationException    if the wrap operation fails
     */
    byte[] wrapDek(byte[] plaintextDek, String keyVersionId);

    /**
     * Re-wraps a DEK: decrypts it under the old KEK, then re-encrypts it under the new KEK.
     *
     * <p>Called by the rotation batch processor for each token record during key rotation.
     * The plaintext DEK bytes are held in memory only for the duration of this call
     * and must be zeroed by the implementation before returning.
     *
     * @param encryptedDek      the DEK wrapped under the old KEK; must not be null
     * @param oldKeyVersionId   the key version that wrapped {@code encryptedDek}; used for decryption context
     * @param newKeyVersionId   the key version to wrap the DEK under; used for encryption context
     * @return the DEK re-wrapped under the new KEK, safe for storage
     * @throws KmsOperationException if either the unwrap or re-wrap operation fails
     */
    byte[] rewrapDek(byte[] encryptedDek, String oldKeyVersionId, String newKeyVersionId);

    /**
     * Retrieves metadata for a KMS key by its internal identifier.
     *
     * <p>Used by the tamper reconciliation job to validate that the local
     * {@code key_versions} record is consistent with the KMS source of truth.
     *
     * @param kmsKeyId the KMS-internal key identifier (e.g. AWS KMS key ARN); must not be null
     * @return key metadata as reported by the KMS
     * @throws KmsOperationException if the KMS is unreachable or the key does not exist
     */
    KeyMetadata describeKey(String kmsKeyId);
}
