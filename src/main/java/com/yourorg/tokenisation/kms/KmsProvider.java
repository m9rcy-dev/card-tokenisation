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
 *   <li>{@link #decryptDataKey} is called once per DEK version at startup only
 *   <li>{@link #generateDataKey} is called once per rotation event (not per tokenisation)
 *   <li>Normal tokenisation uses the in-memory DEK from the ring — zero KMS calls
 * </ul>
 */
public interface KmsProvider {

    /**
     * Generates a new Data Encryption Key (DEK) and returns both its plaintext and
     * KMS-encrypted forms.
     *
     * <p>For AWS: calls {@code kms:GenerateDataKey(AES_256)} — one atomic round-trip that
     * returns both forms. For other providers: generates 32 random bytes locally and encrypts
     * them with the provider-specific mechanism.
     *
     * <p>Used by seeders on first boot and by {@code KeyRotationService} on each rotation.
     * The {@link DataKey#plaintextDek()} must be zeroed by the caller after loading into the ring.
     * The {@link DataKey#encryptedDekBlob()} is stored in {@code key_versions.encrypted_dek_blob}.
     *
     * @return a {@link DataKey} holding both plaintext and encrypted forms of the new DEK
     * @throws KmsOperationException if the KMS call fails
     */
    DataKey generateDataKey();

    /**
     * Decrypts a stored encrypted DEK blob and returns the raw 32-byte DEK.
     *
     * <p>Called once per DEK version at startup by {@code KeyRingInitialiser}.
     * The returned bytes are loaded into {@code InMemoryDekKeyRing} and the array is
     * zeroed immediately after loading. The caller is responsible for zeroing the array.
     *
     * @param encryptedDekBlob the KMS ciphertext as stored in {@code key_versions.encrypted_dek_blob}; must not be null
     * @return the raw 32-byte (AES-256) DEK; the caller must zero this array after loading it into the ring
     * @throws IllegalArgumentException if {@code encryptedDekBlob} is null
     * @throws KmsOperationException    if the KMS call fails or the blob cannot be decrypted
     */
    byte[] decryptDataKey(byte[] encryptedDekBlob);

    /**
     * Encrypts a freshly generated HMAC secret under the KMS master key for storage.
     *
     * <p>Uses encryption context {@code purpose=hmac-key}, distinct from the DEK context,
     * so that a blob encrypted by this method cannot be decrypted via {@link #decryptDataKey}
     * and vice versa.
     *
     * <p>Callers must zero {@code plaintextHmacKey} immediately after this method returns.
     *
     * @param plaintextHmacKey the raw HMAC secret bytes to protect; must not be null
     * @return the KMS-encrypted HMAC secret blob, suitable for storage as BYTEA in {@code key_versions.encrypted_secret}
     * @throws KmsOperationException if the KMS call fails
     */
    byte[] wrapNewHmacKey(byte[] plaintextHmacKey);

    /**
     * Decrypts a stored HMAC secret blob and returns the raw secret bytes.
     *
     * <p>Called once per HMAC key version at startup by {@code KeyRingInitialiser}.
     * The caller must zero the returned array immediately after loading it into the HMAC ring.
     *
     * @param encryptedHmacBlob the KMS ciphertext as stored in {@code key_versions.encrypted_secret}; must not be null
     * @return the raw HMAC secret bytes; caller must zero after use
     * @throws KmsOperationException if the KMS call fails or the blob is invalid
     */
    byte[] unwrapHmacKey(byte[] encryptedHmacBlob);

    /**
     * Retrieves metadata for a KMS key by its internal identifier.
     *
     * <p>Used for operational health checks to validate that the local
     * {@code key_versions} record is consistent with the KMS source of truth.
     *
     * @param kmsKeyId the KMS-internal key identifier (e.g. AWS KMS key ARN); must not be null
     * @return key metadata as reported by the KMS
     * @throws KmsOperationException if the KMS is unreachable or the key does not exist
     */
    KeyMetadata describeKey(String kmsKeyId);
}
