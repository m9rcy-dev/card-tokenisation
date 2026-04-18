package com.yourorg.tokenisation.kms;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DescribeKeyRequest;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.KmsException;

import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

/**
 * AWS KMS adapter — implements {@link KmsProvider} using the AWS SDK v2 KMS client.
 *
 * <p>Activated when {@code kms.provider=aws}. Uses the master key ARN from
 * {@code kms.aws.master-key-arn} for all wrapping and unwrapping operations.
 *
 * <p>This adapter minimises KMS call volume:
 * <ul>
 *   <li>{@link #unwrapKek} is called once per key version at startup only.
 *   <li>{@link #wrapDek} and {@link #rewrapDek} are called only during key rotation,
 *       not on every tokenisation — DEKs are generated locally via {@code SecureRandom}.
 *   <li>Normal tokenisation generates DEKs locally and wraps them in-process using the
 *       in-memory KEK, with no KMS call at all.
 * </ul>
 *
 * <p>All operations include an encryption context ({@code purpose} and {@code keyVersionId})
 * to bind ciphertexts to their intended use, preventing ciphertext reuse across contexts.
 */
@Component
@ConditionalOnProperty(name = "kms.provider", havingValue = "aws")
@Slf4j
public class AwsKmsAdapter implements KmsProvider {

    private static final String ENCRYPTION_CONTEXT_PURPOSE_KEY = "purpose";
    private static final String ENCRYPTION_CONTEXT_KEY_VERSION_KEY = "keyVersionId";
    private static final String ENCRYPTION_CONTEXT_KEK_UNWRAP_VALUE = "kek-unwrap";
    private static final String ENCRYPTION_CONTEXT_DEK_WRAP_VALUE = "dek-wrap";

    private final KmsClient kmsClient;
    private final String masterKeyArn;

    /**
     * Constructs the AWS KMS adapter.
     *
     * @param kmsClient    the AWS SDK KMS client configured with the correct region and credentials;
     *                     must not be null
     * @param masterKeyArn the ARN of the master key used for all wrap/unwrap operations;
     *                     must not be null or empty
     */
    public AwsKmsAdapter(KmsClient kmsClient,
                         @Value("${kms.aws.master-key-arn}") String masterKeyArn) {
        this.kmsClient = kmsClient;
        this.masterKeyArn = masterKeyArn;
    }

    /**
     * Decrypts the stored KEK ciphertext blob using AWS KMS and returns the raw KEK bytes.
     *
     * <p>The {@code encryptedKekBlob} is expected to be a Base64-encoded AWS KMS ciphertext
     * produced by a prior {@code kms:Encrypt} call against the master key ARN.
     * An encryption context of {@code purpose=kek-unwrap} is asserted — blobs encrypted
     * with a different context will fail with an {@code InvalidCiphertextException}.
     *
     * @param encryptedKekBlob Base64-encoded KMS ciphertext of the KEK; must not be null or empty
     * @return raw 32-byte KEK; caller must zero after loading into the key ring
     * @throws IllegalArgumentException if {@code encryptedKekBlob} is null or empty
     * @throws KmsOperationException    if the KMS call fails or the ciphertext is invalid
     */
    @Override
    public byte[] unwrapKek(String encryptedKekBlob) {
        if (encryptedKekBlob == null || encryptedKekBlob.isBlank()) {
            throw new IllegalArgumentException("Encrypted KEK blob must not be null or blank");
        }
        try {
            DecryptRequest decryptRequest = DecryptRequest.builder()
                    .ciphertextBlob(SdkBytes.fromByteArray(Base64.getDecoder().decode(encryptedKekBlob)))
                    .keyId(masterKeyArn)
                    .encryptionContext(Map.of(ENCRYPTION_CONTEXT_PURPOSE_KEY, ENCRYPTION_CONTEXT_KEK_UNWRAP_VALUE))
                    .build();
            log.info("Unwrapping KEK from AWS KMS — key ARN redacted, context: purpose=kek-unwrap");
            return kmsClient.decrypt(decryptRequest).plaintext().asByteArray();
        } catch (KmsException kmsException) {
            throw new KmsOperationException("AWS KMS KEK unwrap failed", kmsException);
        }
    }

    /**
     * Wraps a locally generated DEK by encrypting it with the master KEK via AWS KMS.
     *
     * <p>Uses {@code kms:Encrypt} with an encryption context binding the wrapped DEK
     * to the given {@code keyVersionId}. This prevents the encrypted DEK from being
     * decrypted under a different key version context.
     *
     * @param plaintextDek  the 32-byte DEK to wrap; must not be null; must be exactly 32 bytes
     * @param keyVersionId  the key version UUID used as encryption context; must not be null
     * @return Base64-decoded KMS ciphertext of the DEK (raw bytes, suitable for storage)
     * @throws IllegalArgumentException if {@code plaintextDek} is not 32 bytes
     * @throws KmsOperationException    if the KMS call fails
     */
    @Override
    public byte[] wrapDek(byte[] plaintextDek, String keyVersionId) {
        if (plaintextDek == null || plaintextDek.length != 32) {
            throw new IllegalArgumentException("Plaintext DEK must be exactly 32 bytes");
        }
        try {
            EncryptRequest encryptRequest = EncryptRequest.builder()
                    .keyId(masterKeyArn)
                    .plaintext(SdkBytes.fromByteArray(plaintextDek))
                    .encryptionContext(Map.of(
                            ENCRYPTION_CONTEXT_PURPOSE_KEY, ENCRYPTION_CONTEXT_DEK_WRAP_VALUE,
                            ENCRYPTION_CONTEXT_KEY_VERSION_KEY, keyVersionId))
                    .build();
            return kmsClient.encrypt(encryptRequest).ciphertextBlob().asByteArray();
        } catch (KmsException kmsException) {
            throw new KmsOperationException("AWS KMS DEK wrap failed for key version: " + keyVersionId, kmsException);
        }
    }

    /**
     * Re-wraps a DEK from one key version to another via AWS KMS.
     *
     * <p>Decrypts the DEK using the old key version's encryption context, then
     * immediately re-encrypts it under the new key version's context. The plaintext
     * DEK bytes are held in memory only for the duration of the re-wrap and zeroed
     * before this method returns.
     *
     * @param encryptedDek      KMS ciphertext of the DEK (raw bytes from storage); must not be null
     * @param oldKeyVersionId   key version UUID used as context during the original wrap; must not be null
     * @param newKeyVersionId   key version UUID to use as context for the re-wrap; must not be null
     * @return KMS ciphertext of the DEK wrapped under the new key version
     * @throws KmsOperationException if either the decrypt or encrypt KMS call fails
     */
    @Override
    public byte[] rewrapDek(byte[] encryptedDek, String oldKeyVersionId, String newKeyVersionId) {
        byte[] plaintextDek = unwrapDekForVersion(encryptedDek, oldKeyVersionId);
        try {
            return wrapDek(plaintextDek, newKeyVersionId);
        } finally {
            // Plaintext DEK must not persist in memory beyond the re-wrap operation
            Arrays.fill(plaintextDek, (byte) 0);
        }
    }

    /**
     * Retrieves key metadata from AWS KMS using {@code kms:DescribeKey}.
     *
     * <p>Used by the tamper reconciliation job to validate the local {@code key_versions}
     * record against the KMS source of truth.
     *
     * @param kmsKeyId the KMS key ARN or alias to describe; must not be null
     * @return key metadata as reported by AWS KMS
     * @throws KmsOperationException if the KMS call fails or the key does not exist
     */
    @Override
    public KeyMetadata describeKey(String kmsKeyId) {
        try {
            DescribeKeyRequest describeRequest = DescribeKeyRequest.builder()
                    .keyId(kmsKeyId)
                    .build();
            var keyMetadata = kmsClient.describeKey(describeRequest).keyMetadata();
            return new KeyMetadata(
                    keyMetadata.keyId(),
                    keyMetadata.description(),
                    keyMetadata.enabled(),
                    keyMetadata.creationDate()
            );
        } catch (KmsException kmsException) {
            throw new KmsOperationException("AWS KMS describeKey failed for key: " + kmsKeyId, kmsException);
        }
    }

    /**
     * Decrypts a KMS-encrypted DEK using the given key version's encryption context.
     *
     * <p>The caller is responsible for zeroing the returned byte array after use.
     *
     * @param encryptedDek  KMS ciphertext of the DEK
     * @param keyVersionId  the key version UUID that was used as encryption context during wrapping
     * @return plaintext DEK bytes — caller must zero after use
     * @throws KmsOperationException if the KMS call fails
     */
    private byte[] unwrapDekForVersion(byte[] encryptedDek, String keyVersionId) {
        try {
            DecryptRequest decryptRequest = DecryptRequest.builder()
                    .ciphertextBlob(SdkBytes.fromByteArray(encryptedDek))
                    .keyId(masterKeyArn)
                    .encryptionContext(Map.of(
                            ENCRYPTION_CONTEXT_PURPOSE_KEY, ENCRYPTION_CONTEXT_DEK_WRAP_VALUE,
                            ENCRYPTION_CONTEXT_KEY_VERSION_KEY, keyVersionId))
                    .build();
            return kmsClient.decrypt(decryptRequest).plaintext().asByteArray();
        } catch (KmsException kmsException) {
            throw new KmsOperationException(
                    "AWS KMS DEK unwrap failed for key version: " + keyVersionId, kmsException);
        }
    }
}
