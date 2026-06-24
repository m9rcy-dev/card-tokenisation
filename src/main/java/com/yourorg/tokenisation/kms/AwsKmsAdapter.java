package com.yourorg.tokenisation.kms;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DataKeySpec;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DescribeKeyRequest;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest;
import software.amazon.awssdk.services.kms.model.KmsException;

import java.util.Map;

/**
 * AWS KMS adapter — implements {@link KmsProvider} using the AWS SDK v2 KMS client.
 *
 * <p>Activated when {@code kms.provider=aws}. Uses the master key ARN from
 * {@code kms.aws.master-key-arn} for all operations.
 *
 * <p>KMS call profile:
 * <ul>
 *   <li>{@link #generateDataKey} — called once per rotation event (not per tokenisation)
 *   <li>{@link #decryptDataKey} — called once per active/rotating DEK version at startup
 *   <li>Normal tokenisation uses the in-memory DEK from the ring — zero KMS calls
 * </ul>
 */
@Component
@ConditionalOnProperty(name = "kms.provider", havingValue = "aws")
@Slf4j
public class AwsKmsAdapter implements KmsProvider {

    private static final String ENCRYPTION_CONTEXT_PURPOSE_KEY = "purpose";
    private static final String ENCRYPTION_CONTEXT_DATA_KEY_VALUE = "data-key";
    private static final String ENCRYPTION_CONTEXT_HMAC_KEY_VALUE = "hmac-key";

    private final KmsClient kmsClient;
    private final String masterKeyArn;

    public AwsKmsAdapter(KmsClient kmsClient,
                         @Value("${kms.aws.master-key-arn}") String masterKeyArn) {
        this.kmsClient = kmsClient;
        this.masterKeyArn = masterKeyArn;
    }

    /**
     * Generates a new AES-256 DEK via AWS KMS {@code GenerateDataKey}.
     *
     * <p>Returns both plaintext and ciphertext in one atomic call — saves one round-trip
     * compared to a separate Generate + Encrypt sequence. The encrypted blob is stored
     * in {@code key_versions.encrypted_dek_blob}; the plaintext is loaded into the ring
     * and must be zeroed by the caller after loading.
     */
    @Override
    public DataKey generateDataKey() {
        try {
            var response = kmsClient.generateDataKey(GenerateDataKeyRequest.builder()
                    .keyId(masterKeyArn)
                    .keySpec(DataKeySpec.AES_256)
                    .encryptionContext(Map.of(ENCRYPTION_CONTEXT_PURPOSE_KEY, ENCRYPTION_CONTEXT_DATA_KEY_VALUE))
                    .build());
            log.info("Generated new DEK via AWS KMS GenerateDataKey — context: purpose=data-key");
            return new DataKey(
                    response.plaintext().asByteArray(),
                    response.ciphertextBlob().asByteArray());
        } catch (KmsException e) {
            throw new KmsOperationException("AWS KMS GenerateDataKey failed", e);
        }
    }

    /**
     * Decrypts a stored DEK ciphertext blob using AWS KMS {@code Decrypt}.
     *
     * <p>Called once per active/rotating DEK version at startup. Asserts encryption context
     * {@code purpose=data-key} to prevent cross-context decryption.
     *
     * @param encryptedDekBlob raw KMS ciphertext from {@code key_versions.encrypted_dek_blob}; must not be null
     * @return raw 32-byte DEK; caller must zero after loading into the ring
     */
    @Override
    public byte[] decryptDataKey(byte[] encryptedDekBlob) {
        if (encryptedDekBlob == null) {
            throw new IllegalArgumentException("encryptedDekBlob must not be null");
        }
        try {
            var response = kmsClient.decrypt(DecryptRequest.builder()
                    .ciphertextBlob(SdkBytes.fromByteArray(encryptedDekBlob))
                    .keyId(masterKeyArn)
                    .encryptionContext(Map.of(ENCRYPTION_CONTEXT_PURPOSE_KEY, ENCRYPTION_CONTEXT_DATA_KEY_VALUE))
                    .build());
            log.info("Decrypted DEK from AWS KMS — context: purpose=data-key");
            return response.plaintext().asByteArray();
        } catch (KmsException e) {
            throw new KmsOperationException("AWS KMS DEK decrypt failed", e);
        }
    }

    /**
     * Encrypts a freshly generated HMAC secret under the AWS KMS master key.
     *
     * <p>Uses encryption context {@code purpose=hmac-key} — distinct from {@code purpose=data-key}.
     */
    @Override
    public byte[] wrapNewHmacKey(byte[] plaintextHmacKey) {
        if (plaintextHmacKey == null) {
            throw new IllegalArgumentException("plaintextHmacKey must not be null");
        }
        try {
            var response = kmsClient.encrypt(EncryptRequest.builder()
                    .keyId(masterKeyArn)
                    .plaintext(SdkBytes.fromByteArray(plaintextHmacKey))
                    .encryptionContext(Map.of(ENCRYPTION_CONTEXT_PURPOSE_KEY, ENCRYPTION_CONTEXT_HMAC_KEY_VALUE))
                    .build());
            return response.ciphertextBlob().asByteArray();
        } catch (KmsException e) {
            throw new KmsOperationException("AWS KMS HMAC key wrap failed", e);
        }
    }

    /**
     * Decrypts a stored HMAC secret blob using AWS KMS.
     *
     * <p>Asserts encryption context {@code purpose=hmac-key}.
     */
    @Override
    public byte[] unwrapHmacKey(byte[] encryptedHmacBlob) {
        if (encryptedHmacBlob == null) {
            throw new IllegalArgumentException("encryptedHmacBlob must not be null");
        }
        try {
            var response = kmsClient.decrypt(DecryptRequest.builder()
                    .ciphertextBlob(SdkBytes.fromByteArray(encryptedHmacBlob))
                    .keyId(masterKeyArn)
                    .encryptionContext(Map.of(ENCRYPTION_CONTEXT_PURPOSE_KEY, ENCRYPTION_CONTEXT_HMAC_KEY_VALUE))
                    .build());
            log.info("Unwrapping HMAC key from AWS KMS — context: purpose=hmac-key");
            return response.plaintext().asByteArray();
        } catch (KmsException e) {
            throw new KmsOperationException("AWS KMS HMAC key unwrap failed", e);
        }
    }

    /**
     * Retrieves key metadata from AWS KMS using {@code kms:DescribeKey}.
     */
    @Override
    public KeyMetadata describeKey(String kmsKeyId) {
        try {
            var keyMetadata = kmsClient.describeKey(DescribeKeyRequest.builder()
                    .keyId(kmsKeyId)
                    .build()).keyMetadata();
            return new KeyMetadata(
                    keyMetadata.keyId(),
                    keyMetadata.description(),
                    keyMetadata.enabled(),
                    keyMetadata.creationDate());
        } catch (KmsException e) {
            throw new KmsOperationException("AWS KMS describeKey failed for key: " + kmsKeyId, e);
        }
    }
}
