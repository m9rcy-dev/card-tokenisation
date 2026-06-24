package com.yourorg.tokenisation.kms;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;
import software.amazon.awssdk.services.kms.model.KeyMetadata;

import java.time.Instant;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link AwsKmsAdapter}.
 *
 * <p>All AWS KMS calls are mocked — no real credentials or network access required.
 * Tests verify that the adapter sends correctly structured requests to KMS and
 * handles KMS exceptions by wrapping them in {@link KmsOperationException}.
 */
@ExtendWith(MockitoExtension.class)
class AwsKmsAdapterTest {

    private static final String MASTER_KEY_ARN = "arn:aws:kms:ap-southeast-2:123456789:key/test-key";
    private static final byte[] PLAINTEXT_DEK  = new byte[32];
    private static final byte[] MOCK_CIPHERTEXT = new byte[]{0x01, 0x02, 0x03, 0x04};

    static {
        Arrays.fill(PLAINTEXT_DEK, (byte) 0xBB);
    }

    @Mock
    private KmsClient kmsClient;

    private AwsKmsAdapter adapter;

    @BeforeEach
    void setUp() {
        adapter = new AwsKmsAdapter(kmsClient, MASTER_KEY_ARN);
    }

    // ── generateDataKey ───────────────────────────────────────────────────────

    @Test
    void generateDataKey_callsKmsGenerateDataKeyAndReturnsDataKey() {
        stubGenerateDataKeyResponse(PLAINTEXT_DEK, MOCK_CIPHERTEXT);

        DataKey result = adapter.generateDataKey();

        assertThat(result.plaintextDek()).isEqualTo(PLAINTEXT_DEK);
        assertThat(result.encryptedDekBlob()).isEqualTo(MOCK_CIPHERTEXT);
        ArgumentCaptor<GenerateDataKeyRequest> requestCaptor =
                ArgumentCaptor.forClass(GenerateDataKeyRequest.class);
        verify(kmsClient).generateDataKey(requestCaptor.capture());
        GenerateDataKeyRequest sentRequest = requestCaptor.getValue();
        assertThat(sentRequest.keyId()).isEqualTo(MASTER_KEY_ARN);
        assertThat(sentRequest.keySpec()).isEqualTo(DataKeySpec.AES_256);
        assertThat(sentRequest.encryptionContext()).containsEntry("purpose", "data-key");
    }

    @Test
    void generateDataKey_kmsException_throwsKmsOperationException() {
        when(kmsClient.generateDataKey(any(GenerateDataKeyRequest.class)))
                .thenThrow(KmsException.builder().message("AccessDenied").build());

        assertThatThrownBy(() -> adapter.generateDataKey())
                .isInstanceOf(KmsOperationException.class)
                .hasMessageContaining("GenerateDataKey failed");
    }

    // ── decryptDataKey ────────────────────────────────────────────────────────

    @Test
    void decryptDataKey_validBlob_callsKmsDecryptAndReturnsPlaintext() {
        stubDecryptResponse(PLAINTEXT_DEK);

        byte[] result = adapter.decryptDataKey(MOCK_CIPHERTEXT);

        assertThat(result).isEqualTo(PLAINTEXT_DEK);
        ArgumentCaptor<DecryptRequest> requestCaptor = ArgumentCaptor.forClass(DecryptRequest.class);
        verify(kmsClient).decrypt(requestCaptor.capture());
        DecryptRequest sentRequest = requestCaptor.getValue();
        assertThat(sentRequest.keyId()).isEqualTo(MASTER_KEY_ARN);
        assertThat(sentRequest.encryptionContext()).containsEntry("purpose", "data-key");
    }

    @Test
    void decryptDataKey_kmsException_throwsKmsOperationException() {
        when(kmsClient.decrypt(any(DecryptRequest.class)))
                .thenThrow(KmsException.builder().message("AccessDenied").build());

        assertThatThrownBy(() -> adapter.decryptDataKey(MOCK_CIPHERTEXT))
                .isInstanceOf(KmsOperationException.class)
                .hasMessageContaining("DEK decrypt failed");
    }

    @Test
    void decryptDataKey_nullBlob_throwsIllegalArgument() {
        assertThatThrownBy(() -> adapter.decryptDataKey(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    // ── wrapNewHmacKey ────────────────────────────────────────────────────────

    @Test
    void wrapNewHmacKey_validKey_callsKmsEncryptWithHmacContext() {
        stubEncryptResponse(MOCK_CIPHERTEXT);
        byte[] hmacKey = new byte[32];

        byte[] wrappedKey = adapter.wrapNewHmacKey(hmacKey);

        assertThat(wrappedKey).isEqualTo(MOCK_CIPHERTEXT);
        ArgumentCaptor<EncryptRequest> requestCaptor = ArgumentCaptor.forClass(EncryptRequest.class);
        verify(kmsClient).encrypt(requestCaptor.capture());
        EncryptRequest sentRequest = requestCaptor.getValue();
        assertThat(sentRequest.keyId()).isEqualTo(MASTER_KEY_ARN);
        assertThat(sentRequest.encryptionContext()).containsEntry("purpose", "hmac-key");
    }

    @Test
    void wrapNewHmacKey_kmsException_throwsKmsOperationException() {
        when(kmsClient.encrypt(any(EncryptRequest.class)))
                .thenThrow(KmsException.builder().message("InvalidKeyUsage").build());

        assertThatThrownBy(() -> adapter.wrapNewHmacKey(new byte[32]))
                .isInstanceOf(KmsOperationException.class);
    }

    // ── unwrapHmacKey ─────────────────────────────────────────────────────────

    @Test
    void unwrapHmacKey_validBlob_callsKmsDecryptWithHmacContext() {
        stubDecryptResponse(PLAINTEXT_DEK);

        byte[] result = adapter.unwrapHmacKey(MOCK_CIPHERTEXT);

        assertThat(result).isEqualTo(PLAINTEXT_DEK);
        ArgumentCaptor<DecryptRequest> requestCaptor = ArgumentCaptor.forClass(DecryptRequest.class);
        verify(kmsClient).decrypt(requestCaptor.capture());
        assertThat(requestCaptor.getValue().encryptionContext()).containsEntry("purpose", "hmac-key");
    }

    // ── describeKey ──────────────────────────────────────────────────────────

    @Test
    void describeKey_validKeyId_returnsKeyMetadata() {
        Instant keyCreatedAt = Instant.parse("2025-01-01T00:00:00Z");
        stubDescribeKeyResponse("test-alias", true, keyCreatedAt);

        com.yourorg.tokenisation.kms.KeyMetadata metadata = adapter.describeKey(MASTER_KEY_ARN);

        assertThat(metadata.enabled()).isTrue();
        assertThat(metadata.keyAlias()).isEqualTo("test-alias");
        assertThat(metadata.createdAt()).isEqualTo(keyCreatedAt);
        ArgumentCaptor<DescribeKeyRequest> requestCaptor = ArgumentCaptor.forClass(DescribeKeyRequest.class);
        verify(kmsClient).describeKey(requestCaptor.capture());
        assertThat(requestCaptor.getValue().keyId()).isEqualTo(MASTER_KEY_ARN);
    }

    @Test
    void describeKey_kmsException_throwsKmsOperationException() {
        when(kmsClient.describeKey(any(DescribeKeyRequest.class)))
                .thenThrow(KmsException.builder().message("NotFoundException").build());

        assertThatThrownBy(() -> adapter.describeKey("nonexistent-key"))
                .isInstanceOf(KmsOperationException.class)
                .hasMessageContaining("describeKey failed");
    }

    // ── Test helpers ─────────────────────────────────────────────────────────

    private void stubGenerateDataKeyResponse(byte[] plaintext, byte[] ciphertext) {
        when(kmsClient.generateDataKey(any(GenerateDataKeyRequest.class)))
                .thenReturn(GenerateDataKeyResponse.builder()
                        .plaintext(SdkBytes.fromByteArray(plaintext))
                        .ciphertextBlob(SdkBytes.fromByteArray(ciphertext))
                        .build());
    }

    private void stubDecryptResponse(byte[] plaintext) {
        when(kmsClient.decrypt(any(DecryptRequest.class)))
                .thenReturn(DecryptResponse.builder()
                        .plaintext(SdkBytes.fromByteArray(plaintext))
                        .build());
    }

    private void stubEncryptResponse(byte[] ciphertext) {
        when(kmsClient.encrypt(any(EncryptRequest.class)))
                .thenReturn(EncryptResponse.builder()
                        .ciphertextBlob(SdkBytes.fromByteArray(ciphertext))
                        .build());
    }

    private void stubDescribeKeyResponse(String alias, boolean enabled, Instant createdAt) {
        when(kmsClient.describeKey(any(DescribeKeyRequest.class)))
                .thenReturn(DescribeKeyResponse.builder()
                        .keyMetadata(KeyMetadata.builder()
                                .keyId(MASTER_KEY_ARN)
                                .description(alias)
                                .enabled(enabled)
                                .creationDate(createdAt)
                                .build())
                        .build());
    }
}
