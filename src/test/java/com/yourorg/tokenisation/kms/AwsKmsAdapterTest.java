package com.yourorg.tokenisation.kms;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.DescribeKeyRequest;
import software.amazon.awssdk.services.kms.model.DescribeKeyResponse;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptResponse;
import software.amazon.awssdk.services.kms.model.KmsException;
import software.amazon.awssdk.services.kms.model.KeyMetadata;

import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;

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
    private static final byte[] PLAINTEXT_KEK = new byte[32];
    private static final byte[] PLAINTEXT_DEK = new byte[32];
    private static final byte[] MOCK_CIPHERTEXT = new byte[]{0x01, 0x02, 0x03, 0x04};

    static {
        Arrays.fill(PLAINTEXT_KEK, (byte) 0xAA);
        Arrays.fill(PLAINTEXT_DEK, (byte) 0xBB);
    }

    @Mock
    private KmsClient kmsClient;

    private AwsKmsAdapter adapter;

    @BeforeEach
    void setUp() {
        adapter = new AwsKmsAdapter(kmsClient, MASTER_KEY_ARN);
    }

    // ── unwrapKek ────────────────────────────────────────────────────────────

    @Test
    void unwrapKek_validBlob_callsKmsDecryptAndReturnsPlaintext() {
        byte[] encryptedKekBytes = new byte[]{0x10, 0x20, 0x30};
        String encryptedKekBlob = Base64.getEncoder().encodeToString(encryptedKekBytes);
        stubDecryptResponse(PLAINTEXT_KEK);

        byte[] returnedKek = adapter.unwrapKek(encryptedKekBlob);

        assertThat(returnedKek).isEqualTo(PLAINTEXT_KEK);
        ArgumentCaptor<DecryptRequest> requestCaptor = ArgumentCaptor.forClass(DecryptRequest.class);
        verify(kmsClient).decrypt(requestCaptor.capture());
        DecryptRequest sentRequest = requestCaptor.getValue();
        assertThat(sentRequest.keyId()).isEqualTo(MASTER_KEY_ARN);
        assertThat(sentRequest.encryptionContext()).containsKey("purpose");
        assertThat(sentRequest.encryptionContext().get("purpose")).isEqualTo("kek-unwrap");
    }

    @Test
    void unwrapKek_blankBlob_throwsIllegalArgument() {
        assertThatThrownBy(() -> adapter.unwrapKek("   "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("null or blank");
    }

    @Test
    void unwrapKek_nullBlob_throwsIllegalArgument() {
        assertThatThrownBy(() -> adapter.unwrapKek(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void unwrapKek_kmsException_throwsKmsOperationException() {
        String validBlob = Base64.getEncoder().encodeToString(new byte[]{0x01});
        when(kmsClient.decrypt(any(DecryptRequest.class)))
                .thenThrow(KmsException.builder().message("AccessDenied").build());

        assertThatThrownBy(() -> adapter.unwrapKek(validBlob))
                .isInstanceOf(KmsOperationException.class)
                .hasMessageContaining("KEK unwrap failed");
    }

    // ── wrapDek ──────────────────────────────────────────────────────────────

    @Test
    void wrapDek_validDek_callsKmsEncryptWithCorrectContext() {
        stubEncryptResponse(MOCK_CIPHERTEXT);

        byte[] wrappedDek = adapter.wrapDek(PLAINTEXT_DEK.clone(), "version-123");

        assertThat(wrappedDek).isEqualTo(MOCK_CIPHERTEXT);
        ArgumentCaptor<EncryptRequest> requestCaptor = ArgumentCaptor.forClass(EncryptRequest.class);
        verify(kmsClient).encrypt(requestCaptor.capture());
        EncryptRequest sentRequest = requestCaptor.getValue();
        assertThat(sentRequest.keyId()).isEqualTo(MASTER_KEY_ARN);
        assertThat(sentRequest.encryptionContext()).containsEntry("purpose", "dek-wrap");
        assertThat(sentRequest.encryptionContext()).containsEntry("keyVersionId", "version-123");
    }

    @Test
    void wrapDek_nullDek_throwsIllegalArgument() {
        assertThatThrownBy(() -> adapter.wrapDek(null, "version-1"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("32 bytes");
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 16, 24, 31, 33, 64})
    void wrapDek_wrongDekLength_throwsIllegalArgument(int wrongLength) {
        byte[] wrongSizeDek = new byte[wrongLength];
        assertThatThrownBy(() -> adapter.wrapDek(wrongSizeDek, "version-1"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("32 bytes");
    }

    @Test
    void wrapDek_kmsException_throwsKmsOperationException() {
        when(kmsClient.encrypt(any(EncryptRequest.class)))
                .thenThrow(KmsException.builder().message("InvalidKeyUsage").build());

        assertThatThrownBy(() -> adapter.wrapDek(PLAINTEXT_DEK.clone(), "version-1"))
                .isInstanceOf(KmsOperationException.class)
                .hasMessageContaining("DEK wrap failed");
    }

    // ── rewrapDek ────────────────────────────────────────────────────────────

    @Test
    void rewrapDek_validDek_decryptsUnderOldVersionThenEncryptsUnderNew() {
        byte[] existingEncryptedDek = new byte[]{0x55, 0x66};
        stubDecryptResponse(PLAINTEXT_DEK);
        stubEncryptResponse(MOCK_CIPHERTEXT);

        byte[] rewrapped = adapter.rewrapDek(existingEncryptedDek, "old-version", "new-version");

        assertThat(rewrapped).isEqualTo(MOCK_CIPHERTEXT);
        // Verify decrypt was called with old-version context
        ArgumentCaptor<DecryptRequest> decryptCaptor = ArgumentCaptor.forClass(DecryptRequest.class);
        verify(kmsClient).decrypt(decryptCaptor.capture());
        assertThat(decryptCaptor.getValue().encryptionContext()).containsEntry("keyVersionId", "old-version");
        // Verify encrypt was called with new-version context
        ArgumentCaptor<EncryptRequest> encryptCaptor = ArgumentCaptor.forClass(EncryptRequest.class);
        verify(kmsClient).encrypt(encryptCaptor.capture());
        assertThat(encryptCaptor.getValue().encryptionContext()).containsEntry("keyVersionId", "new-version");
    }

    @Test
    void rewrapDek_kmsDecryptFails_throwsKmsOperationException() {
        when(kmsClient.decrypt(any(DecryptRequest.class)))
                .thenThrow(KmsException.builder().message("DisabledException").build());

        assertThatThrownBy(() -> adapter.rewrapDek(new byte[]{0x01}, "old-version", "new-version"))
                .isInstanceOf(KmsOperationException.class)
                .hasMessageContaining("DEK unwrap failed");
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
