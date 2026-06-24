package com.yourorg.tokenisation.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link AesGcmCipher}.
 *
 * <p>No Spring context. No mocks — AES-GCM is a pure JCA operation tested directly.
 * Coverage targets: 95% line coverage on crypto layer per {@code agent-test-standards.md}.
 */
class AesGcmCipherTest {

    private static final byte[] VALID_DEK = new byte[32];
    private static final byte[] VALID_PAN_BYTES = "4111111111111111".getBytes();

    static {
        Arrays.fill(VALID_DEK, (byte) 0xAA);
    }

    private AesGcmCipher cipher;

    @BeforeEach
    void setUp() {
        cipher = new AesGcmCipher();
    }

    // ── encrypt ──────────────────────────────────────────────────────────────

    @Test
    void encrypt_validPanAndDek_returnsNonNullResult() {
        EncryptResult encryptResult = cipher.encrypt(VALID_PAN_BYTES.clone(), VALID_DEK.clone());

        assertThat(encryptResult).isNotNull();
        assertThat(encryptResult.ciphertext()).isNotEmpty();
        assertThat(encryptResult.iv()).hasSize(AesGcmCipher.GCM_IV_LENGTH_BYTES);
        assertThat(encryptResult.authTag()).hasSize(AesGcmCipher.GCM_TAG_LENGTH_BYTES);
    }

    @Test
    void encrypt_calledTwiceWithSamePan_producesDifferentCiphertextDueToFreshIv() {
        EncryptResult firstResult = cipher.encrypt(VALID_PAN_BYTES.clone(), VALID_DEK.clone());
        EncryptResult secondResult = cipher.encrypt(VALID_PAN_BYTES.clone(), VALID_DEK.clone());

        assertThat(firstResult.iv()).isNotEqualTo(secondResult.iv());
        assertThat(firstResult.ciphertext()).isNotEqualTo(secondResult.ciphertext());
    }

    @Test
    void encrypt_nullPan_throwsIllegalArgument() {
        assertThatThrownBy(() -> cipher.encrypt(null, VALID_DEK.clone()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("null or empty");
    }

    @Test
    void encrypt_emptyPan_throwsIllegalArgument() {
        assertThatThrownBy(() -> cipher.encrypt(new byte[0], VALID_DEK.clone()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("null or empty");
    }

    @Test
    void encrypt_nullDek_throwsIllegalArgument() {
        assertThatThrownBy(() -> cipher.encrypt(VALID_PAN_BYTES.clone(), null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("32 bytes");
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 16, 24, 31, 33, 64})
    void encrypt_wrongDekLength_throwsIllegalArgument(int wrongLength) {
        byte[] wrongLengthDek = new byte[wrongLength];
        assertThatThrownBy(() -> cipher.encrypt(VALID_PAN_BYTES.clone(), wrongLengthDek))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("32 bytes");
    }

    // ── decrypt — round-trip ─────────────────────────────────────────────────

    @Test
    void encrypt_thenDecrypt_recoversOriginalPan() {
        EncryptResult encryptResult = cipher.encrypt(VALID_PAN_BYTES.clone(), VALID_DEK.clone());

        byte[] decryptedPan = cipher.decrypt(
                encryptResult.ciphertext(),
                encryptResult.iv(),
                encryptResult.authTag(),
                VALID_DEK.clone()
        );

        assertThat(decryptedPan).isEqualTo(VALID_PAN_BYTES);
    }

    // ── decrypt — tamper detection ────────────────────────────────────────────

    @Test
    void decrypt_ciphertextModified_throwsEncryptionExceptionWithTamperMessage() {
        EncryptResult encryptResult = cipher.encrypt(VALID_PAN_BYTES.clone(), VALID_DEK.clone());
        byte[] tamperedCiphertext = encryptResult.ciphertext().clone();
        tamperedCiphertext[0] ^= 0xFF;

        assertThatThrownBy(() -> cipher.decrypt(
                tamperedCiphertext,
                encryptResult.iv(),
                encryptResult.authTag(),
                VALID_DEK.clone()))
                .isInstanceOf(EncryptionException.class)
                .hasMessageContaining("tampered");
    }

    @Test
    void decrypt_authTagModified_throwsEncryptionException() {
        EncryptResult encryptResult = cipher.encrypt(VALID_PAN_BYTES.clone(), VALID_DEK.clone());
        byte[] tamperedTag = encryptResult.authTag().clone();
        tamperedTag[0] ^= 0xFF;

        assertThatThrownBy(() -> cipher.decrypt(
                encryptResult.ciphertext(),
                encryptResult.iv(),
                tamperedTag,
                VALID_DEK.clone()))
                .isInstanceOf(EncryptionException.class)
                .hasMessageContaining("tampered");
    }

    @Test
    void decrypt_wrongDek_throwsEncryptionException() {
        EncryptResult encryptResult = cipher.encrypt(VALID_PAN_BYTES.clone(), VALID_DEK.clone());
        byte[] wrongDek = new byte[32];
        Arrays.fill(wrongDek, (byte) 0xBB);

        assertThatThrownBy(() -> cipher.decrypt(
                encryptResult.ciphertext(),
                encryptResult.iv(),
                encryptResult.authTag(),
                wrongDek))
                .isInstanceOf(EncryptionException.class);
    }

    @Test
    void decrypt_nullIv_throwsIllegalArgument() {
        EncryptResult encryptResult = cipher.encrypt(VALID_PAN_BYTES.clone(), VALID_DEK.clone());

        assertThatThrownBy(() -> cipher.decrypt(
                encryptResult.ciphertext(), null, encryptResult.authTag(), VALID_DEK.clone()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("12 bytes");
    }

    @Test
    void decrypt_wrongIvLength_throwsIllegalArgument() {
        EncryptResult encryptResult = cipher.encrypt(VALID_PAN_BYTES.clone(), VALID_DEK.clone());
        byte[] wrongIv = new byte[8];

        assertThatThrownBy(() -> cipher.decrypt(
                encryptResult.ciphertext(), wrongIv, encryptResult.authTag(), VALID_DEK.clone()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("12 bytes");
    }

    // ── EncryptResult structural invariants ──────────────────────────────────

    @Test
    void encryptResult_ivIsAlways12Bytes() {
        EncryptResult encryptResult = cipher.encrypt(VALID_PAN_BYTES.clone(), VALID_DEK.clone());
        assertThat(encryptResult.iv()).hasSize(12);
    }

    @Test
    void encryptResult_authTagIsAlways16Bytes() {
        EncryptResult encryptResult = cipher.encrypt(VALID_PAN_BYTES.clone(), VALID_DEK.clone());
        assertThat(encryptResult.authTag()).hasSize(16);
    }
}
