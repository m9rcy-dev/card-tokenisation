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

    private static final byte[] VALID_KEK = new byte[32];
    private static final byte[] VALID_PAN_BYTES = "4111111111111111".getBytes();

    static {
        Arrays.fill(VALID_KEK, (byte) 0xAA);
    }

    private AesGcmCipher cipher;

    @BeforeEach
    void setUp() {
        cipher = new AesGcmCipher();
    }

    // ── encrypt ──────────────────────────────────────────────────────────────

    @Test
    void encrypt_validPanAndKek_returnsNonNullResult() {
        EncryptResult encryptResult = cipher.encrypt(VALID_PAN_BYTES.clone(), VALID_KEK.clone());

        assertThat(encryptResult).isNotNull();
        assertThat(encryptResult.ciphertext()).isNotEmpty();
        assertThat(encryptResult.iv()).hasSize(AesGcmCipher.GCM_IV_LENGTH_BYTES);
        assertThat(encryptResult.authTag()).hasSize(AesGcmCipher.GCM_TAG_LENGTH_BYTES);
        assertThat(encryptResult.encryptedDek()).isNotEmpty();
    }

    @Test
    void encrypt_calledTwiceWithSamePan_producesDifferentCiphertextDueToFreshIv() {
        EncryptResult firstResult = cipher.encrypt(VALID_PAN_BYTES.clone(), VALID_KEK.clone());
        EncryptResult secondResult = cipher.encrypt(VALID_PAN_BYTES.clone(), VALID_KEK.clone());

        assertThat(firstResult.iv()).isNotEqualTo(secondResult.iv());
        assertThat(firstResult.ciphertext()).isNotEqualTo(secondResult.ciphertext());
    }

    @Test
    void encrypt_nullPan_throwsIllegalArgument() {
        assertThatThrownBy(() -> cipher.encrypt(null, VALID_KEK.clone()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("null or empty");
    }

    @Test
    void encrypt_emptyPan_throwsIllegalArgument() {
        assertThatThrownBy(() -> cipher.encrypt(new byte[0], VALID_KEK.clone()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("null or empty");
    }

    @Test
    void encrypt_nullKek_throwsIllegalArgument() {
        assertThatThrownBy(() -> cipher.encrypt(VALID_PAN_BYTES.clone(), null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("32 bytes");
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 16, 24, 31, 33, 64})
    void encrypt_wrongKekLength_throwsIllegalArgument(int wrongLength) {
        byte[] wrongLengthKek = new byte[wrongLength];
        assertThatThrownBy(() -> cipher.encrypt(VALID_PAN_BYTES.clone(), wrongLengthKek))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("32 bytes");
    }

    // ── decrypt — round-trip ─────────────────────────────────────────────────

    @Test
    void encrypt_thenDecrypt_recoversOriginalPan() {
        EncryptResult encryptResult = cipher.encrypt(VALID_PAN_BYTES.clone(), VALID_KEK.clone());

        byte[] decryptedPan = cipher.decrypt(
                encryptResult.ciphertext(),
                encryptResult.iv(),
                encryptResult.authTag(),
                encryptResult.encryptedDek(),
                VALID_KEK.clone()
        );

        assertThat(decryptedPan).isEqualTo(VALID_PAN_BYTES);
    }

    // ── decrypt — tamper detection ────────────────────────────────────────────

    @Test
    void decrypt_ciphertextModified_throwsEncryptionExceptionWithTamperMessage() {
        EncryptResult encryptResult = cipher.encrypt(VALID_PAN_BYTES.clone(), VALID_KEK.clone());
        byte[] tamperedCiphertext = encryptResult.ciphertext().clone();
        tamperedCiphertext[0] ^= 0xFF;  // flip bits in first byte

        assertThatThrownBy(() -> cipher.decrypt(
                tamperedCiphertext,
                encryptResult.iv(),
                encryptResult.authTag(),
                encryptResult.encryptedDek(),
                VALID_KEK.clone()))
                .isInstanceOf(EncryptionException.class)
                .hasMessageContaining("tampered");
    }

    @Test
    void decrypt_authTagModified_throwsEncryptionException() {
        EncryptResult encryptResult = cipher.encrypt(VALID_PAN_BYTES.clone(), VALID_KEK.clone());
        byte[] tamperedTag = encryptResult.authTag().clone();
        tamperedTag[0] ^= 0xFF;

        assertThatThrownBy(() -> cipher.decrypt(
                encryptResult.ciphertext(),
                encryptResult.iv(),
                tamperedTag,
                encryptResult.encryptedDek(),
                VALID_KEK.clone()))
                .isInstanceOf(EncryptionException.class)
                .hasMessageContaining("tampered");
    }

    @Test
    void decrypt_wrongKek_throwsEncryptionException() {
        EncryptResult encryptResult = cipher.encrypt(VALID_PAN_BYTES.clone(), VALID_KEK.clone());
        byte[] wrongKek = new byte[32];
        Arrays.fill(wrongKek, (byte) 0xBB);

        assertThatThrownBy(() -> cipher.decrypt(
                encryptResult.ciphertext(),
                encryptResult.iv(),
                encryptResult.authTag(),
                encryptResult.encryptedDek(),
                wrongKek))
                .isInstanceOf(EncryptionException.class);
    }

    @Test
    void decrypt_nullIv_throwsIllegalArgument() {
        EncryptResult encryptResult = cipher.encrypt(VALID_PAN_BYTES.clone(), VALID_KEK.clone());

        assertThatThrownBy(() -> cipher.decrypt(
                encryptResult.ciphertext(), null, encryptResult.authTag(),
                encryptResult.encryptedDek(), VALID_KEK.clone()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("12 bytes");
    }

    @Test
    void decrypt_wrongIvLength_throwsIllegalArgument() {
        EncryptResult encryptResult = cipher.encrypt(VALID_PAN_BYTES.clone(), VALID_KEK.clone());
        byte[] wrongIv = new byte[8];

        assertThatThrownBy(() -> cipher.decrypt(
                encryptResult.ciphertext(), wrongIv, encryptResult.authTag(),
                encryptResult.encryptedDek(), VALID_KEK.clone()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("12 bytes");
    }

    // ── wrapDek / unwrapDek ───────────────────────────────────────────────────

    @Test
    void wrapDek_thenUnwrapDek_recoversOriginalDek() {
        byte[] plaintextDek = new byte[32];
        Arrays.fill(plaintextDek, (byte) 0xCC);

        byte[] wrappedDek = cipher.wrapDek(plaintextDek.clone(), VALID_KEK.clone());
        byte[] unwrappedDek = cipher.unwrapDek(wrappedDek, VALID_KEK.clone());

        assertThat(unwrappedDek).isEqualTo(plaintextDek);
    }

    @Test
    void wrapDek_calledTwice_producesDistinctWrappedBlobs() {
        byte[] plaintextDek = new byte[32];

        byte[] firstWrapped = cipher.wrapDek(plaintextDek.clone(), VALID_KEK.clone());
        byte[] secondWrapped = cipher.wrapDek(plaintextDek.clone(), VALID_KEK.clone());

        assertThat(firstWrapped).isNotEqualTo(secondWrapped);
    }

    @Test
    void wrapDek_nullDek_throwsIllegalArgument() {
        assertThatThrownBy(() -> cipher.wrapDek(null, VALID_KEK.clone()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("32 bytes");
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 16, 24, 31, 33})
    void wrapDek_wrongDekLength_throwsIllegalArgument(int wrongLength) {
        byte[] wrongDek = new byte[wrongLength];
        assertThatThrownBy(() -> cipher.wrapDek(wrongDek, VALID_KEK.clone()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("32 bytes");
    }

    @Test
    void unwrapDek_nullWrappedDek_throwsIllegalArgument() {
        assertThatThrownBy(() -> cipher.unwrapDek(null, VALID_KEK.clone()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("null or too short");
    }

    @Test
    void unwrapDek_tooShortBlob_throwsIllegalArgument() {
        byte[] tooShort = new byte[10];
        assertThatThrownBy(() -> cipher.unwrapDek(tooShort, VALID_KEK.clone()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("null or too short");
    }

    @Test
    void unwrapDek_corruptedBlob_throwsEncryptionException() {
        byte[] corruptedBlob = new byte[60]; // random zeros — not valid GCM ciphertext
        assertThatThrownBy(() -> cipher.unwrapDek(corruptedBlob, VALID_KEK.clone()))
                .isInstanceOf(EncryptionException.class);
    }

    // ── EncryptResult structural invariants ──────────────────────────────────

    @Test
    void encryptResult_ivIsAlways12Bytes() {
        EncryptResult encryptResult = cipher.encrypt(VALID_PAN_BYTES.clone(), VALID_KEK.clone());
        assertThat(encryptResult.iv()).hasSize(12);
    }

    @Test
    void encryptResult_authTagIsAlways16Bytes() {
        EncryptResult encryptResult = cipher.encrypt(VALID_PAN_BYTES.clone(), VALID_KEK.clone());
        assertThat(encryptResult.authTag()).hasSize(16);
    }
}
