package com.yourorg.tokenisation.kms;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link LocalDevKmsAdapter}.
 *
 * <p>No Spring context is loaded. All crypto operations use standard JCA providers
 * available in any JDK — no cloud credentials or network access required.
 */
class LocalDevKmsAdapterTest {

    private static final String VALID_KEK_HEX =
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    private LocalDevKmsAdapter adapter;

    @BeforeEach
    void setUp() {
        adapter = new LocalDevKmsAdapter(VALID_KEK_HEX);
    }

    // ── Constructor ──────────────────────────────────────────────────────────

    @Test
    void constructor_validKekHex_createsAdapterSuccessfully() {
        LocalDevKmsAdapter created = new LocalDevKmsAdapter(VALID_KEK_HEX);
        DataKey dataKey = created.generateDataKey();
        assertThat(dataKey).isNotNull();
    }

    @Test
    void constructor_kekHexNot32Bytes_throwsIllegalArgument() {
        String shortKekHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e";
        assertThatThrownBy(() -> new LocalDevKmsAdapter(shortKekHex))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("32 bytes");
    }

    // ── generateDataKey ───────────────────────────────────────────────────────

    @Test
    void generateDataKey_returnsDataKeyWithPlaintextAndEncryptedBlob() {
        DataKey dataKey = adapter.generateDataKey();

        assertThat(dataKey).isNotNull();
        assertThat(dataKey.plaintextDek()).hasSize(32);
        assertThat(dataKey.encryptedDekBlob()).isNotEmpty();
        // IV (12) + ciphertext (32) + GCM tag (16) = 60 bytes minimum
        assertThat(dataKey.encryptedDekBlob().length).isGreaterThanOrEqualTo(60);
    }

    @Test
    void generateDataKey_calledTwice_producesDifferentPlaintextDeks() {
        DataKey first = adapter.generateDataKey();
        DataKey second = adapter.generateDataKey();

        // Each call generates a new random DEK
        assertThat(first.plaintextDek()).isNotEqualTo(second.plaintextDek());
    }

    @Test
    void generateDataKey_calledTwice_producesDifferentEncryptedBlobs() {
        DataKey first = adapter.generateDataKey();
        DataKey second = adapter.generateDataKey();

        // Different DEK + fresh IV → different blobs
        assertThat(first.encryptedDekBlob()).isNotEqualTo(second.encryptedDekBlob());
    }

    // ── decryptDataKey ────────────────────────────────────────────────────────

    @Test
    void decryptDataKey_blobFromGenerateDataKey_recoversOriginalPlaintextDek() {
        DataKey dataKey = adapter.generateDataKey();
        byte[] originalDek = dataKey.plaintextDek().clone();
        byte[] encryptedBlob = dataKey.encryptedDekBlob();

        byte[] recovered = adapter.decryptDataKey(encryptedBlob);

        assertThat(recovered).isEqualTo(originalDek);
    }

    @Test
    void decryptDataKey_returnsCopy_notSameArrayReference() {
        DataKey dataKey = adapter.generateDataKey();
        byte[] encryptedBlob = dataKey.encryptedDekBlob();

        byte[] firstDecrypt = adapter.decryptDataKey(encryptedBlob);
        byte[] secondDecrypt = adapter.decryptDataKey(encryptedBlob);

        firstDecrypt[0] = (byte) 0xFF;
        assertThat(secondDecrypt[0]).isNotEqualTo((byte) 0xFF);
    }

    @Test
    void decryptDataKey_nullBlob_throwsIllegalArgument() {
        assertThatThrownBy(() -> adapter.decryptDataKey(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void decryptDataKey_corruptedBlob_throwsKmsOperationException() {
        byte[] corruptedBlob = new byte[60]; // random zeros — not valid GCM ciphertext
        assertThatThrownBy(() -> adapter.decryptDataKey(corruptedBlob))
                .isInstanceOf(KmsOperationException.class);
    }

    // ── wrapNewHmacKey / unwrapHmacKey ────────────────────────────────────────

    @Test
    void wrapNewHmacKey_validKey_returnsNonEmptyBlob() {
        byte[] hmacKey = new byte[32];
        Arrays.fill(hmacKey, (byte) 0xCC);

        byte[] wrapped = adapter.wrapNewHmacKey(hmacKey);

        assertThat(wrapped).isNotEmpty();
        assertThat(wrapped.length).isGreaterThanOrEqualTo(60);
    }

    @Test
    void wrapAndUnwrapHmacKey_roundTrip_recoversOriginalKey() {
        byte[] originalKey = new byte[32];
        Arrays.fill(originalKey, (byte) 0xDD);

        byte[] wrapped = adapter.wrapNewHmacKey(originalKey.clone());
        byte[] recovered = adapter.unwrapHmacKey(wrapped);

        assertThat(recovered).isEqualTo(originalKey);
    }

    @Test
    void wrapNewHmacKey_nullKey_throwsIllegalArgument() {
        assertThatThrownBy(() -> adapter.wrapNewHmacKey(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void unwrapHmacKey_nullBlob_throwsIllegalArgument() {
        assertThatThrownBy(() -> adapter.unwrapHmacKey(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    // ── describeKey ──────────────────────────────────────────────────────────

    @Test
    void describeKey_anyKeyId_returnsSyntheticMetadata() {
        KeyMetadata metadata = adapter.describeKey("any-key-id");

        assertThat(metadata).isNotNull();
        assertThat(metadata.enabled()).isTrue();
        assertThat(metadata.kmsKeyId()).isEqualTo("local-dev-key");
    }
}
