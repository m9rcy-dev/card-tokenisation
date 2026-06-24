package com.yourorg.tokenisation.kms;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * Local development KMS adapter — uses a fixed AES-256 key from configuration.
 *
 * <p><strong>This adapter must never be used in production.</strong>
 * It is activated only when {@code kms.provider=local-dev}, which should be set
 * exclusively in {@code application-local.yml} and {@code application-test.yml}.
 *
 * <p>DEK generation and decryption are performed locally using AES-256-GCM — no network
 * calls, no cloud credentials required. This makes all integration tests hermetic.
 */
@Component
@ConditionalOnProperty(name = "kms.provider", havingValue = "local-dev")
@Slf4j
public class LocalDevKmsAdapter implements KmsProvider {

    private static final int GCM_IV_LENGTH_BYTES = 12;
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final String AES_GCM_ALGORITHM = "AES/GCM/NoPadding";

    private final byte[] localKek;
    private final SecureRandom secureRandom;

    public LocalDevKmsAdapter(
            @org.springframework.beans.factory.annotation.Value("${kms.local-dev.kek-hex}") String kekHex) {
        byte[] decodedKek = HexFormat.of().parseHex(kekHex);
        if (decodedKek.length != 32) {
            throw new IllegalArgumentException(
                    "Local dev KEK must be exactly 32 bytes (64 hex chars); got " + decodedKek.length + " bytes");
        }
        this.localKek = decodedKek;
        this.secureRandom = new SecureRandom();
        log.warn("LocalDevKmsAdapter active — suitable for development and testing ONLY, never production");
    }

    /**
     * Generates a new DEK by creating 32 random bytes and encrypting them with the local KEK.
     *
     * <p>The plaintext DEK must be zeroed by the caller after loading into the ring.
     * The encrypted blob is an IV-prefixed AES-GCM ciphertext, suitable for BYTEA storage.
     */
    @Override
    public DataKey generateDataKey() {
        byte[] plaintextDek = new byte[32];
        secureRandom.nextBytes(plaintextDek);
        byte[] encryptedBlob = encryptWithLocalKek(plaintextDek);
        return new DataKey(plaintextDek, encryptedBlob);
    }

    /**
     * Decrypts an IV-prefixed AES-256-GCM DEK blob using the local fixed KEK.
     *
     * @param encryptedDekBlob IV-prefixed GCM ciphertext; must not be null
     * @return plaintext 32-byte DEK; caller must zero after use
     */
    @Override
    public byte[] decryptDataKey(byte[] encryptedDekBlob) {
        if (encryptedDekBlob == null) {
            throw new IllegalArgumentException("encryptedDekBlob must not be null");
        }
        return decryptWithLocalKek(encryptedDekBlob);
    }

    /**
     * Encrypts an HMAC secret using AES-256-GCM with the local fixed KEK.
     */
    @Override
    public byte[] wrapNewHmacKey(byte[] plaintextHmacKey) {
        if (plaintextHmacKey == null) {
            throw new IllegalArgumentException("plaintextHmacKey must not be null");
        }
        return encryptWithLocalKek(plaintextHmacKey);
    }

    /**
     * Decrypts an IV-prefixed AES-256-GCM HMAC secret blob using the local fixed KEK.
     */
    @Override
    public byte[] unwrapHmacKey(byte[] encryptedHmacBlob) {
        if (encryptedHmacBlob == null) {
            throw new IllegalArgumentException("encryptedHmacBlob must not be null");
        }
        return decryptWithLocalKek(encryptedHmacBlob);
    }

    /**
     * Returns stub metadata for the local dev key.
     */
    @Override
    public KeyMetadata describeKey(String kmsKeyId) {
        return new KeyMetadata(
                "local-dev-key",
                "local-dev",
                true,
                Instant.EPOCH
        );
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    private byte[] encryptWithLocalKek(byte[] plaintext) {
        try {
            byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
            secureRandom.nextBytes(iv);
            SecretKey kekKey = new SecretKeySpec(localKek, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            Cipher cipher = Cipher.getInstance(AES_GCM_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, kekKey, gcmSpec);
            byte[] ciphertext = cipher.doFinal(plaintext);
            return prependIv(iv, ciphertext);
        } catch (Exception e) {
            throw new KmsOperationException("Failed to encrypt with local KEK", e);
        }
    }

    private byte[] decryptWithLocalKek(byte[] ivPrefixedCiphertext) {
        try {
            byte[] iv = Arrays.copyOfRange(ivPrefixedCiphertext, 0, GCM_IV_LENGTH_BYTES);
            byte[] ciphertext = Arrays.copyOfRange(ivPrefixedCiphertext, GCM_IV_LENGTH_BYTES, ivPrefixedCiphertext.length);
            SecretKey kekKey = new SecretKeySpec(localKek, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            Cipher cipher = Cipher.getInstance(AES_GCM_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, kekKey, gcmSpec);
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new KmsOperationException("Failed to decrypt with local KEK", e);
        }
    }

    private byte[] prependIv(byte[] iv, byte[] ciphertext) {
        byte[] combined = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
        return combined;
    }
}
