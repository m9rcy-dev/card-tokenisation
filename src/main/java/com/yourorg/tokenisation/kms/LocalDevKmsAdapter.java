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
 * <p>The fixed KEK is specified as a hex string in configuration ({@code kms.local-dev.kek-hex}).
 * DEK wrapping and unwrapping are performed locally using AES-256-GCM — no network calls,
 * no cloud credentials required. This makes all integration tests hermetic.
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

    /**
     * Constructs the adapter from the hex-encoded KEK in configuration.
     *
     * @param kekHex hex-encoded 32-byte (64-character) AES-256 key from {@code kms.local-dev.kek-hex};
     *               must not be null or empty; must represent exactly 32 bytes
     * @throws IllegalArgumentException if the hex string does not decode to exactly 32 bytes
     */
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
     * Returns the fixed local KEK bytes — no decryption is needed since the KEK
     * is not actually encrypted in the local-dev profile.
     *
     * <p>The {@code encryptedKekBlob} parameter is ignored in this adapter because
     * there is no real KMS to unwrap from. The fixed KEK from configuration is returned directly.
     *
     * @param encryptedKekBlob ignored in this adapter
     * @return a copy of the configured 32-byte local KEK
     */
    @Override
    public byte[] unwrapKek(String encryptedKekBlob) {
        // A fresh copy is returned so the caller can zero it independently
        return localKek.clone();
    }

    /**
     * Wraps a plaintext DEK using AES-256-GCM with the local fixed KEK.
     *
     * <p>Format of the returned blob: {@code [12-byte IV][GCM ciphertext including 16-byte tag]}.
     *
     * @param plaintextDek  the 32-byte DEK to wrap; must not be null; must be exactly 32 bytes
     * @param keyVersionId  not used for cryptographic operations in this adapter; included for interface parity
     * @return IV-prefixed GCM ciphertext of the DEK
     * @throws IllegalArgumentException if {@code plaintextDek} is not 32 bytes
     * @throws KmsOperationException    if the AES-GCM operation fails
     */
    @Override
    public byte[] wrapDek(byte[] plaintextDek, String keyVersionId) {
        if (plaintextDek == null || plaintextDek.length != 32) {
            throw new IllegalArgumentException("Plaintext DEK must be exactly 32 bytes");
        }
        try {
            byte[] iv = generateIv();
            SecretKey kekKey = new SecretKeySpec(localKek, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            Cipher cipher = Cipher.getInstance(AES_GCM_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, kekKey, gcmSpec);
            byte[] wrappedDek = cipher.doFinal(plaintextDek);
            return prependIv(iv, wrappedDek);
        } catch (Exception encryptionException) {
            throw new KmsOperationException("Failed to wrap DEK using local KEK", encryptionException);
        }
    }

    /**
     * Re-wraps a DEK: unwraps it from the old KEK context, then wraps it under the new.
     *
     * <p>In this adapter both old and new KEK are the same fixed key, so this is
     * effectively a decrypt-then-re-encrypt with a new IV.
     *
     * @param encryptedDek      IV-prefixed GCM ciphertext of the DEK; must not be null
     * @param oldKeyVersionId   not used in this adapter
     * @param newKeyVersionId   not used in this adapter
     * @return the DEK re-wrapped with a fresh IV under the local KEK
     * @throws KmsOperationException if unwrap or re-wrap fails
     */
    @Override
    public byte[] rewrapDek(byte[] encryptedDek, String oldKeyVersionId, String newKeyVersionId) {
        byte[] plaintextDek = unwrapDekInternal(encryptedDek);
        try {
            return wrapDek(plaintextDek, newKeyVersionId);
        } finally {
            Arrays.fill(plaintextDek, (byte) 0);
        }
    }

    /**
     * Returns stub metadata for the local dev key.
     *
     * <p>No real KMS is available in the local-dev profile, so this returns a synthetic
     * {@link KeyMetadata} indicating the key is enabled. The tamper reconciliation job
     * must not run against the local-dev adapter.
     *
     * @param kmsKeyId not used; the local adapter has a single fixed key
     * @return synthetic metadata for the local dev key
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

    /**
     * Decrypts an IV-prefixed GCM ciphertext using the local KEK.
     *
     * <p>The caller is responsible for zeroing the returned array after use.
     *
     * @param ivPrefixedCiphertext IV-prefixed GCM ciphertext; first 12 bytes are the IV
     * @return the decrypted plaintext bytes
     * @throws KmsOperationException if decryption fails (e.g. auth tag mismatch)
     */
    private byte[] unwrapDekInternal(byte[] ivPrefixedCiphertext) {
        try {
            byte[] iv = extractIv(ivPrefixedCiphertext);
            byte[] ciphertext = extractCiphertext(ivPrefixedCiphertext);
            SecretKey kekKey = new SecretKeySpec(localKek, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            Cipher cipher = Cipher.getInstance(AES_GCM_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, kekKey, gcmSpec);
            return cipher.doFinal(ciphertext);
        } catch (Exception decryptionException) {
            throw new KmsOperationException("Failed to unwrap DEK using local KEK", decryptionException);
        }
    }

    private byte[] generateIv() {
        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        secureRandom.nextBytes(iv);
        return iv;
    }

    private byte[] prependIv(byte[] iv, byte[] ciphertext) {
        byte[] combined = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
        return combined;
    }

    private byte[] extractIv(byte[] ivPrefixedCiphertext) {
        return Arrays.copyOfRange(ivPrefixedCiphertext, 0, GCM_IV_LENGTH_BYTES);
    }

    private byte[] extractCiphertext(byte[] ivPrefixedCiphertext) {
        return Arrays.copyOfRange(ivPrefixedCiphertext, GCM_IV_LENGTH_BYTES, ivPrefixedCiphertext.length);
    }
}
