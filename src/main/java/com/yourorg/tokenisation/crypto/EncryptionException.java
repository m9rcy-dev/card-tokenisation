package com.yourorg.tokenisation.crypto;

import com.yourorg.tokenisation.exception.TokenisationException;

/**
 * Thrown when an AES-GCM encryption or decryption operation fails.
 *
 * <p>This exception signals a JCE infrastructure failure (e.g. algorithm not available,
 * invalid key length, provider error) — not a tamper detection failure.
 * GCM authentication tag failures are wrapped in this exception with a message
 * that does not reveal the plaintext or ciphertext content.
 *
 * <p>Never include PAN bytes, key bytes, or ciphertext content in the exception message.
 */
public class EncryptionException extends TokenisationException {

    /**
     * Constructs an {@code EncryptionException} with a descriptive message.
     *
     * @param message description of the failure; must not contain sensitive material
     */
    public EncryptionException(String message) {
        super(message);
    }

    /**
     * Constructs an {@code EncryptionException} wrapping a lower-level JCE exception.
     *
     * @param message description of the failure; must not contain sensitive material
     * @param cause   the underlying JCE exception ({@code GeneralSecurityException} subtype)
     */
    public EncryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
