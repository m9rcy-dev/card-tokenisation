package com.yourorg.tokenisation.kms;

/**
 * Thrown when a KMS operation fails — e.g. the KMS is unreachable, the key does
 * not exist, or the ciphertext cannot be decrypted.
 *
 * <p>This exception signals an infrastructure failure, not a business logic error.
 * It is intentionally not part of the domain exception hierarchy so that callers
 * can distinguish KMS failures from tokenisation business failures.
 *
 * <p>Never include key bytes, PAN digits, or other sensitive material in the message.
 */
public class KmsOperationException extends RuntimeException {

    /**
     * Constructs a {@code KmsOperationException} with a descriptive message.
     *
     * @param message description of the KMS failure; must not contain sensitive material
     */
    public KmsOperationException(String message) {
        super(message);
    }

    /**
     * Constructs a {@code KmsOperationException} wrapping a lower-level cause.
     *
     * @param message description of the KMS failure; must not contain sensitive material
     * @param cause   the underlying exception from the KMS SDK or network layer
     */
    public KmsOperationException(String message, Throwable cause) {
        super(message, cause);
    }
}
