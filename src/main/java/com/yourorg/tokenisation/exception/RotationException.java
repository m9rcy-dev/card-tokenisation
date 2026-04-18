package com.yourorg.tokenisation.exception;

/**
 * Thrown when a key rotation operation fails in an unrecoverable way.
 *
 * <p>This exception signals that the rotation batch job or emergency rotation
 * could not complete — for example, because the KMS rejected the re-wrap request,
 * the database was unavailable, or an optimistic locking conflict was retried
 * beyond the configured limit.
 *
 * <p>A {@code RotationException} should always be accompanied by appropriate logging
 * at {@code ERROR} level including the rotation job ID and affected key version ID.
 * The message must not include key bytes or PAN data.
 */
public class RotationException extends TokenisationException {

    /**
     * Constructs a {@code RotationException} with a descriptive message.
     *
     * @param message description of the rotation failure;
     *                must not contain key material or PAN data
     */
    public RotationException(String message) {
        super(message);
    }

    /**
     * Constructs a {@code RotationException} wrapping a lower-level cause.
     *
     * @param message description of the rotation failure;
     *                must not contain key material or PAN data
     * @param cause   the underlying exception (e.g. from the KMS adapter or JPA layer)
     */
    public RotationException(String message, Throwable cause) {
        super(message, cause);
    }
}
