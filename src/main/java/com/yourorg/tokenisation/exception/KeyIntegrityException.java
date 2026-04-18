package com.yourorg.tokenisation.exception;

/**
 * Thrown when tampering is detected on a key version record in {@code key_versions}.
 *
 * <p>The {@code TamperDetector} computes an HMAC-SHA256 over the key version's
 * immutable fields and compares it against the stored {@code checksum}. Any mismatch
 * indicates that the row was modified outside of the application, which constitutes
 * a tamper event.
 *
 * <p>When this exception is thrown:
 * <ol>
 *   <li>A {@code TAMPER_ALERT} record must be written to {@code token_audit_log}.
 *   <li>The key version must be marked {@code COMPROMISED} in the key ring.
 *   <li>All detokenisation operations using this key version must be blocked.
 * </ol>
 *
 * <p>The exception message may include the key version ID (a UUID, not sensitive)
 * but must never include HMAC values, key bytes, or PAN data.
 */
public class KeyIntegrityException extends TokenisationException {

    /**
     * Constructs a {@code KeyIntegrityException} with a descriptive message.
     *
     * @param message description of the integrity failure, including the key version ID;
     *                must not contain HMAC values or key material
     */
    public KeyIntegrityException(String message) {
        super(message);
    }

    /**
     * Constructs a {@code KeyIntegrityException} wrapping a lower-level cause.
     *
     * @param message description of the integrity failure
     * @param cause   the underlying exception
     */
    public KeyIntegrityException(String message, Throwable cause) {
        super(message, cause);
    }
}
