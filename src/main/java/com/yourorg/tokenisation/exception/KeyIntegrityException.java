package com.yourorg.tokenisation.exception;

/**
 * Thrown when a cryptographic integrity check fails during detokenisation.
 *
 * <p>Two conditions raise this exception:
 * <ol>
 *   <li><strong>Compromised key</strong> — the key ring marks the key version as
 *       {@code COMPROMISED} (e.g. after an emergency rotation). Detokenisation is
 *       blocked immediately to prevent further data exposure.
 *   <li><strong>GCM auth tag failure</strong> — AES-256-GCM authentication tag
 *       verification fails during decryption, meaning the stored ciphertext or IV
 *       was modified outside the application.
 * </ol>
 *
 * <p>When this exception is thrown a {@code TAMPER_ALERT} record is written to
 * {@code token_audit_log} and a {@code 500} is returned to the caller.
 *
 * <p>The exception message may include the key version ID (a UUID, not sensitive)
 * but must never include key bytes or PAN data.
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
