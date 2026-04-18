package com.yourorg.tokenisation.audit;

/**
 * Enumeration of all event types written to {@code token_audit_log}.
 *
 * <p>Each constant corresponds to a distinct security-relevant event in the
 * tokenisation system lifecycle. The string representation (from {@link #name()})
 * is stored verbatim in the {@code event_type} column.
 */
public enum AuditEventType {

    /**
     * A PAN was successfully tokenised or a de-dup match was returned for a RECURRING token.
     */
    TOKENISE,

    /**
     * A token was successfully detokenised and the PAN was returned to the caller.
     */
    DETOKENISE,

    /**
     * A tokenisation or detokenisation operation failed (validation error, crypto failure, etc.).
     * The specific failure is described in the {@code failure_reason} column.
     */
    TOKENISE_FAILURE,

    /**
     * A detokenisation operation failed.
     */
    DETOKENISE_FAILURE,

    /**
     * A cross-merchant access attempt was detected and rejected.
     * The requesting merchant does not own the token they attempted to detokenise.
     */
    MERCHANT_SCOPE_VIOLATION,

    /**
     * Ciphertext or authentication tag tampering was detected during decryption.
     * GCM authentication tag verification failed — the stored ciphertext was modified outside the application.
     */
    TAMPER_ALERT,

    /**
     * Scheduled key rotation was initiated (compliance-driven TTL expiry).
     */
    KEY_ROTATION_STARTED,

    /**
     * Key rotation batch re-encryption completed successfully and the old key version was retired.
     */
    KEY_ROTATION_COMPLETED,

    /**
     * Emergency key rotation was initiated due to a detected key compromise.
     */
    EMERGENCY_ROTATION_STARTED,

    /**
     * An HMAC integrity check on a {@code key_versions} row failed — the row was modified
     * outside the application (database-level tamper detected).
     */
    KEY_INTEGRITY_VIOLATION,

    /**
     * A token vault record's DEK was successfully re-wrapped under the new key version
     * during batch re-encryption.
     */
    TOKEN_REENCRYPTED,

    /**
     * Re-encryption of a single token vault record failed during key rotation.
     * The record is skipped and the batch continues.
     */
    RE_ENCRYPTION_FAILURE,

    /**
     * Key rotation batch completed: all tokens have been re-encrypted and the old key retired.
     */
    KEY_ROTATION_COMPLETED_BATCH
}
