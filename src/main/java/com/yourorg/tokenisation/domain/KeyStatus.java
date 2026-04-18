package com.yourorg.tokenisation.domain;

/**
 * Lifecycle state of a key version in the {@code key_versions} table.
 *
 * <p>Valid transitions:
 * <pre>
 *   ACTIVE ──► ROTATING ──► RETIRED
 *   ACTIVE ──► COMPROMISED
 *   ROTATING ──► COMPROMISED
 * </pre>
 *
 * <p>A key version in {@code COMPROMISED} status immediately blocks detokenisation
 * for all tokens encrypted under that version. Key material is never deleted from
 * KMS — only the status column changes.
 */
public enum KeyStatus {

    /**
     * The key version is current and used for all new tokenisation operations.
     * At most one key version may be {@code ACTIVE} at any time (enforced by DB
     * partial unique index {@code idx_key_versions_single_active}).
     */
    ACTIVE,

    /**
     * The key version is being replaced by a newer version.
     * It remains valid for decryption and for tokenisation during the cutover window.
     * Tokens are being batch re-encrypted to the new key in the background.
     */
    ROTATING,

    /**
     * The key version has been superseded. All tokens have been re-encrypted to a newer version.
     * The version stays in the key ring for audit purposes and in case any missed records
     * need recovery — it is never removed from KMS.
     */
    RETIRED,

    /**
     * The key version has been identified as potentially compromised.
     * Detokenisation is immediately blocked for all tokens encrypted under this version.
     * Emergency rotation is initiated.
     */
    COMPROMISED
}
