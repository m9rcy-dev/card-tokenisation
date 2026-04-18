package com.yourorg.tokenisation.kms;

import java.time.Instant;

/**
 * Describes metadata for a KMS-managed key, as returned by {@link KmsProvider#describeKey}.
 *
 * <p>Used by the tamper reconciliation job to cross-check local {@code key_versions} state
 * against the authoritative KMS record. Any discrepancy (e.g. KMS reports a key as disabled
 * while the local record shows it as {@code ACTIVE}) triggers a tamper alert.
 *
 * @param kmsKeyId   the KMS-internal key identifier (e.g. AWS KMS key ARN)
 * @param keyAlias   the human-readable alias as registered in KMS
 * @param enabled    whether the KMS key is currently enabled for cryptographic operations
 * @param createdAt  when the KMS key was created, as reported by the KMS
 */
public record KeyMetadata(
        String kmsKeyId,
        String keyAlias,
        boolean enabled,
        Instant createdAt
) {}
