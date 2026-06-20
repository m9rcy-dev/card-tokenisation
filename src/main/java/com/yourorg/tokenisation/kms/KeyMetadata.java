package com.yourorg.tokenisation.kms;

import java.time.Instant;

/**
 * Describes metadata for a KMS-managed key, as returned by {@link KmsProvider#describeKey}.
 *
 * <p>Used for operational health checks and rotation validation — for example, confirming
 * that the KMS key backing an ACTIVE {@code key_versions} row is still enabled before
 * initiating a rotation or unwrap operation.
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
