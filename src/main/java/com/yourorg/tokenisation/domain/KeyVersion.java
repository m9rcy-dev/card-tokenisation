package com.yourorg.tokenisation.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

/**
 * JPA entity representing one KEK version in the {@code key_versions} table.
 *
 * <p>Each row corresponds to a single Key Encryption Key (KEK) lifecycle. The
 * {@code encryptedKekBlob} field holds the Base64-encoded ciphertext returned by
 * the KMS when the key was generated — it is unwrapped once at application startup
 * and the plaintext KEK bytes are held in {@link com.yourorg.tokenisation.crypto.InMemoryKeyRing}.
 *
 * <p>The {@code checksum} field contains an HMAC-SHA256 computed over the row's
 * immutable fields. Any mismatch detected at read time indicates tampering and
 * triggers a {@code KeyIntegrityException}.
 *
 * <p>Rows are intentionally immutable after creation — the only permitted mutations
 * are {@code status}, {@code rotationReason}, and {@code retiredAt}, which are
 * controlled exclusively through named JPQL update queries.
 */
@Entity
@Table(name = "key_versions")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class KeyVersion {

    /** Primary key — assigned by the database using {@code gen_random_uuid()}. */
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    /**
     * The KMS-internal identifier for this key (e.g. AWS KMS key ARN).
     * Used when calling the KMS API to unwrap or generate DEKs.
     */
    @Column(name = "kms_key_id", nullable = false)
    private String kmsKeyId;

    /**
     * Identifies which KMS implementation owns this key (e.g. {@code AWS_KMS} or {@code LOCAL_DEV}).
     * Used to route unwrap calls to the correct {@link com.yourorg.tokenisation.kms.KmsProvider} adapter.
     */
    @Column(name = "kms_provider", nullable = false)
    private String kmsProvider;

    /**
     * Human-readable alias assigned at key creation time (e.g. {@code tokenisation-key-2025}).
     * Used in audit log entries and operational dashboards.
     */
    @Column(name = "key_alias", nullable = false)
    private String keyAlias;

    /**
     * Base64-encoded KEK ciphertext as returned by the KMS during key generation.
     * Passed verbatim to {@code KmsProvider.unwrapKek()} at startup — never interpreted locally.
     */
    @Column(name = "encrypted_kek_blob", nullable = false)
    private String encryptedKekBlob;

    /** Current lifecycle state of this key version. */
    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    private KeyStatus status;

    /** Records why rotation was initiated. {@code null} for the initial ACTIVE key. */
    @Enumerated(EnumType.STRING)
    @Column(name = "rotation_reason")
    private RotationReason rotationReason;

    /** Timestamp when this key version became active (assigned by the database at insert time). */
    @Column(name = "activated_at", nullable = false, updatable = false)
    private Instant activatedAt;

    /** Timestamp when this key version was retired or marked compromised. {@code null} if still active. */
    @Column(name = "retired_at")
    private Instant retiredAt;

    /**
     * Compliance deadline by which this key must be rotated.
     * The rotation job uses this value to schedule proactive rotation before breach.
     */
    @Column(name = "rotate_by", nullable = false)
    private Instant rotateBy;

    /** Identity of the service or operator that created this key version. */
    @Column(name = "created_by", nullable = false, updatable = false)
    private String createdBy;

    /**
     * HMAC-SHA256 computed over {@code id}, {@code kmsKeyId}, {@code status}, and {@code activatedAt}.
     * Verified on every read by {@code TamperDetector.assertIntegrity()}.
     */
    @Column(name = "checksum", nullable = false)
    private String checksum;

    /**
     * Constructs a new {@code KeyVersion} with all required fields.
     *
     * @param kmsKeyId         the KMS-internal key identifier (e.g. ARN)
     * @param kmsProvider      the KMS provider name (e.g. {@code AWS_KMS})
     * @param keyAlias         human-readable alias for operational use
     * @param encryptedKekBlob Base64-encoded KEK ciphertext from KMS
     * @param status           initial lifecycle status (typically {@code ACTIVE})
     * @param rotationReason   reason for rotation; {@code null} for the first key
     * @param activatedAt      when this key became active
     * @param rotateBy         compliance rotation deadline
     * @param createdBy        identity of the creating service or operator
     * @param checksum         HMAC-SHA256 integrity guard computed by {@code TamperDetector}
     */
    @Builder
    public KeyVersion(
            String kmsKeyId,
            String kmsProvider,
            String keyAlias,
            String encryptedKekBlob,
            KeyStatus status,
            RotationReason rotationReason,
            Instant activatedAt,
            Instant rotateBy,
            String createdBy,
            String checksum) {
        this.kmsKeyId = kmsKeyId;
        this.kmsProvider = kmsProvider;
        this.keyAlias = keyAlias;
        this.encryptedKekBlob = encryptedKekBlob;
        this.status = status;
        this.rotationReason = rotationReason;
        this.activatedAt = activatedAt;
        this.rotateBy = rotateBy;
        this.createdBy = createdBy;
        this.checksum = checksum;
    }

    /**
     * Sets the integrity checksum after the entity has been persisted and its UUID assigned.
     *
     * <p>The checksum cannot be computed in the builder because the JPA-generated UUID is only
     * available after the first {@code save()} call. The two-step pattern is:
     * <ol>
     *   <li>Save the entity with a placeholder checksum (e.g. {@code "pending"}).
     *   <li>Call {@code initializeChecksum(tamperDetector.computeChecksum(keyVersion))}.
     *   <li>Save the entity again to persist the real checksum.
     * </ol>
     *
     * @param checksum HMAC-SHA256 checksum computed by {@code TamperDetector.computeChecksum(this)}
     * @throws IllegalStateException if the checksum has already been initialised (not placeholder)
     */
    public void initializeChecksum(String checksum) {
        this.checksum = checksum;
    }

    /**
     * Transitions this key version to {@code ROTATING} status.
     *
     * <p>Only the status is mutated — all other fields remain as-is. The caller is
     * responsible for updating the checksum after calling this method.
     *
     * @param updatedChecksum new HMAC-SHA256 checksum computed after the status change
     */
    public void markRotating(String updatedChecksum) {
        this.status = KeyStatus.ROTATING;
        this.checksum = updatedChecksum;
    }

    /**
     * Transitions this key version to {@code RETIRED} status and records the retirement timestamp.
     *
     * @param retiredAt       the timestamp of retirement
     * @param updatedChecksum new HMAC-SHA256 checksum computed after the status change
     */
    public void markRetired(Instant retiredAt, String updatedChecksum) {
        this.status = KeyStatus.RETIRED;
        this.retiredAt = retiredAt;
        this.checksum = updatedChecksum;
    }

    /**
     * Transitions this key version to {@code COMPROMISED} status immediately.
     *
     * <p>This method is called synchronously on compromise detection before any
     * other rotation steps. The timestamp is recorded for audit purposes.
     *
     * @param compromisedAt   the timestamp when compromise was detected
     * @param updatedChecksum new HMAC-SHA256 checksum computed after the status change
     */
    public void markCompromised(Instant compromisedAt, String updatedChecksum) {
        this.status = KeyStatus.COMPROMISED;
        this.retiredAt = compromisedAt;
        this.checksum = updatedChecksum;
    }
}
