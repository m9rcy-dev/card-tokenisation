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
 * JPA entity representing one key version in the {@code key_versions} table.
 *
 * <p>A single table holds both KEK and HMAC key versions, discriminated by {@code key_type}.
 * KEK rows hold KMS-related fields ({@code kms_key_id}, {@code encrypted_kek_blob}, etc.)
 * and leave HMAC fields null. HMAC rows hold {@code encrypted_secret} and
 * {@code encrypting_kek_id} and leave KMS fields null.
 *
 * <p>Rows are intentionally immutable after creation — the only permitted mutations are
 * {@code status}, {@code rotation_reason}, and {@code retired_at}, controlled through
 * entity methods.
 */
@Entity
@Table(name = "key_versions")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class KeyVersion {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    /** Discriminator: {@code KEK} or {@code HMAC}. */
    @Enumerated(EnumType.STRING)
    @Column(name = "key_type", nullable = false)
    private KeyType keyType;

    /** KMS-internal key identifier (e.g. AWS KMS ARN). Null for HMAC rows. */
    @Column(name = "kms_key_id")
    private String kmsKeyId;

    /** KMS provider name (e.g. {@code AWS_KMS} or {@code LOCAL_DEV}). Null for HMAC rows. */
    @Column(name = "kms_provider")
    private String kmsProvider;

    /** Human-readable alias for operational use. */
    @Column(name = "key_alias", nullable = false)
    private String keyAlias;

    /** Base64-encoded KEK ciphertext from KMS. Null for HMAC rows. */
    @Column(name = "encrypted_kek_blob")
    private String encryptedKekBlob;

    /**
     * IV-prefixed AES-GCM blob of the HMAC secret, wrapped under {@code encrypting_kek_id}.
     * Null for KEK rows.
     */
    @Column(name = "encrypted_secret")
    private byte[] encryptedSecret;

    /**
     * UUID of the KEK version that encrypted {@code encrypted_secret}.
     * Self-referential FK on {@code key_versions.id}. Null for KEK rows.
     */
    @Column(name = "encrypting_kek_id")
    private UUID encryptingKekId;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    private KeyStatus status;

    @Enumerated(EnumType.STRING)
    @Column(name = "rotation_reason")
    private RotationReason rotationReason;

    @Column(name = "activated_at", nullable = false, updatable = false)
    private Instant activatedAt;

    @Column(name = "retired_at")
    private Instant retiredAt;

    @Column(name = "rotate_by", nullable = false)
    private Instant rotateBy;

    @Column(name = "created_by", nullable = false, updatable = false)
    private String createdBy;

    @Builder
    public KeyVersion(
            KeyType keyType,
            String kmsKeyId,
            String kmsProvider,
            String keyAlias,
            String encryptedKekBlob,
            byte[] encryptedSecret,
            UUID encryptingKekId,
            KeyStatus status,
            RotationReason rotationReason,
            Instant activatedAt,
            Instant rotateBy,
            String createdBy) {
        this.keyType = keyType != null ? keyType : KeyType.KEK;
        this.kmsKeyId = kmsKeyId;
        this.kmsProvider = kmsProvider;
        this.keyAlias = keyAlias;
        this.encryptedKekBlob = encryptedKekBlob;
        this.encryptedSecret = encryptedSecret != null ? encryptedSecret.clone() : null;
        this.encryptingKekId = encryptingKekId;
        this.status = status;
        this.rotationReason = rotationReason;
        this.activatedAt = activatedAt;
        this.rotateBy = rotateBy;
        this.createdBy = createdBy;
    }

    /** Factory method for HMAC key version rows. */
    public static KeyVersion forHmac(byte[] encryptedSecret,
                                     UUID encryptingKekId,
                                     String keyAlias,
                                     Instant rotateBy,
                                     String createdBy) {
        return KeyVersion.builder()
                .keyType(KeyType.HMAC)
                .keyAlias(keyAlias)
                .encryptedSecret(encryptedSecret)
                .encryptingKekId(encryptingKekId)
                .status(KeyStatus.ACTIVE)
                .activatedAt(Instant.now())
                .rotateBy(rotateBy)
                .createdBy(createdBy)
                .build();
    }

    /** Returns a defensive copy of the encrypted HMAC secret. */
    public byte[] getEncryptedSecret() {
        return encryptedSecret != null ? encryptedSecret.clone() : null;
    }

    public void markRotating() {
        this.status = KeyStatus.ROTATING;
    }

    public void markRetired(Instant retiredAt) {
        this.status = KeyStatus.RETIRED;
        this.retiredAt = retiredAt;
    }

    public void markCompromised(Instant compromisedAt) {
        this.status = KeyStatus.COMPROMISED;
        this.retiredAt = compromisedAt;
    }
}
