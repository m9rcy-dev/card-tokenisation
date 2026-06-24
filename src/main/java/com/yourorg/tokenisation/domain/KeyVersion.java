package com.yourorg.tokenisation.domain;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

/**
 * JPA entity representing one key version in the {@code key_versions} table.
 *
 * <p>A single table holds both DEK and HMAC key versions, discriminated by {@code key_type}.
 * DEK rows hold KMS-related fields ({@code kms_key_id}, {@code encrypted_dek_blob}, etc.)
 * and leave HMAC fields null. HMAC rows hold {@code encrypted_secret} (KMS ciphertext
 * protected directly by the CMK with {@code purpose=hmac-key} context) and leave DEK fields null.
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

    /** KMS-internal key identifier (e.g. AWS KMS ARN). Populated for both KEK and HMAC rows. */
    @Column(name = "kms_key_id")
    private String kmsKeyId;

    /** KMS provider name (e.g. {@code AWS_KMS} or {@code LOCAL_DEV}). Populated for both KEK and HMAC rows. */
    @Column(name = "kms_provider")
    private String kmsProvider;

    /** Human-readable alias for operational use. */
    @Column(name = "key_alias", nullable = false)
    private String keyAlias;

    /** KMS ciphertext of the DEK (raw bytes from GenerateDataKey). Null for HMAC rows. */
    @Column(name = "encrypted_dek_blob")
    private byte[] encryptedDekBlob;

    /**
     * KMS ciphertext of the HMAC secret, protected directly by the CMK with
     * {@code purpose=hmac-key} encryption context. Null for KEK rows.
     */
    @Column(name = "encrypted_secret")
    private byte[] encryptedSecret;

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
            byte[] encryptedDekBlob,
            byte[] encryptedSecret,
            KeyStatus status,
            RotationReason rotationReason,
            Instant activatedAt,
            Instant rotateBy,
            String createdBy) {
        this.keyType = keyType != null ? keyType : KeyType.DEK;
        this.kmsKeyId = kmsKeyId;
        this.kmsProvider = kmsProvider;
        this.keyAlias = keyAlias;
        this.encryptedDekBlob = encryptedDekBlob != null ? encryptedDekBlob.clone() : null;
        this.encryptedSecret = encryptedSecret != null ? encryptedSecret.clone() : null;
        this.status = status;
        this.rotationReason = rotationReason;
        this.activatedAt = activatedAt;
        this.rotateBy = rotateBy;
        this.createdBy = createdBy;
    }

    /** Returns a defensive copy of the encrypted DEK blob. */
    public byte[] getEncryptedDekBlob() {
        return encryptedDekBlob != null ? encryptedDekBlob.clone() : null;
    }

    /** Factory method for HMAC key version rows. */
    public static KeyVersion forHmac(byte[] encryptedSecret,
                                     String kmsKeyId,
                                     String kmsProvider,
                                     String keyAlias,
                                     Instant rotateBy,
                                     String createdBy) {
        return KeyVersion.builder()
                .keyType(KeyType.HMAC)
                .kmsKeyId(kmsKeyId)
                .kmsProvider(kmsProvider)
                .keyAlias(keyAlias)
                .encryptedSecret(encryptedSecret)
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
