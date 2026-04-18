package com.yourorg.tokenisation.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * JPA entity representing a single append-only audit log entry in {@code token_audit_log}.
 *
 * <p>Every tokenisation, detokenisation, key rotation event, and tamper alert produces
 * exactly one audit log record. Records are never updated or deleted — immutability is
 * enforced at the DB role level (INSERT and SELECT only; no UPDATE or DELETE).
 *
 * <p><strong>PAN must never appear in any field of this entity.</strong>
 * Log entries use {@code tokenId} and {@code keyVersionId} as references.
 * The {@code failureReason} field must use only generic descriptions.
 */
@Entity
@Table(name = "token_audit_log")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class TokenAuditLog {

    /** Auto-incremented primary key — assigned by the database via {@code BIGSERIAL}. */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", updatable = false, nullable = false)
    private Long id;

    /**
     * The type of event that produced this record (e.g. {@code TOKENISE}, {@code DETOKENISE},
     * {@code KEY_ROTATION_STARTED}, {@code TAMPER_ALERT}).
     */
    @Column(name = "event_type", nullable = false, updatable = false)
    private String eventType;

    /**
     * The token vault record affected by this event.
     * {@code null} for key-level events (rotation, tamper) where no single token is involved.
     */
    @Column(name = "token_id", updatable = false)
    private UUID tokenId;

    /**
     * The key version involved in this event.
     * {@code null} for tokenisation events where the key version is not relevant to the audit.
     */
    @Column(name = "key_version_id", updatable = false)
    private UUID keyVersionId;

    /**
     * Identity of the service or user that triggered the event.
     * Extracted from the authenticated JWT subject claim — never from the request body.
     */
    @Column(name = "actor_id", updatable = false)
    private String actorId;

    /**
     * IP address of the caller as seen at the API gateway.
     * Used for access pattern analysis and incident investigation.
     */
    @Column(name = "actor_ip", updatable = false)
    private String actorIp;

    /**
     * The merchant whose token was operated on.
     * {@code null} for key-level events with no merchant scope.
     */
    @Column(name = "merchant_id", updatable = false)
    private String merchantId;

    /**
     * Whether the operation succeeded or failed.
     * One of {@code SUCCESS} or {@code FAILURE}.
     */
    @Column(name = "outcome", nullable = false, updatable = false)
    private String outcome;

    /**
     * Human-readable description of why the operation failed.
     * Present only when {@code outcome} is {@code FAILURE}.
     * Must never contain PAN digits, key bytes, or other sensitive material.
     */
    @Column(name = "failure_reason", updatable = false)
    private String failureReason;

    /**
     * Structured additional context as a JSONB document.
     * Used for events with variable metadata (e.g. rotation batch statistics,
     * tamper detection details). Must never contain PAN or key material.
     */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "metadata", updatable = false, columnDefinition = "jsonb")
    private Map<String, Object> metadata;

    /** Timestamp when this audit record was created. Assigned by the database. */
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    /**
     * Constructs a new audit log entry.
     *
     * @param eventType     the event type string (use constants from {@code AuditEventType})
     * @param tokenId       the affected token; may be {@code null} for key-level events
     * @param keyVersionId  the affected key version; may be {@code null}
     * @param actorId       identity of the caller; may be {@code null} if unauthenticated
     * @param actorIp       IP address of the caller; may be {@code null}
     * @param merchantId    the merchant scope; may be {@code null}
     * @param outcome       {@code SUCCESS} or {@code FAILURE}
     * @param failureReason description of failure; must not contain PAN; may be {@code null}
     * @param metadata      optional structured extras; may be {@code null}
     * @param createdAt     timestamp of the event
     */
    @Builder
    public TokenAuditLog(
            String eventType,
            UUID tokenId,
            UUID keyVersionId,
            String actorId,
            String actorIp,
            String merchantId,
            String outcome,
            String failureReason,
            Map<String, Object> metadata,
            Instant createdAt) {
        this.eventType = eventType;
        this.tokenId = tokenId;
        this.keyVersionId = keyVersionId;
        this.actorId = actorId;
        this.actorIp = actorIp;
        this.merchantId = merchantId;
        this.outcome = outcome;
        this.failureReason = failureReason;
        this.metadata = metadata;
        this.createdAt = createdAt;
    }
}
