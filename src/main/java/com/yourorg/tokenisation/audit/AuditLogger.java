package com.yourorg.tokenisation.audit;

import com.yourorg.tokenisation.domain.TokenAuditLog;
import com.yourorg.tokenisation.repository.AuditLogRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * Component responsible for writing append-only audit log records to {@code token_audit_log}.
 *
 * <p>Every tokenisation, detokenisation, key rotation, and security violation event
 * produces exactly one audit record. This component is the single point of write access
 * for the audit log — service classes must not call {@code AuditLogRepository} directly.
 *
 * <p><strong>Contract: this component never throws.</strong> If an audit log write fails
 * (e.g. database unavailable), the error is logged at {@code ERROR} level but the exception
 * is swallowed. A failed audit write must not prevent the primary business operation from
 * completing — audit failure is operationally visible through monitoring but does not
 * constitute a transactional failure for the caller.
 *
 * <p>Each call runs in its own {@code REQUIRES_NEW} transaction. This ensures that:
 * <ul>
 *   <li>An in-progress business transaction rolling back does not prevent the failure
 *       audit record from being committed.
 *   <li>A failure in the audit write does not mark the business transaction for rollback.
 * </ul>
 *
 * <p><strong>PAN must never appear in any audit log field.</strong> Callers are responsible
 * for ensuring that {@code failureReason} and {@code metadata} values are PAN-free.
 */
@Component
@Slf4j
public class AuditLogger {

    private static final String OUTCOME_SUCCESS = "SUCCESS";
    private static final String OUTCOME_FAILURE = "FAILURE";

    private final AuditLogRepository auditLogRepository;

    /**
     * Constructs an {@code AuditLogger} with the given repository.
     *
     * @param auditLogRepository the repository for persisting audit records; must not be null
     */
    public AuditLogger(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    /**
     * Writes a SUCCESS audit record for the given event.
     *
     * <p>Runs in its own database transaction ({@code REQUIRES_NEW}), independent of
     * any enclosing transaction. Never throws — exceptions are logged at {@code ERROR}.
     *
     * @param eventType   the type of event that succeeded; must not be null
     * @param tokenId     the affected token's vault ID; may be {@code null} for key-level events
     * @param merchantId  the merchant scope of the event; may be {@code null}
     * @param actorId     identity of the calling service or user; may be {@code null}
     * @param actorIp     IP address of the caller; may be {@code null}
     * @param metadata    optional structured extras; must not contain PAN; may be {@code null}
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logSuccess(AuditEventType eventType,
                           UUID tokenId,
                           String merchantId,
                           String actorId,
                           String actorIp,
                           Map<String, Object> metadata) {
        writeAuditRecord(eventType, tokenId, null, actorId, actorIp, merchantId,
                OUTCOME_SUCCESS, null, metadata);
    }

    /**
     * Writes a FAILURE audit record for the given event.
     *
     * <p>Runs in its own database transaction ({@code REQUIRES_NEW}), independent of
     * any enclosing transaction. Never throws — exceptions are logged at {@code ERROR}.
     *
     * <p>The {@code failureReason} must not contain PAN digits, key bytes, or any
     * other sensitive material.
     *
     * @param eventType     the type of event that failed; must not be null
     * @param tokenId       the affected token's vault ID; may be {@code null}
     * @param merchantId    the merchant scope; may be {@code null}
     * @param actorId       identity of the caller; may be {@code null}
     * @param actorIp       IP address of the caller; may be {@code null}
     * @param failureReason human-readable failure description; must not contain PAN
     * @param metadata      optional structured extras; must not contain PAN; may be {@code null}
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logFailure(AuditEventType eventType,
                           UUID tokenId,
                           String merchantId,
                           String actorId,
                           String actorIp,
                           String failureReason,
                           Map<String, Object> metadata) {
        writeAuditRecord(eventType, tokenId, null, actorId, actorIp, merchantId,
                OUTCOME_FAILURE, failureReason, metadata);
    }

    /**
     * Writes a key-level audit record, including the key version involved.
     *
     * <p>Used for key rotation events and key integrity violations where a specific
     * key version is the subject of the event (not a token).
     *
     * <p>Runs in its own database transaction ({@code REQUIRES_NEW}). Never throws.
     *
     * @param eventType    the key-level event type; must not be null
     * @param keyVersionId the key version UUID involved; may be {@code null}
     * @param outcome      {@code "SUCCESS"} or {@code "FAILURE"}
     * @param failureReason reason for failure; {@code null} on success; must not contain sensitive material
     * @param metadata     optional structured extras; may be {@code null}
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logKeyEvent(AuditEventType eventType,
                            UUID keyVersionId,
                            String outcome,
                            String failureReason,
                            Map<String, Object> metadata) {
        writeAuditRecord(eventType, null, keyVersionId, null, null, null,
                outcome, failureReason, metadata);
    }

    // ── Private ──────────────────────────────────────────────────────────────

    /**
     * Builds and saves a {@link TokenAuditLog} record. Catches all exceptions to
     * satisfy the "never throws" contract of this component.
     *
     * @param eventType     the event category
     * @param tokenId       the affected token; may be null
     * @param keyVersionId  the affected key version; may be null
     * @param actorId       the caller identity; may be null
     * @param actorIp       the caller IP; may be null
     * @param merchantId    the merchant scope; may be null
     * @param outcome       SUCCESS or FAILURE
     * @param failureReason description of failure; null on success
     * @param metadata      additional structured data; may be null
     */
    private void writeAuditRecord(AuditEventType eventType,
                                  UUID tokenId,
                                  UUID keyVersionId,
                                  String actorId,
                                  String actorIp,
                                  String merchantId,
                                  String outcome,
                                  String failureReason,
                                  Map<String, Object> metadata) {
        try {
            TokenAuditLog entry = TokenAuditLog.builder()
                    .eventType(eventType.name())
                    .tokenId(tokenId)
                    .keyVersionId(keyVersionId)
                    .actorId(actorId)
                    .actorIp(actorIp)
                    .merchantId(merchantId)
                    .outcome(outcome)
                    .failureReason(failureReason)
                    .metadata(metadata)
                    .createdAt(Instant.now())
                    .build();
            auditLogRepository.save(entry);
        } catch (Exception auditWriteException) {
            // Audit writes must never propagate — log at ERROR so monitoring can detect failures
            log.error("Failed to write audit record for event type [{}]: {}",
                    eventType, auditWriteException.getMessage(), auditWriteException);
        }
    }
}
