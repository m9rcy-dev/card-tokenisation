package com.yourorg.tokenisation.repository;

import com.yourorg.tokenisation.domain.TokenAuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Repository for {@link TokenAuditLog} entities stored in {@code token_audit_log}.
 *
 * <p>This repository is intentionally write-heavy: the application inserts a record
 * on every API call and key operation. Reads are infrequent (compliance queries,
 * investigation, load test assertions).
 *
 * <p>The underlying table is append-only. The database role must never be granted
 * UPDATE or DELETE on {@code token_audit_log} — see {@code PP-1} in {@code progress.md}.
 */
public interface AuditLogRepository extends JpaRepository<TokenAuditLog, Long> {

    /**
     * Returns all audit log entries for the specified token, ordered most recent first.
     *
     * <p>Used during incident investigation to reconstruct the full history of a token.
     * Uses the {@code idx_audit_log_token_id} index.
     *
     * @param tokenId the token vault primary key to query; must not be null
     * @return all audit records for the token, newest first
     */
    @Query("SELECT al FROM TokenAuditLog al WHERE al.tokenId = :tokenId ORDER BY al.createdAt DESC")
    List<TokenAuditLog> findByTokenId(@Param("tokenId") UUID tokenId);

    /**
     * Returns all audit log entries of the given event type created after the specified timestamp.
     *
     * <p>Used in load tests to verify tamper alert events were written within the expected
     * time window after a key corruption was committed.
     *
     * @param eventType  the event type to filter on (e.g. {@code TAMPER_ALERT}); must not be null
     * @param after      the lower bound timestamp (exclusive); must not be null
     * @return matching audit records ordered by {@code createdAt} ascending
     */
    @Query("""
            SELECT al FROM TokenAuditLog al
            WHERE al.eventType = :eventType
              AND al.createdAt > :after
            ORDER BY al.createdAt ASC
            """)
    List<TokenAuditLog> findByEventTypeAfter(
            @Param("eventType") String eventType,
            @Param("after") Instant after);

    /**
     * Counts audit records matching the given event type and outcome created after a timestamp.
     *
     * <p>Used in the tamper-under-load test to assert zero successful detokenisations
     * occurred after a key row was corrupted in the database.
     *
     * @param eventType  the event type to count; must not be null
     * @param outcome    the outcome to filter on ({@code SUCCESS} or {@code FAILURE}); must not be null
     * @param after      the lower bound timestamp (exclusive); must not be null
     * @return count of matching audit records
     */
    @Query("""
            SELECT COUNT(al) FROM TokenAuditLog al
            WHERE al.eventType = :eventType
              AND al.outcome = :outcome
              AND al.createdAt > :after
            """)
    long countByEventTypeAndOutcomeAfter(
            @Param("eventType") String eventType,
            @Param("outcome") String outcome,
            @Param("after") Instant after);
}
