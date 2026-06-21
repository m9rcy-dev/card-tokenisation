package com.yourorg.tokenisation.repository;

import com.yourorg.tokenisation.domain.KeyStatus;
import com.yourorg.tokenisation.domain.KeyVersion;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for {@link KeyVersion} entities stored in the {@code key_versions} table.
 *
 * <p>Both KEK and HMAC versions are stored in the same table. Query methods are
 * scoped by {@code key_type} where it matters — startup loaders, rotation services,
 * and admin endpoints all work with type-specific subsets.
 */
public interface KeyVersionRepository extends JpaRepository<KeyVersion, UUID> {

    // ── KEK queries ───────────────────────────────────────────────────────────

    /**
     * Finds all KEK versions whose status is in the given set.
     * Used by {@code KeyRingInitialiser} to load all ACTIVE and ROTATING KEKs at startup.
     */
    @Query("""
            SELECT kv FROM KeyVersion kv
            WHERE kv.keyType = 'KEK' AND kv.status IN :statuses
            ORDER BY kv.activatedAt ASC
            """)
    List<KeyVersion> findKekByStatusIn(@Param("statuses") List<KeyStatus> statuses);

    /**
     * Returns the single ACTIVE KEK version.
     * The partial unique index enforces at most one ACTIVE KEK at a time.
     */
    @Query("SELECT kv FROM KeyVersion kv WHERE kv.keyType = 'KEK' AND kv.status = 'ACTIVE'")
    Optional<KeyVersion> findActiveKek();

    default KeyVersion findActiveKekOrThrow() {
        return findActiveKek().orElseThrow(() ->
                new IllegalStateException("No ACTIVE KEK version found in key_versions table"));
    }

    /**
     * Finds the oldest KEK version currently requiring token migration
     * (ROTATING for scheduled, COMPROMISED for emergency rotation).
     */
    @Query("""
            SELECT kv FROM KeyVersion kv
            WHERE kv.keyType = 'KEK' AND kv.status IN ('ROTATING', 'COMPROMISED')
            ORDER BY kv.activatedAt ASC
            """)
    Optional<KeyVersion> findOldestPendingMigration();

    // ── HMAC queries ──────────────────────────────────────────────────────────

    /**
     * Finds all HMAC versions whose status is in the given set.
     * Used by {@code KeyRingInitialiser} to load ACTIVE and ROTATING HMAC secrets at startup.
     */
    @Query("""
            SELECT kv FROM KeyVersion kv
            WHERE kv.keyType = 'HMAC' AND kv.status IN :statuses
            ORDER BY kv.activatedAt ASC
            """)
    List<KeyVersion> findHmacByStatusIn(@Param("statuses") List<KeyStatus> statuses);

    /**
     * Returns the single ACTIVE HMAC version.
     * The partial unique index enforces at most one ACTIVE HMAC at a time.
     */
    @Query("SELECT kv FROM KeyVersion kv WHERE kv.keyType = 'HMAC' AND kv.status = 'ACTIVE'")
    Optional<KeyVersion> findActiveHmac();

    default KeyVersion findActiveHmacOrThrow() {
        return findActiveHmac().orElseThrow(() ->
                new IllegalStateException("No ACTIVE HMAC key version found in key_versions table"));
    }

    // ── Legacy compatibility ──────────────────────────────────────────────────

    /**
     * Finds the oldest key version requiring migration regardless of type.
     *
     * @deprecated Use {@link #findOldestPendingMigration()} for KEK rotation.
     *             HMAC rotation uses its own batch job.
     */
    @Deprecated
    @Query("""
            SELECT kv FROM KeyVersion kv
            WHERE kv.status IN ('ROTATING', 'COMPROMISED')
            ORDER BY kv.activatedAt ASC
            """)
    Optional<KeyVersion> findOldestPendingMigrationAny();

    /** Finds all KEK or HMAC versions with the given status set (general-purpose). */
    @Query("SELECT kv FROM KeyVersion kv WHERE kv.status IN :statuses ORDER BY kv.activatedAt ASC")
    List<KeyVersion> findByStatusIn(@Param("statuses") List<KeyStatus> statuses);

    /** Returns the single ACTIVE key (any type). Used by legacy callers during migration window. */
    @Query("SELECT kv FROM KeyVersion kv WHERE kv.status = 'ACTIVE' AND kv.keyType = 'KEK'")
    Optional<KeyVersion> findActive();

    default KeyVersion findActiveOrThrow() {
        return findActiveKekOrThrow();
    }

    /** Finds the oldest ROTATING KEK (legacy RotationJob helper). */
    @Query("SELECT kv FROM KeyVersion kv WHERE kv.keyType = 'KEK' AND kv.status = 'ROTATING' ORDER BY kv.activatedAt ASC")
    Optional<KeyVersion> findOldestRotating();

}
