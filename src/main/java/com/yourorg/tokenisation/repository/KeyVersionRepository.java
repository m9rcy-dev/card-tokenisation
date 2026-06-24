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
 * <p>Both DEK and HMAC versions are stored in the same table. Query methods are
 * scoped by {@code key_type} where it matters — startup loaders, rotation services,
 * and admin endpoints all work with type-specific subsets.
 */
public interface KeyVersionRepository extends JpaRepository<KeyVersion, UUID> {

    // ── DEK queries ───────────────────────────────────────────────────────────

    /**
     * Finds all DEK versions whose status is in the given set.
     * Used by {@code KeyRingInitialiser} to load all ACTIVE and ROTATING DEKs at startup.
     */
    @Query("""
            SELECT kv FROM KeyVersion kv
            WHERE kv.keyType = 'DEK' AND kv.status IN :statuses
            ORDER BY kv.activatedAt ASC
            """)
    List<KeyVersion> findDekByStatusIn(@Param("statuses") List<KeyStatus> statuses);

    /**
     * Returns the single ACTIVE DEK version.
     * The partial unique index enforces at most one ACTIVE DEK at a time.
     */
    @Query("SELECT kv FROM KeyVersion kv WHERE kv.keyType = 'DEK' AND kv.status = 'ACTIVE'")
    Optional<KeyVersion> findActiveDek();

    default KeyVersion findActiveDekOrThrow() {
        return findActiveDek().orElseThrow(() ->
                new IllegalStateException("No ACTIVE DEK version found in key_versions table"));
    }

    /**
     * Finds the oldest DEK version currently requiring token migration
     * (ROTATING for scheduled, COMPROMISED for emergency rotation).
     */
    @Query("""
            SELECT kv FROM KeyVersion kv
            WHERE kv.keyType = 'DEK' AND kv.status IN ('ROTATING', 'COMPROMISED')
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

}
