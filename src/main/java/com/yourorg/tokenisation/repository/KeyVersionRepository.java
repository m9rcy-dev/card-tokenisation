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
 * <p>All query methods operate in read mode. Mutations to {@code KeyVersion} state
 * (status transitions) are performed via entity methods and flushed by JPA —
 * no bulk update queries are used here to preserve optimistic locking.
 */
public interface KeyVersionRepository extends JpaRepository<KeyVersion, UUID> {

    /**
     * Finds all key versions whose status is in the given set.
     *
     * <p>Used at startup by {@code KeyRingInitialiser} to load all {@code ACTIVE}
     * and {@code ROTATING} key versions into the in-memory key ring.
     *
     * @param statuses the set of statuses to include; must not be null or empty
     * @return all matching key versions, ordered by {@code activatedAt} ascending
     */
    @Query("SELECT kv FROM KeyVersion kv WHERE kv.status IN :statuses ORDER BY kv.activatedAt ASC")
    List<KeyVersion> findByStatusIn(@Param("statuses") List<KeyStatus> statuses);

    /**
     * Returns the single {@code ACTIVE} key version.
     *
     * <p>The database enforces at most one {@code ACTIVE} key at a time via
     * {@code idx_key_versions_single_active} (partial unique index on status = 'ACTIVE').
     *
     * @return the active key version, or empty if none exists
     */
    @Query("SELECT kv FROM KeyVersion kv WHERE kv.status = 'ACTIVE'")
    Optional<KeyVersion> findActive();

    /**
     * Returns the single {@code ACTIVE} key version, throwing if none is found.
     *
     * <p>Used during startup initialisation and tokenisation. An absent active key
     * indicates a misconfigured or partially rotated system.
     *
     * @return the active key version
     * @throws IllegalStateException if no active key version exists in the database
     */
    default KeyVersion findActiveOrThrow() {
        return findActive().orElseThrow(() ->
                new IllegalStateException("No ACTIVE key version found in key_versions table"));
    }

    /**
     * Finds the oldest key version currently in {@code ROTATING} status.
     *
     * <p>Used by the rotation batch job to determine which key version's tokens
     * still need re-encryption. "Oldest rotating" is used to process rotations in order.
     *
     * @return the oldest rotating key version, or empty if no rotation is in progress
     */
    @Query("SELECT kv FROM KeyVersion kv WHERE kv.status = 'ROTATING' ORDER BY kv.activatedAt ASC")
    Optional<KeyVersion> findOldestRotating();

    /**
     * Finds the oldest key version requiring token migration — either {@code ROTATING} (scheduled)
     * or {@code COMPROMISED} (emergency rotation).
     *
     * <p>Both statuses indicate that tokens on this key version must be re-encrypted to the
     * current {@code ACTIVE} key. {@code ROTATING} is used by scheduled rotation;
     * {@code COMPROMISED} by emergency rotation. The batch job processes either.
     *
     * @return the oldest key version pending migration, or empty if none exists
     */
    @Query("SELECT kv FROM KeyVersion kv WHERE kv.status IN ('ROTATING', 'COMPROMISED') ORDER BY kv.activatedAt ASC")
    Optional<KeyVersion> findOldestPendingMigration();
}
