package com.yourorg.tokenisation.repository;

import com.yourorg.tokenisation.domain.TokenVault;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for {@link TokenVault} entities stored in the {@code token_vault} table.
 *
 * <p>Query methods are grouped by the feature that uses them:
 * <ul>
 *   <li>Tokenisation — de-duplication lookup for {@code RECURRING} tokens
 *   <li>Detokenisation — hot-path lookup by token value
 *   <li>Key rotation — batch queries over active tokens for a given key version
 * </ul>
 */
public interface TokenVaultRepository extends JpaRepository<TokenVault, UUID> {

    // ── Detokenisation ──────────────────────────────────────────────────────

    /**
     * Looks up an active token vault record by its surrogate token value.
     *
     * <p>This is the detokenisation hot path. The query uses the
     * {@code idx_token_vault_token} unique index.
     *
     * @param token the opaque token value to look up; must not be null
     * @return the matching record if found and active, otherwise empty
     */
    @Query("SELECT tv FROM TokenVault tv WHERE tv.token = :token AND tv.isActive = true")
    Optional<TokenVault> findActiveByToken(@Param("token") String token);

    // ── Tokenisation de-dup ──────────────────────────────────────────────

    /**
     * Checks for an existing active {@code RECURRING} token for the given PAN hash and merchant.
     *
     * <p>Used by {@code TokenisationService} before issuing a new token.
     * If a match is found, the existing token is returned instead of creating a new record.
     * The query targets the {@code idx_token_vault_pan_hash_recurring} partial index.
     *
     * @param panHash    the HMAC-SHA256 of the PAN; must not be null
     * @param merchantId the merchant scope; may be {@code null} for global tokens
     * @return the existing recurring token if found, otherwise empty
     */
    @Query("""
            SELECT tv FROM TokenVault tv
            WHERE tv.panHash = :panHash
              AND tv.tokenType = 'RECURRING'
              AND tv.isActive = true
              AND (:merchantId IS NULL AND tv.merchantId IS NULL
                   OR tv.merchantId = :merchantId)
            """)
    Optional<TokenVault> findActiveRecurringByPanHashAndMerchant(
            @Param("panHash") String panHash,
            @Param("merchantId") String merchantId);

    // ── Key rotation ────────────────────────────────────────────────────

    /**
     * Returns a page of active token vault records that are still encrypted under
     * the specified key version.
     *
     * <p>Used by the rotation batch processor to select records that need
     * DEK re-wrapping. The {@code pageable} parameter controls batch size.
     *
     * @param keyVersionId the key version whose tokens need re-encryption; must not be null
     * @param pageable     pagination parameters controlling batch size; must not be null
     * @return a page of matching active records
     */
    @Query("""
            SELECT tv FROM TokenVault tv
            WHERE tv.keyVersion.id = :keyVersionId
              AND tv.isActive = true
            """)
    List<TokenVault> findActiveByKeyVersionId(
            @Param("keyVersionId") UUID keyVersionId,
            Pageable pageable);

    /**
     * Counts active tokens still encrypted under the specified key version.
     *
     * <p>Used by the rotation job to determine whether re-encryption is complete.
     * When this count reaches zero, the old key version can be retired.
     *
     * @param keyVersionId the key version to check; must not be null
     * @return number of active tokens still referencing this key version
     */
    @Query("""
            SELECT COUNT(tv) FROM TokenVault tv
            WHERE tv.keyVersion.id = :keyVersionId
              AND tv.isActive = true
            """)
    long countActiveByKeyVersionId(@Param("keyVersionId") UUID keyVersionId);
}
