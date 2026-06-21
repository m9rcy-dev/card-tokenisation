package com.yourorg.tokenisation.rotation;

import com.yourorg.tokenisation.audit.AuditEventType;
import com.yourorg.tokenisation.audit.AuditLogger;
import com.yourorg.tokenisation.crypto.InMemoryHmacKeyRing;
import com.yourorg.tokenisation.domain.KeyVersion;
import com.yourorg.tokenisation.kms.KmsProvider;
import com.yourorg.tokenisation.repository.KeyVersionRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.UUID;

/**
 * Orchestrates HMAC key rotation for PAN hash versioning.
 *
 * <h3>Rotation flow</h3>
 * <ol>
 *   <li>{@link #initiateRotation} — marks current ACTIVE HMAC version as ROTATING, generates a
 *       fresh 32-byte secret, encrypts it directly under the KMS CMK ({@code purpose=hmac-key}),
 *       persists a new ACTIVE HMAC version, and promotes it in the in-memory ring.
 *       New tokenisations immediately use the new secret. The KEK is not involved.
 *   <li>{@code HmacRotationJob} — driven by cron, calls {@code PanHashBatchProcessor} to re-hash
 *       all vault records still on the rotating version.
 *   <li>{@link #completeRotation} — called by {@code HmacRotationJob} once all records are
 *       re-hashed; retires the old version in DB and removes it from the in-memory ring.
 * </ol>
 *
 * <p>During the rotation window, {@code TokenisationService} performs a dual-lookup: it checks
 * the new hash first, then falls back to the old hash if no match is found.  This prevents
 * duplicate tokens from being issued while the batch is in progress.
 */
@Service
@Slf4j
public class HmacRotationService {

    private static final int HMAC_SECRET_LENGTH_BYTES = 32;
    private static final int ROTATE_BY_DAYS = 365;

    private final KeyVersionRepository keyVersionRepository;
    private final KmsProvider kmsProvider;
    private final InMemoryHmacKeyRing hmacKeyRing;
    private final AuditLogger auditLogger;

    public HmacRotationService(KeyVersionRepository keyVersionRepository,
                                KmsProvider kmsProvider,
                                InMemoryHmacKeyRing hmacKeyRing,
                                AuditLogger auditLogger) {
        this.keyVersionRepository = keyVersionRepository;
        this.kmsProvider = kmsProvider;
        this.hmacKeyRing = hmacKeyRing;
        this.auditLogger = auditLogger;
    }

    /**
     * Initiates a scheduled HMAC key rotation.
     *
     * <p>The current ACTIVE HMAC version transitions to ROTATING.  A new ACTIVE version is
     * created with a fresh 32-byte {@link SecureRandom} secret and promoted in the in-memory
     * ring so that new tokenisations immediately switch to the new secret.
     *
     * @param newKeyAlias human-readable alias for the new key version; must not be blank
     * @return the UUID of the newly created ACTIVE HMAC version
     * @throws IllegalStateException if no ACTIVE HMAC version exists
     */
    @Transactional
    public UUID initiateRotation(String newKeyAlias) {
        // 1. Transition existing ACTIVE HMAC → ROTATING
        KeyVersion activeHmac = keyVersionRepository.findActiveHmacOrThrow();
        UUID oldVersionId = activeHmac.getId();
        activeHmac.markRotating();
        keyVersionRepository.save(activeHmac);
        keyVersionRepository.flush();

        // 2. Generate new secret — zeroed in finally regardless of success or failure
        byte[] newSecret = new byte[HMAC_SECRET_LENGTH_BYTES];
        new SecureRandom().nextBytes(newSecret);
        try {
            byte[] encryptedSecret = kmsProvider.wrapNewHmacKey(newSecret);

            // 3. Persist new HMAC version (ACTIVE) — carry forward kmsKeyId/kmsProvider from the active row
            Instant rotateBy = Instant.now().plus(ROTATE_BY_DAYS, ChronoUnit.DAYS);
            KeyVersion newHmacVersion = KeyVersion.forHmac(
                    encryptedSecret, activeHmac.getKmsKeyId(), activeHmac.getKmsProvider(),
                    newKeyAlias, rotateBy, "hmac-rotation-service");
            keyVersionRepository.saveAndFlush(newHmacVersion);
            String newVersionId = newHmacVersion.getId().toString();

            // 4. Load into ring and promote — new tokenisations use new secret immediately
            hmacKeyRing.load(newVersionId, newSecret, rotateBy);
            hmacKeyRing.promoteActive(newVersionId);

            // 5. Audit
            auditLogger.logKeyEvent(
                    AuditEventType.HMAC_ROTATION_STARTED,
                    oldVersionId,
                    "SUCCESS",
                    "HMAC rotation started: old=[" + oldVersionId + "] → ROTATING, new=["
                            + newVersionId + "] → ACTIVE",
                    null);

            log.info("HMAC rotation initiated: rotating=[{}], new=[{}]", oldVersionId, newVersionId);
            return newHmacVersion.getId();
        } finally {
            Arrays.fill(newSecret, (byte) 0);
        }
    }

    /**
     * Completes a rotation cycle by retiring the old HMAC version.
     *
     * <p>Called by {@code HmacRotationJob} after all vault records have been re-hashed.
     * The old version is removed from the DB and zeroed in the in-memory ring.
     *
     * @param rotatingVersionId UUID of the ROTATING HMAC version to retire
     * @throws IllegalStateException if the version is not found in the repository
     */
    @Transactional
    public void completeRotation(UUID rotatingVersionId) {
        KeyVersion rotatingHmac = keyVersionRepository.findById(rotatingVersionId)
                .orElseThrow(() -> new IllegalStateException(
                        "HMAC version not found for retirement: " + rotatingVersionId));

        rotatingHmac.markRetired(Instant.now());
        keyVersionRepository.save(rotatingHmac);

        hmacKeyRing.retire(rotatingVersionId.toString());

        auditLogger.logKeyEvent(
                AuditEventType.HMAC_ROTATION_COMPLETED,
                rotatingVersionId,
                "SUCCESS",
                "HMAC rotation complete: version [" + rotatingVersionId + "] retired",
                null);

        log.info("HMAC rotation completed: version [{}] retired", rotatingVersionId);
    }
}
