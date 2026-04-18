package com.yourorg.tokenisation.rotation;

import com.yourorg.tokenisation.audit.AuditEventType;
import com.yourorg.tokenisation.audit.AuditLogger;
import com.yourorg.tokenisation.config.RotationProperties;
import com.yourorg.tokenisation.crypto.InMemoryKeyRing;
import com.yourorg.tokenisation.crypto.TamperDetector;
import com.yourorg.tokenisation.domain.KeyStatus;
import com.yourorg.tokenisation.domain.KeyVersion;
import com.yourorg.tokenisation.domain.RotationReason;
import com.yourorg.tokenisation.exception.KeyIntegrityException;
import com.yourorg.tokenisation.kms.KmsProvider;
import com.yourorg.tokenisation.repository.KeyVersionRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.UUID;

/**
 * Orchestrates both scheduled and emergency key rotation flows.
 *
 * <h3>Scheduled rotation</h3>
 * <ol>
 *   <li>Verify integrity of the current {@code ACTIVE} key via {@link TamperDetector}.
 *   <li>Transition the old key to {@code ROTATING} in the database (so no two {@code ACTIVE}
 *       rows exist simultaneously — enforced by the partial unique index).
 *   <li>Create and persist a new {@code ACTIVE} key version using the same KMS key ID.
 *       A two-step save pattern is used because the UUID is only available after the first persist.
 *   <li>Load the new KEK into {@link InMemoryKeyRing} and promote it as active.
 *   <li>Write a {@code KEY_ROTATION_STARTED} audit event.
 * </ol>
 *
 * <h3>Emergency rotation</h3>
 * <ol>
 *   <li>Verify integrity of the compromised key.
 *   <li>Immediately transition the compromised key to {@code COMPROMISED} in the database.
 *   <li>Mark it {@code COMPROMISED} in the ring — this blocks all detokenisation calls
 *       for tokens encrypted under that key version.
 *   <li>Create and persist a new {@code ACTIVE} key version.
 *   <li>Load and promote the new key in the ring.
 *   <li>Write {@code EMERGENCY_ROTATION_STARTED} and {@code KEY_INTEGRITY_VIOLATION} audit events.
 *   <li>Publish a {@link SecurityAlertEvent} to notify the security team.
 * </ol>
 *
 * <h3>Checksum lifecycle</h3>
 * All key version status transitions update the checksum via the two-step pattern:
 * <ol>
 *   <li>Call the transition method (e.g. {@code markRotating("pending")}) and save.
 *   <li>Flush to ensure the UPDATE executes before any subsequent INSERT of a new ACTIVE key.
 *   <li>Compute the real checksum for the new state and call {@link KeyVersion#initializeChecksum}.
 *   <li>Save again.
 * </ol>
 *
 * <p><strong>Note:</strong> {@link TamperDetector#assertIntegrity} is deliberately NOT called
 * on the seed key loaded during startup — the seed row uses a placeholder checksum
 * ({@code "seed-checksum"}) that would fail verification. Integrity checks only apply
 * to key versions created or rotated by this service.
 */
@Service
@Slf4j
public class KeyRotationService {

    private final KeyVersionRepository keyVersionRepository;
    private final TamperDetector tamperDetector;
    private final KmsProvider kmsProvider;
    private final InMemoryKeyRing keyRing;
    private final AuditLogger auditLogger;
    private final ApplicationEventPublisher eventPublisher;
    private final RotationProperties rotationProperties;

    /**
     * Constructs the rotation service with all required collaborators.
     *
     * @param keyVersionRepository the repository for {@code key_versions}; must not be null
     * @param tamperDetector       HMAC integrity verifier; must not be null
     * @param kmsProvider          KMS adapter for KEK unwrap; must not be null
     * @param keyRing              in-memory key ring; must not be null
     * @param auditLogger          audit event writer; must not be null
     * @param eventPublisher       Spring event publisher for security alerts; must not be null
     * @param rotationProperties   rotation and compliance configuration; must not be null
     */
    public KeyRotationService(KeyVersionRepository keyVersionRepository,
                               TamperDetector tamperDetector,
                               KmsProvider kmsProvider,
                               InMemoryKeyRing keyRing,
                               AuditLogger auditLogger,
                               ApplicationEventPublisher eventPublisher,
                               RotationProperties rotationProperties) {
        this.keyVersionRepository = keyVersionRepository;
        this.tamperDetector = tamperDetector;
        this.kmsProvider = kmsProvider;
        this.keyRing = keyRing;
        this.auditLogger = auditLogger;
        this.eventPublisher = eventPublisher;
        this.rotationProperties = rotationProperties;
    }

    /**
     * Initiates a scheduled (compliance-driven) key rotation.
     *
     * <p>The current {@code ACTIVE} key is transitioned to {@code ROTATING}. A new
     * {@code ACTIVE} key version is created and immediately promoted in the ring — new
     * tokenisation operations switch to the new key atomically after the DB flush.
     * Tokens encrypted under the old key remain decryptable while the batch job
     * re-encrypts them.
     *
     * <p>This method is idempotent with respect to the ring state: if the new key
     * version is already loaded, {@link InMemoryKeyRing#load} replaces the entry
     * and {@link InMemoryKeyRing#promoteActive} updates the pointer.
     *
     * @param newKeyAlias human-readable alias for the new key version (e.g. {@code "tokenisation-key-2026"})
     * @param rotationReason the reason for rotation (typically {@link RotationReason#SCHEDULED} or {@link RotationReason#MANUAL})
     * @throws KeyIntegrityException if the current active key fails the integrity check
     * @throws IllegalStateException if no active key version exists
     */
    @Transactional
    public void initiateScheduledRotation(String newKeyAlias, RotationReason rotationReason) {
        KeyVersion activeKey = keyVersionRepository.findActiveOrThrow();
        tamperDetector.assertIntegrity(activeKey);

        String oldKeyId = activeKey.getId().toString();
        log.info("Initiating scheduled rotation: old key [{}], alias [{}], reason [{}]",
                oldKeyId, newKeyAlias, rotationReason);

        // Transition old key to ROTATING first — must flush before inserting new ACTIVE key
        // to avoid violating the partial unique index (only one ACTIVE row allowed).
        transitionKeyStatus(activeKey, KeyStatus.ROTATING, rotationReason, null);
        keyVersionRepository.flush();

        // Create and persist new ACTIVE key version (2-step checksum pattern)
        KeyVersion newKey = buildNewKeyVersion(newKeyAlias, activeKey, KeyStatus.ACTIVE, null);
        persistWithChecksum(newKey);

        // Load new KEK into ring and promote — new tokenisations switch immediately
        loadAndPromoteNewKey(newKey);

        auditLogger.logKeyEvent(
                AuditEventType.KEY_ROTATION_STARTED,
                activeKey.getId(),
                "SUCCESS",
                "Scheduled rotation: old key [" + oldKeyId + "] → ROTATING, new key ["
                        + newKey.getId() + "] → ACTIVE",
                null);

        log.info("Scheduled rotation initiated: old key [{}] → ROTATING, new key [{}] → ACTIVE",
                oldKeyId, newKey.getId());
    }

    /**
     * Initiates an emergency rotation in response to a detected key compromise.
     *
     * <p>The compromised key is immediately blocked for detokenisation by marking it
     * {@code COMPROMISED} in both the database and the in-memory ring. A new {@code ACTIVE}
     * key is created and promoted. A {@link SecurityAlertEvent} is published so that
     * the configured security alert listener can notify the security team.
     *
     * @param compromisedVersionId the UUID of the key version that was compromised; must exist
     * @param newKeyAlias          human-readable alias for the replacement key version
     * @throws KeyIntegrityException    if the compromised key itself fails the integrity check
     *                                  (i.e. the checksum is also tampered)
     * @throws IllegalArgumentException if no key version exists with the given ID
     */
    @Transactional
    public void initiateEmergencyRotation(UUID compromisedVersionId, String newKeyAlias) {
        KeyVersion compromisedKey = keyVersionRepository.findById(compromisedVersionId)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Key version not found: " + compromisedVersionId));

        // Integrity check even on the compromised key — the checksum itself may have been tampered.
        // If the checksum is also corrupted, we log the additional tamper and proceed regardless.
        try {
            tamperDetector.assertIntegrity(compromisedKey);
        } catch (KeyIntegrityException checksumTamperedToo) {
            log.error("Compromised key [{}] also has a tampered checksum — proceeding with emergency rotation",
                    compromisedVersionId);
        }

        log.warn("Emergency rotation initiated for compromised key [{}]", compromisedVersionId);

        // Step 1: Mark compromised in DB and ring immediately — blocks detokenisation
        Instant now = Instant.now();
        transitionKeyStatus(compromisedKey, KeyStatus.COMPROMISED, RotationReason.COMPROMISE, now);
        keyVersionRepository.flush();
        keyRing.markCompromised(compromisedVersionId.toString());

        // Step 2: Create and persist new ACTIVE key version
        KeyVersion newKey = buildNewKeyVersion(newKeyAlias, compromisedKey, KeyStatus.ACTIVE, null);
        persistWithChecksum(newKey);

        // Step 3: Load new KEK into ring and promote immediately
        loadAndPromoteNewKey(newKey);

        // Step 4: Audit
        auditLogger.logKeyEvent(
                AuditEventType.KEY_INTEGRITY_VIOLATION,
                compromisedVersionId,
                "FAILURE",
                "Key version " + compromisedVersionId + " marked COMPROMISED — emergency rotation initiated",
                null);
        auditLogger.logKeyEvent(
                AuditEventType.EMERGENCY_ROTATION_STARTED,
                newKey.getId(),
                "SUCCESS",
                "Emergency rotation: compromised key [" + compromisedVersionId + "] replaced by ["
                        + newKey.getId() + "]",
                null);

        // Step 5: Notify security team
        eventPublisher.publishEvent(new SecurityAlertEvent(
                this,
                compromisedVersionId,
                "Key version " + compromisedVersionId + " compromised — emergency rotation initiated, new key: " + newKey.getId()));

        log.warn("Emergency rotation complete: compromised key [{}] blocked, new key [{}] active",
                compromisedVersionId, newKey.getId());
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /**
     * Transitions a key version to the given status, updating its checksum accordingly.
     *
     * <p>Two saves are required:
     * <ol>
     *   <li>Transition with a placeholder checksum so the status change is visible to
     *       the checksum computation.
     *   <li>Compute the real checksum for the new status and save again.
     * </ol>
     *
     * @param key            the key version to transition
     * @param targetStatus   the new status
     * @param reason         the rotation reason; may be null for non-rotation transitions
     * @param retiredAt      the retirement/compromise timestamp; used for RETIRED/COMPROMISED; may be null
     */
    private void transitionKeyStatus(KeyVersion key, KeyStatus targetStatus,
                                     RotationReason reason, Instant retiredAt) {
        switch (targetStatus) {
            case ROTATING -> key.markRotating("pending");
            case RETIRED  -> key.markRetired(retiredAt != null ? retiredAt : Instant.now(), "pending");
            case COMPROMISED -> key.markCompromised(retiredAt != null ? retiredAt : Instant.now(), "pending");
            default -> throw new IllegalArgumentException("Unsupported target status: " + targetStatus);
        }
        keyVersionRepository.save(key);
        // Compute real checksum now that the entity reflects the new status
        key.initializeChecksum(tamperDetector.computeChecksum(key));
        keyVersionRepository.save(key);
    }

    /**
     * Creates an unsaved {@link KeyVersion} for the new key, copying KMS config from
     * the reference key. A placeholder checksum ({@code "pending"}) is set — the caller
     * must call {@link #persistWithChecksum} to assign the real checksum after the UUID
     * is generated by the database.
     *
     * @param alias           human-readable alias for the new key version
     * @param referenceKey    the existing key to copy {@code kmsKeyId}, {@code kmsProvider},
     *                        and {@code encryptedKekBlob} from
     * @param status          the initial status for the new key (typically {@code ACTIVE})
     * @param rotationReason  reason for this key version's creation; may be null
     * @return a new, unsaved {@link KeyVersion}
     */
    private KeyVersion buildNewKeyVersion(String alias,
                                          KeyVersion referenceKey,
                                          KeyStatus status,
                                          RotationReason rotationReason) {
        Instant now = Instant.now();
        long maxAgeDays = rotationProperties.getCompliance().getMaxKeyAgeDays();
        return KeyVersion.builder()
                .kmsKeyId(referenceKey.getKmsKeyId())
                .kmsProvider(referenceKey.getKmsProvider())
                .keyAlias(alias)
                .encryptedKekBlob(referenceKey.getEncryptedKekBlob())
                .status(status)
                .rotationReason(rotationReason)
                .activatedAt(now)
                .rotateBy(now.plus(maxAgeDays, ChronoUnit.DAYS))
                .createdBy("rotation-service")
                .checksum("pending")
                .build();
    }

    /**
     * Persists a new key version using the two-step checksum pattern.
     *
     * <ol>
     *   <li>First save assigns the JPA-generated UUID.
     *   <li>Compute the real HMAC-SHA256 checksum using the assigned UUID.
     *   <li>Second save persists the real checksum.
     * </ol>
     *
     * @param keyVersion the key version to persist; must not already be managed by JPA
     */
    private void persistWithChecksum(KeyVersion keyVersion) {
        keyVersionRepository.save(keyVersion);   // step 1: UUID assigned
        keyVersion.initializeChecksum(tamperDetector.computeChecksum(keyVersion));
        keyVersionRepository.save(keyVersion);   // step 2: real checksum persisted
    }

    /**
     * Unwraps the KEK for the given key version from KMS, loads it into the ring,
     * and promotes the version as the active key.
     *
     * <p>The raw KEK bytes are zeroed immediately after being passed to the ring,
     * regardless of whether the operation succeeds.
     *
     * @param keyVersion the new key version whose KEK should be loaded and promoted
     */
    private void loadAndPromoteNewKey(KeyVersion keyVersion) {
        String keyVersionId = keyVersion.getId().toString();
        byte[] kek = kmsProvider.unwrapKek(keyVersion.getEncryptedKekBlob());
        try {
            keyRing.load(keyVersionId, kek, keyVersion.getRotateBy());
            keyRing.promoteActive(keyVersionId);
            log.info("New key version [{}] loaded into ring and promoted to active", keyVersionId);
        } finally {
            Arrays.fill(kek, (byte) 0);
        }
    }
}
