package com.yourorg.tokenisation.rotation;

import com.yourorg.tokenisation.audit.AuditEventType;
import com.yourorg.tokenisation.audit.AuditLogger;
import com.yourorg.tokenisation.config.RotationProperties;
import com.yourorg.tokenisation.crypto.InMemoryDekKeyRing;
import com.yourorg.tokenisation.domain.KeyStatus;
import com.yourorg.tokenisation.domain.KeyType;
import com.yourorg.tokenisation.domain.KeyVersion;
import com.yourorg.tokenisation.domain.RotationReason;
import com.yourorg.tokenisation.kms.DataKey;
import com.yourorg.tokenisation.kms.KmsProvider;
import com.yourorg.tokenisation.repository.KeyVersionRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.UUID;

/**
 * Orchestrates both scheduled and emergency DEK rotation flows.
 */
@Service
@Slf4j
public class KeyRotationService {

    private final KeyVersionRepository keyVersionRepository;
    private final KmsProvider kmsProvider;
    private final InMemoryDekKeyRing dekRing;
    private final AuditLogger auditLogger;
    private final ApplicationEventPublisher eventPublisher;
    private final RotationProperties rotationProperties;

    public KeyRotationService(KeyVersionRepository keyVersionRepository,
                               KmsProvider kmsProvider,
                               InMemoryDekKeyRing dekRing,
                               AuditLogger auditLogger,
                               ApplicationEventPublisher eventPublisher,
                               RotationProperties rotationProperties) {
        this.keyVersionRepository = keyVersionRepository;
        this.kmsProvider = kmsProvider;
        this.dekRing = dekRing;
        this.auditLogger = auditLogger;
        this.eventPublisher = eventPublisher;
        this.rotationProperties = rotationProperties;
    }

    /**
     * Initiates a scheduled (compliance-driven) DEK rotation.
     *
     * <p>The current ACTIVE DEK transitions to ROTATING. A new ACTIVE DEK is created and
     * promoted in the ring — new tokenisations switch to the new key immediately.
     * Tokens encrypted under the old DEK are re-encrypted by the batch job.
     */
    @Transactional
    public void initiateScheduledRotation(String newKeyAlias, RotationReason rotationReason) {
        KeyVersion activeKey = keyVersionRepository.findActiveDekOrThrow();
        String oldKeyId = activeKey.getId().toString();
        log.info("Initiating scheduled rotation: old key [{}], alias [{}], reason [{}]",
                oldKeyId, newKeyAlias, rotationReason);

        activeKey.markRotating();
        keyVersionRepository.save(activeKey);
        keyVersionRepository.flush();

        KeyVersion newKey = buildNewDekVersion(newKeyAlias, activeKey, KeyStatus.ACTIVE, null);
        keyVersionRepository.save(newKey);

        final KeyVersion savedNewKey = newKey;
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    loadAndPromoteNewKey(savedNewKey);
                }
            });
        } else {
            loadAndPromoteNewKey(savedNewKey);
        }

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
     * <p>The compromised DEK is immediately blocked for detokenisation by marking it COMPROMISED
     * in both the database and the in-memory ring. A new ACTIVE DEK is created and promoted.
     */
    @Transactional
    public void initiateEmergencyRotation(UUID compromisedVersionId, String newKeyAlias) {
        KeyVersion compromisedKey = keyVersionRepository.findById(compromisedVersionId)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Key version not found: " + compromisedVersionId));

        log.warn("Emergency rotation initiated for compromised key [{}]", compromisedVersionId);

        Instant now = Instant.now();
        compromisedKey.markCompromised(now);
        keyVersionRepository.save(compromisedKey);
        keyVersionRepository.flush();
        dekRing.markCompromised(compromisedVersionId.toString());

        KeyVersion newKey = buildNewDekVersion(newKeyAlias, compromisedKey, KeyStatus.ACTIVE, null);
        keyVersionRepository.save(newKey);

        final KeyVersion savedNewKey = newKey;
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    loadAndPromoteNewKey(savedNewKey);
                }
            });
        } else {
            loadAndPromoteNewKey(savedNewKey);
        }

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

        eventPublisher.publishEvent(new SecurityAlertEvent(
                this,
                compromisedVersionId,
                "Key version " + compromisedVersionId + " compromised — emergency rotation initiated, new key: " + newKey.getId()));

        log.warn("Emergency rotation complete: compromised key [{}] blocked, new key [{}] active",
                compromisedVersionId, newKey.getId());
    }

    @Transactional(readOnly = true)
    public UUID getActiveKeyVersionId() {
        return keyVersionRepository.findActiveDekOrThrow().getId();
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private KeyVersion buildNewDekVersion(String alias, KeyVersion referenceKey,
                                          KeyStatus status, RotationReason rotationReason) {
        DataKey dataKey = kmsProvider.generateDataKey();
        byte[] encryptedDekBlob = dataKey.encryptedDekBlob().clone();
        Arrays.fill(dataKey.plaintextDek(), (byte) 0);

        Instant now = Instant.now();
        long maxAgeDays = rotationProperties.getCompliance().getMaxKeyAgeDays();
        return KeyVersion.builder()
                .keyType(KeyType.DEK)
                .kmsKeyId(referenceKey.getKmsKeyId())
                .kmsProvider(referenceKey.getKmsProvider())
                .keyAlias(alias)
                .encryptedDekBlob(encryptedDekBlob)
                .status(status)
                .rotationReason(rotationReason)
                .activatedAt(now)
                .rotateBy(now.plus(maxAgeDays, ChronoUnit.DAYS))
                .createdBy("rotation-service")
                .build();
    }

    private void loadAndPromoteNewKey(KeyVersion keyVersion) {
        String keyVersionId = keyVersion.getId().toString();
        byte[] dek = kmsProvider.decryptDataKey(keyVersion.getEncryptedDekBlob());
        try {
            dekRing.load(keyVersionId, dek, keyVersion.getRotateBy());
            dekRing.promoteActive(keyVersionId);
            log.info("New DEK version [{}] loaded into ring and promoted to active", keyVersionId);
        } finally {
            Arrays.fill(dek, (byte) 0);
        }
    }
}
