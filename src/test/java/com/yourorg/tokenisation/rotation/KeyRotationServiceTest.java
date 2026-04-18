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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;

import java.lang.reflect.Field;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link KeyRotationService}.
 *
 * <p>All collaborators are mocked. Tests verify:
 * <ul>
 *   <li>Scheduled rotation: old key transitions to ROTATING, new key created as ACTIVE
 *   <li>Scheduled rotation: ring is loaded and promoted
 *   <li>Scheduled rotation: audit event written
 *   <li>Scheduled rotation: integrity check fails — throws {@link KeyIntegrityException}
 *   <li>Emergency rotation: compromised key marked in DB and ring
 *   <li>Emergency rotation: new key loaded and promoted
 *   <li>Emergency rotation: security alert event published
 *   <li>Emergency rotation: audit events written
 *   <li>Emergency rotation: proceeds even if compromised key's checksum is also tampered
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class KeyRotationServiceTest {

    private static final UUID ACTIVE_KEY_ID = UUID.fromString("aaaaaaaa-0000-0000-0000-000000000001");
    private static final UUID NEW_KEY_ID    = UUID.fromString("bbbbbbbb-0000-0000-0000-000000000002");
    private static final byte[] DUMMY_KEK   = new byte[32];

    @Mock private KeyVersionRepository keyVersionRepository;
    @Mock private TamperDetector tamperDetector;
    @Mock private KmsProvider kmsProvider;
    @Mock private InMemoryKeyRing keyRing;
    @Mock private AuditLogger auditLogger;
    @Mock private ApplicationEventPublisher eventPublisher;

    private KeyRotationService service;

    @BeforeEach
    void setUp() {
        RotationProperties props = new RotationProperties();
        props.getCompliance().setMaxKeyAgeDays(365);
        service = new KeyRotationService(keyVersionRepository, tamperDetector, kmsProvider,
                keyRing, auditLogger, eventPublisher, props);
    }

    // ── Scheduled rotation ────────────────────────────────────────────────────

    @Test
    void initiateScheduledRotation_transitionsOldKeyToRotating() {
        KeyVersion activeKey = buildKeyVersion(ACTIVE_KEY_ID, KeyStatus.ACTIVE);
        stubSaveToAssignId(NEW_KEY_ID);
        when(keyVersionRepository.findActiveOrThrow()).thenReturn(activeKey);
        when(kmsProvider.unwrapKek(any())).thenReturn(DUMMY_KEK.clone());
        when(tamperDetector.computeChecksum(any())).thenReturn("computed-checksum");

        service.initiateScheduledRotation("new-key-alias", RotationReason.SCHEDULED);

        assertThat(activeKey.getStatus()).isEqualTo(KeyStatus.ROTATING);
    }

    @Test
    void initiateScheduledRotation_loadsAndPromotesNewKeyInRing() {
        KeyVersion activeKey = buildKeyVersion(ACTIVE_KEY_ID, KeyStatus.ACTIVE);
        stubSaveToAssignId(NEW_KEY_ID);
        when(keyVersionRepository.findActiveOrThrow()).thenReturn(activeKey);
        when(kmsProvider.unwrapKek(any())).thenReturn(DUMMY_KEK.clone());
        when(tamperDetector.computeChecksum(any())).thenReturn("some-checksum");

        service.initiateScheduledRotation("new-key-alias", RotationReason.SCHEDULED);

        verify(keyRing).load(eq(NEW_KEY_ID.toString()), any(), any());
        verify(keyRing).promoteActive(NEW_KEY_ID.toString());
    }

    @Test
    void initiateScheduledRotation_writesKeyRotationStartedAuditEvent() {
        KeyVersion activeKey = buildKeyVersion(ACTIVE_KEY_ID, KeyStatus.ACTIVE);
        stubSaveToAssignId(NEW_KEY_ID);
        when(keyVersionRepository.findActiveOrThrow()).thenReturn(activeKey);
        when(kmsProvider.unwrapKek(any())).thenReturn(DUMMY_KEK.clone());
        when(tamperDetector.computeChecksum(any())).thenReturn("checksum");

        service.initiateScheduledRotation("new-key-alias", RotationReason.SCHEDULED);

        ArgumentCaptor<AuditEventType> eventCaptor = ArgumentCaptor.forClass(AuditEventType.class);
        verify(auditLogger).logKeyEvent(eventCaptor.capture(), any(), any(), any(), any());
        assertThat(eventCaptor.getValue()).isEqualTo(AuditEventType.KEY_ROTATION_STARTED);
    }

    @Test
    void initiateScheduledRotation_integritycheckFails_throwsKeyIntegrityException() {
        KeyVersion activeKey = buildKeyVersion(ACTIVE_KEY_ID, KeyStatus.ACTIVE);
        when(keyVersionRepository.findActiveOrThrow()).thenReturn(activeKey);
        doThrow(new KeyIntegrityException("checksum mismatch"))
                .when(tamperDetector).assertIntegrity(activeKey);

        assertThatThrownBy(() -> service.initiateScheduledRotation("alias", RotationReason.SCHEDULED))
                .isInstanceOf(KeyIntegrityException.class);

        verify(keyRing, never()).promoteActive(any());
    }

    @Test
    void initiateScheduledRotation_kekZeroedAfterRingLoad() {
        // Verify the byte array returned by unwrapKek is zeroed after loading into the ring.
        // We check this by capturing the array passed to keyRing.load — it must be all zeros
        // because the service fills it after loading.
        byte[] capturedKek = new byte[32];
        capturedKek[0] = 0x42; // non-zero sentinel
        KeyVersion activeKey = buildKeyVersion(ACTIVE_KEY_ID, KeyStatus.ACTIVE);
        stubSaveToAssignId(NEW_KEY_ID);
        when(keyVersionRepository.findActiveOrThrow()).thenReturn(activeKey);
        when(kmsProvider.unwrapKek(any())).thenReturn(capturedKek);
        when(tamperDetector.computeChecksum(any())).thenReturn("checksum");

        service.initiateScheduledRotation("alias", RotationReason.SCHEDULED);

        // After the method completes, capturedKek should be zeroed
        assertThat(capturedKek).containsOnly((byte) 0);
    }

    // ── Emergency rotation ────────────────────────────────────────────────────

    @Test
    void initiateEmergencyRotation_marksCompromisedKeyInDb() {
        KeyVersion compromisedKey = buildKeyVersion(ACTIVE_KEY_ID, KeyStatus.ACTIVE);
        stubSaveToAssignId(NEW_KEY_ID);
        when(keyVersionRepository.findById(ACTIVE_KEY_ID)).thenReturn(Optional.of(compromisedKey));
        when(kmsProvider.unwrapKek(any())).thenReturn(DUMMY_KEK.clone());
        when(tamperDetector.computeChecksum(any())).thenReturn("checksum");

        service.initiateEmergencyRotation(ACTIVE_KEY_ID, "emergency-key");

        assertThat(compromisedKey.getStatus()).isEqualTo(KeyStatus.COMPROMISED);
    }

    @Test
    void initiateEmergencyRotation_marksCompromisedKeyInRing() {
        KeyVersion compromisedKey = buildKeyVersion(ACTIVE_KEY_ID, KeyStatus.ACTIVE);
        stubSaveToAssignId(NEW_KEY_ID);
        when(keyVersionRepository.findById(ACTIVE_KEY_ID)).thenReturn(Optional.of(compromisedKey));
        when(kmsProvider.unwrapKek(any())).thenReturn(DUMMY_KEK.clone());
        when(tamperDetector.computeChecksum(any())).thenReturn("checksum");

        service.initiateEmergencyRotation(ACTIVE_KEY_ID, "emergency-key");

        verify(keyRing).markCompromised(ACTIVE_KEY_ID.toString());
    }

    @Test
    void initiateEmergencyRotation_loadsAndPromotesNewKeyInRing() {
        KeyVersion compromisedKey = buildKeyVersion(ACTIVE_KEY_ID, KeyStatus.ACTIVE);
        stubSaveToAssignId(NEW_KEY_ID);
        when(keyVersionRepository.findById(ACTIVE_KEY_ID)).thenReturn(Optional.of(compromisedKey));
        when(kmsProvider.unwrapKek(any())).thenReturn(DUMMY_KEK.clone());
        when(tamperDetector.computeChecksum(any())).thenReturn("checksum");

        service.initiateEmergencyRotation(ACTIVE_KEY_ID, "emergency-key");

        verify(keyRing).load(eq(NEW_KEY_ID.toString()), any(), any());
        verify(keyRing).promoteActive(NEW_KEY_ID.toString());
    }

    @Test
    void initiateEmergencyRotation_writesEmergencyRotationStartedAudit() {
        KeyVersion compromisedKey = buildKeyVersion(ACTIVE_KEY_ID, KeyStatus.ACTIVE);
        stubSaveToAssignId(NEW_KEY_ID);
        when(keyVersionRepository.findById(ACTIVE_KEY_ID)).thenReturn(Optional.of(compromisedKey));
        when(kmsProvider.unwrapKek(any())).thenReturn(DUMMY_KEK.clone());
        when(tamperDetector.computeChecksum(any())).thenReturn("checksum");

        service.initiateEmergencyRotation(ACTIVE_KEY_ID, "emergency-key");

        ArgumentCaptor<AuditEventType> eventCaptor = ArgumentCaptor.forClass(AuditEventType.class);
        verify(auditLogger, atLeastOnce()).logKeyEvent(eventCaptor.capture(), any(), any(), any(), any());
        assertThat(eventCaptor.getAllValues())
                .contains(AuditEventType.EMERGENCY_ROTATION_STARTED)
                .contains(AuditEventType.KEY_INTEGRITY_VIOLATION);
    }

    @Test
    void initiateEmergencyRotation_publishesSecurityAlertEvent() {
        KeyVersion compromisedKey = buildKeyVersion(ACTIVE_KEY_ID, KeyStatus.ACTIVE);
        stubSaveToAssignId(NEW_KEY_ID);
        when(keyVersionRepository.findById(ACTIVE_KEY_ID)).thenReturn(Optional.of(compromisedKey));
        when(kmsProvider.unwrapKek(any())).thenReturn(DUMMY_KEK.clone());
        when(tamperDetector.computeChecksum(any())).thenReturn("checksum");

        service.initiateEmergencyRotation(ACTIVE_KEY_ID, "emergency-key");

        ArgumentCaptor<SecurityAlertEvent> eventCaptor = ArgumentCaptor.forClass(SecurityAlertEvent.class);
        verify(eventPublisher).publishEvent(eventCaptor.capture());
        assertThat(eventCaptor.getValue().getCompromisedKeyVersionId()).isEqualTo(ACTIVE_KEY_ID);
    }

    @Test
    void initiateEmergencyRotation_proceededEvenIfCompromisedKeyChecksumAlsoTampered() {
        // If the checksum on the compromised key is ALSO tampered, the emergency rotation
        // should still proceed — the compromise response is more important than the checksum.
        KeyVersion compromisedKey = buildKeyVersion(ACTIVE_KEY_ID, KeyStatus.ACTIVE);
        stubSaveToAssignId(NEW_KEY_ID);
        when(keyVersionRepository.findById(ACTIVE_KEY_ID)).thenReturn(Optional.of(compromisedKey));
        doThrow(new KeyIntegrityException("checksum also tampered"))
                .when(tamperDetector).assertIntegrity(compromisedKey);
        when(kmsProvider.unwrapKek(any())).thenReturn(DUMMY_KEK.clone());
        when(tamperDetector.computeChecksum(any())).thenReturn("checksum");

        // Should NOT throw — proceeds despite the integrity exception on the compromised key
        service.initiateEmergencyRotation(ACTIVE_KEY_ID, "emergency-key");

        verify(keyRing).markCompromised(ACTIVE_KEY_ID.toString());
        verify(keyRing).promoteActive(NEW_KEY_ID.toString());
    }

    @Test
    void initiateEmergencyRotation_unknownKeyVersionId_throwsIllegalArgumentException() {
        when(keyVersionRepository.findById(ACTIVE_KEY_ID)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.initiateEmergencyRotation(ACTIVE_KEY_ID, "alias"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining(ACTIVE_KEY_ID.toString());
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private KeyVersion buildKeyVersion(UUID id, KeyStatus status) {
        KeyVersion kv = KeyVersion.builder()
                .kmsKeyId("local-dev-key")
                .kmsProvider("LOCAL_DEV")
                .keyAlias("test-key")
                .encryptedKekBlob("local-dev-key")
                .status(status)
                .activatedAt(Instant.now().minusSeconds(3600))
                .rotateBy(Instant.now().plusSeconds(86400 * 365))
                .createdBy("test")
                .checksum("valid-checksum")
                .build();
        try {
            Field idField = KeyVersion.class.getDeclaredField("id");
            idField.setAccessible(true);
            idField.set(kv, id);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException("Failed to set id on KeyVersion", e);
        }
        return kv;
    }

    /**
     * Stubs {@code keyVersionRepository.save()} to assign the given UUID to the saved
     * {@code KeyVersion} entity (simulating JPA's UUID generation on first persist).
     * Subsequent save() calls (for checksum updates) return the same entity unchanged.
     */
    private void stubSaveToAssignId(UUID newId) {
        when(keyVersionRepository.save(any(KeyVersion.class))).thenAnswer(invocation -> {
            KeyVersion kv = invocation.getArgument(0);
            if (kv.getId() == null) {
                try {
                    Field idField = KeyVersion.class.getDeclaredField("id");
                    idField.setAccessible(true);
                    idField.set(kv, newId);
                } catch (ReflectiveOperationException e) {
                    throw new RuntimeException(e);
                }
            }
            return kv;
        });
    }
}
