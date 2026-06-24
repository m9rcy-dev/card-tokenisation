package com.yourorg.tokenisation.rotation;

import com.yourorg.tokenisation.audit.AuditEventType;
import com.yourorg.tokenisation.audit.AuditLogger;
import com.yourorg.tokenisation.config.RotationProperties;
import com.yourorg.tokenisation.crypto.InMemoryDekKeyRing;
import com.yourorg.tokenisation.domain.KeyStatus;
import com.yourorg.tokenisation.domain.KeyVersion;
import com.yourorg.tokenisation.domain.RotationReason;
import com.yourorg.tokenisation.kms.DataKey;
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
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link KeyRotationService}.
 *
 * <p>All collaborators are mocked. Tests verify:
 * <ul>
 *   <li>Scheduled rotation: old key transitions to ROTATING, new key created as ACTIVE
 *   <li>Scheduled rotation: ring is loaded and promoted
 *   <li>Scheduled rotation: audit event written
 *   <li>Emergency rotation: compromised key marked in DB and ring
 *   <li>Emergency rotation: new key loaded and promoted
 *   <li>Emergency rotation: security alert event published
 *   <li>Emergency rotation: audit events written
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class KeyRotationServiceTest {

    private static final UUID ACTIVE_KEY_ID = UUID.fromString("aaaaaaaa-0000-0000-0000-000000000001");
    private static final UUID NEW_KEY_ID    = UUID.fromString("bbbbbbbb-0000-0000-0000-000000000002");
    private static final byte[] DUMMY_DEK   = new byte[32];

    @Mock private KeyVersionRepository keyVersionRepository;
    @Mock private KmsProvider kmsProvider;
    @Mock private InMemoryDekKeyRing dekRing;
    @Mock private AuditLogger auditLogger;
    @Mock private ApplicationEventPublisher eventPublisher;

    private KeyRotationService service;

    @BeforeEach
    void setUp() {
        RotationProperties props = new RotationProperties();
        props.getCompliance().setMaxKeyAgeDays(365);
        service = new KeyRotationService(keyVersionRepository, kmsProvider,
                dekRing, auditLogger, eventPublisher, props);
    }

    // ── Scheduled rotation ────────────────────────────────────────────────────

    @Test
    void initiateScheduledRotation_transitionsOldKeyToRotating() {
        KeyVersion activeKey = buildKeyVersion(ACTIVE_KEY_ID, KeyStatus.ACTIVE);
        stubGenerateDataKey();
        stubSaveToAssignId(NEW_KEY_ID);
        when(keyVersionRepository.findActiveDekOrThrow()).thenReturn(activeKey);
        when(kmsProvider.decryptDataKey(any(byte[].class))).thenReturn(DUMMY_DEK.clone());

        service.initiateScheduledRotation("new-key-alias", RotationReason.SCHEDULED);

        assertThat(activeKey.getStatus()).isEqualTo(KeyStatus.ROTATING);
    }

    @Test
    void initiateScheduledRotation_loadsAndPromotesNewKeyInRing() {
        KeyVersion activeKey = buildKeyVersion(ACTIVE_KEY_ID, KeyStatus.ACTIVE);
        stubGenerateDataKey();
        stubSaveToAssignId(NEW_KEY_ID);
        when(keyVersionRepository.findActiveDekOrThrow()).thenReturn(activeKey);
        when(kmsProvider.decryptDataKey(any(byte[].class))).thenReturn(DUMMY_DEK.clone());

        service.initiateScheduledRotation("new-key-alias", RotationReason.SCHEDULED);

        verify(dekRing).load(eq(NEW_KEY_ID.toString()), any(), any());
        verify(dekRing).promoteActive(NEW_KEY_ID.toString());
    }

    @Test
    void initiateScheduledRotation_writesKeyRotationStartedAuditEvent() {
        KeyVersion activeKey = buildKeyVersion(ACTIVE_KEY_ID, KeyStatus.ACTIVE);
        stubGenerateDataKey();
        stubSaveToAssignId(NEW_KEY_ID);
        when(keyVersionRepository.findActiveDekOrThrow()).thenReturn(activeKey);
        when(kmsProvider.decryptDataKey(any(byte[].class))).thenReturn(DUMMY_DEK.clone());

        service.initiateScheduledRotation("new-key-alias", RotationReason.SCHEDULED);

        ArgumentCaptor<AuditEventType> eventCaptor = ArgumentCaptor.forClass(AuditEventType.class);
        verify(auditLogger).logKeyEvent(eventCaptor.capture(), any(), any(), any(), any());
        assertThat(eventCaptor.getValue()).isEqualTo(AuditEventType.KEY_ROTATION_STARTED);
    }

    @Test
    void initiateScheduledRotation_plaintextDekZeroedAfterRingLoad() {
        byte[] capturedDek = new byte[32];
        capturedDek[0] = 0x42;
        KeyVersion activeKey = buildKeyVersion(ACTIVE_KEY_ID, KeyStatus.ACTIVE);
        when(kmsProvider.generateDataKey())
                .thenReturn(new DataKey(capturedDek, new byte[60]));
        stubSaveToAssignId(NEW_KEY_ID);
        when(keyVersionRepository.findActiveDekOrThrow()).thenReturn(activeKey);
        when(kmsProvider.decryptDataKey(any(byte[].class))).thenReturn(DUMMY_DEK.clone());

        service.initiateScheduledRotation("alias", RotationReason.SCHEDULED);

        assertThat(capturedDek).containsOnly((byte) 0);
    }

    // ── Emergency rotation ────────────────────────────────────────────────────

    @Test
    void initiateEmergencyRotation_marksCompromisedKeyInDb() {
        KeyVersion compromisedKey = buildKeyVersion(ACTIVE_KEY_ID, KeyStatus.ACTIVE);
        stubGenerateDataKey();
        stubSaveToAssignId(NEW_KEY_ID);
        when(keyVersionRepository.findById(ACTIVE_KEY_ID)).thenReturn(Optional.of(compromisedKey));
        when(kmsProvider.decryptDataKey(any(byte[].class))).thenReturn(DUMMY_DEK.clone());

        service.initiateEmergencyRotation(ACTIVE_KEY_ID, "emergency-key");

        assertThat(compromisedKey.getStatus()).isEqualTo(KeyStatus.COMPROMISED);
    }

    @Test
    void initiateEmergencyRotation_marksCompromisedKeyInRing() {
        KeyVersion compromisedKey = buildKeyVersion(ACTIVE_KEY_ID, KeyStatus.ACTIVE);
        stubGenerateDataKey();
        stubSaveToAssignId(NEW_KEY_ID);
        when(keyVersionRepository.findById(ACTIVE_KEY_ID)).thenReturn(Optional.of(compromisedKey));
        when(kmsProvider.decryptDataKey(any(byte[].class))).thenReturn(DUMMY_DEK.clone());

        service.initiateEmergencyRotation(ACTIVE_KEY_ID, "emergency-key");

        verify(dekRing).markCompromised(ACTIVE_KEY_ID.toString());
    }

    @Test
    void initiateEmergencyRotation_loadsAndPromotesNewKeyInRing() {
        KeyVersion compromisedKey = buildKeyVersion(ACTIVE_KEY_ID, KeyStatus.ACTIVE);
        stubGenerateDataKey();
        stubSaveToAssignId(NEW_KEY_ID);
        when(keyVersionRepository.findById(ACTIVE_KEY_ID)).thenReturn(Optional.of(compromisedKey));
        when(kmsProvider.decryptDataKey(any(byte[].class))).thenReturn(DUMMY_DEK.clone());

        service.initiateEmergencyRotation(ACTIVE_KEY_ID, "emergency-key");

        verify(dekRing).load(eq(NEW_KEY_ID.toString()), any(), any());
        verify(dekRing).promoteActive(NEW_KEY_ID.toString());
    }

    @Test
    void initiateEmergencyRotation_writesEmergencyRotationStartedAndKeyIntegrityViolationAudit() {
        KeyVersion compromisedKey = buildKeyVersion(ACTIVE_KEY_ID, KeyStatus.ACTIVE);
        stubGenerateDataKey();
        stubSaveToAssignId(NEW_KEY_ID);
        when(keyVersionRepository.findById(ACTIVE_KEY_ID)).thenReturn(Optional.of(compromisedKey));
        when(kmsProvider.decryptDataKey(any(byte[].class))).thenReturn(DUMMY_DEK.clone());

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
        stubGenerateDataKey();
        stubSaveToAssignId(NEW_KEY_ID);
        when(keyVersionRepository.findById(ACTIVE_KEY_ID)).thenReturn(Optional.of(compromisedKey));
        when(kmsProvider.decryptDataKey(any(byte[].class))).thenReturn(DUMMY_DEK.clone());

        service.initiateEmergencyRotation(ACTIVE_KEY_ID, "emergency-key");

        ArgumentCaptor<SecurityAlertEvent> eventCaptor = ArgumentCaptor.forClass(SecurityAlertEvent.class);
        verify(eventPublisher).publishEvent(eventCaptor.capture());
        assertThat(eventCaptor.getValue().getCompromisedKeyVersionId()).isEqualTo(ACTIVE_KEY_ID);
    }

    @Test
    void initiateEmergencyRotation_unknownKeyVersionId_throwsIllegalArgumentException() {
        when(keyVersionRepository.findById(ACTIVE_KEY_ID)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.initiateEmergencyRotation(ACTIVE_KEY_ID, "alias"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining(ACTIVE_KEY_ID.toString());
    }

    // ── getActiveKeyVersionId ─────────────────────────────────────────────────

    @Test
    void getActiveKeyVersionId_activeKeyExists_returnsItsUuid() {
        KeyVersion activeKey = buildKeyVersion(ACTIVE_KEY_ID, KeyStatus.ACTIVE);
        when(keyVersionRepository.findActiveDekOrThrow()).thenReturn(activeKey);

        assertThat(service.getActiveKeyVersionId()).isEqualTo(ACTIVE_KEY_ID);
    }

    @Test
    void getActiveKeyVersionId_noActiveKey_propagatesIllegalStateException() {
        when(keyVersionRepository.findActiveDekOrThrow())
                .thenThrow(new IllegalStateException("No ACTIVE DEK version found"));

        assertThatThrownBy(() -> service.getActiveKeyVersionId())
                .isInstanceOf(IllegalStateException.class);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private void stubGenerateDataKey() {
        when(kmsProvider.generateDataKey())
                .thenReturn(new DataKey(new byte[32], new byte[60]));
    }

    private KeyVersion buildKeyVersion(UUID id, KeyStatus status) {
        KeyVersion kv = KeyVersion.builder()
                .kmsKeyId("local-dev-key")
                .kmsProvider("LOCAL_DEV")
                .keyAlias("test-key")
                .encryptedDekBlob(new byte[60])
                .status(status)
                .activatedAt(Instant.now().minusSeconds(3600))
                .rotateBy(Instant.now().plusSeconds(86400 * 365))
                .createdBy("test")
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
