package com.yourorg.tokenisation.crypto;

import com.yourorg.tokenisation.audit.AuditEventType;
import com.yourorg.tokenisation.audit.AuditLogger;
import com.yourorg.tokenisation.config.TamperDetectionProperties;
import com.yourorg.tokenisation.domain.KeyStatus;
import com.yourorg.tokenisation.domain.KeyVersion;
import com.yourorg.tokenisation.exception.KeyIntegrityException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * Unit tests for {@link TamperDetector}.
 *
 * <p>Tests cover:
 * <ul>
 *   <li>Checksum is a non-null 64-character hex string
 *   <li>Same inputs always produce the same checksum (determinism)
 *   <li>Different field values produce different checksums
 *   <li>{@link TamperDetector#assertIntegrity} passes on an unmodified row
 *   <li>{@link TamperDetector#assertIntegrity} throws {@link KeyIntegrityException} on mismatch
 *   <li>{@link TamperDetector#assertIntegrity} writes a {@code TAMPER_ALERT} audit event on mismatch
 *   <li>No audit event written when integrity check passes
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class TamperDetectorTest {

    private static final String SIGNING_SECRET = "test-tamper-secret-32-bytes!!!!!";
    private static final UUID KEY_ID = UUID.fromString("11111111-2222-3333-4444-555555555555");

    @Mock
    private AuditLogger auditLogger;

    private TamperDetector tamperDetector;

    @BeforeEach
    void setUp() {
        TamperDetectionProperties properties = new TamperDetectionProperties();
        properties.setSigningSecret(SIGNING_SECRET);
        tamperDetector = new TamperDetector(properties, auditLogger);
    }

    // ── computeChecksum ───────────────────────────────────────────────────────

    @Test
    void computeChecksum_returnsNonNullHexString() {
        KeyVersion kv = buildKeyVersion(KEY_ID, "kms-key-arn", KeyStatus.ACTIVE, Instant.EPOCH);

        String checksum = tamperDetector.computeChecksum(kv);

        assertThat(checksum).isNotNull().hasSize(64).matches("[0-9a-f]+");
    }

    @Test
    void computeChecksum_isDeterministic_sameInputProducesSameChecksum() {
        KeyVersion kv1 = buildKeyVersion(KEY_ID, "kms-key-arn", KeyStatus.ACTIVE, Instant.EPOCH);
        KeyVersion kv2 = buildKeyVersion(KEY_ID, "kms-key-arn", KeyStatus.ACTIVE, Instant.EPOCH);

        assertThat(tamperDetector.computeChecksum(kv1))
                .isEqualTo(tamperDetector.computeChecksum(kv2));
    }

    @Test
    void computeChecksum_differentId_producesDifferentChecksum() {
        KeyVersion kv1 = buildKeyVersion(KEY_ID, "kms-key-arn", KeyStatus.ACTIVE, Instant.EPOCH);
        KeyVersion kv2 = buildKeyVersion(UUID.randomUUID(), "kms-key-arn", KeyStatus.ACTIVE, Instant.EPOCH);

        assertThat(tamperDetector.computeChecksum(kv1))
                .isNotEqualTo(tamperDetector.computeChecksum(kv2));
    }

    @Test
    void computeChecksum_differentKmsKeyId_producesDifferentChecksum() {
        KeyVersion kv1 = buildKeyVersion(KEY_ID, "arn:aws:kms:ap-southeast-2:111:key/aaa", KeyStatus.ACTIVE, Instant.EPOCH);
        KeyVersion kv2 = buildKeyVersion(KEY_ID, "arn:aws:kms:ap-southeast-2:111:key/bbb", KeyStatus.ACTIVE, Instant.EPOCH);

        assertThat(tamperDetector.computeChecksum(kv1))
                .isNotEqualTo(tamperDetector.computeChecksum(kv2));
    }

    @Test
    void computeChecksum_differentStatus_producesDifferentChecksum() {
        KeyVersion active = buildKeyVersion(KEY_ID, "kms-key-arn", KeyStatus.ACTIVE, Instant.EPOCH);
        KeyVersion rotating = buildKeyVersion(KEY_ID, "kms-key-arn", KeyStatus.ROTATING, Instant.EPOCH);

        assertThat(tamperDetector.computeChecksum(active))
                .isNotEqualTo(tamperDetector.computeChecksum(rotating));
    }

    @Test
    void computeChecksum_differentActivatedAt_producesDifferentChecksum() {
        KeyVersion kv1 = buildKeyVersion(KEY_ID, "kms-key-arn", KeyStatus.ACTIVE, Instant.EPOCH);
        KeyVersion kv2 = buildKeyVersion(KEY_ID, "kms-key-arn", KeyStatus.ACTIVE, Instant.EPOCH.plusSeconds(1));

        assertThat(tamperDetector.computeChecksum(kv1))
                .isNotEqualTo(tamperDetector.computeChecksum(kv2));
    }

    // ── assertIntegrity — pass ────────────────────────────────────────────────

    @Test
    void assertIntegrity_matchingChecksum_doesNotThrow() {
        KeyVersion kv = buildKeyVersion(KEY_ID, "kms-key-arn", KeyStatus.ACTIVE, Instant.EPOCH);
        String realChecksum = tamperDetector.computeChecksum(kv);
        kv.initializeChecksum(realChecksum);

        // Must complete without exception
        tamperDetector.assertIntegrity(kv);
    }

    @Test
    void assertIntegrity_matchingChecksum_noAuditEventWritten() {
        KeyVersion kv = buildKeyVersion(KEY_ID, "kms-key-arn", KeyStatus.ACTIVE, Instant.EPOCH);
        kv.initializeChecksum(tamperDetector.computeChecksum(kv));

        tamperDetector.assertIntegrity(kv);

        verify(auditLogger, never()).logFailure(any(), any(), any(), any(), any(), any(), any());
        verify(auditLogger, never()).logSuccess(any(), any(), any(), any(), any(), any());
        verify(auditLogger, never()).logKeyEvent(any(), any(), any(), any(), any());
    }

    // ── assertIntegrity — fail ────────────────────────────────────────────────

    @Test
    void assertIntegrity_checksumMismatch_throwsKeyIntegrityException() {
        KeyVersion kv = buildKeyVersion(KEY_ID, "kms-key-arn", KeyStatus.ACTIVE, Instant.EPOCH);
        kv.initializeChecksum("tampered-checksum-value-not-64-chars");

        assertThatThrownBy(() -> tamperDetector.assertIntegrity(kv))
                .isInstanceOf(KeyIntegrityException.class)
                .hasMessageContaining(KEY_ID.toString());
    }

    @Test
    void assertIntegrity_checksumMismatch_writesTamperAlertAuditEvent() {
        KeyVersion kv = buildKeyVersion(KEY_ID, "kms-key-arn", KeyStatus.ACTIVE, Instant.EPOCH);
        kv.initializeChecksum("tampered-checksum");

        assertThatThrownBy(() -> tamperDetector.assertIntegrity(kv))
                .isInstanceOf(KeyIntegrityException.class);

        ArgumentCaptor<AuditEventType> eventCaptor = ArgumentCaptor.forClass(AuditEventType.class);
        verify(auditLogger).logFailure(eventCaptor.capture(), any(), any(), any(), any(), any(), any());
        assertThat(eventCaptor.getValue()).isEqualTo(AuditEventType.TAMPER_ALERT);
    }

    @Test
    void assertIntegrity_checksumMismatch_auditMessageContainsKeyId() {
        KeyVersion kv = buildKeyVersion(KEY_ID, "kms-key-arn", KeyStatus.ACTIVE, Instant.EPOCH);
        kv.initializeChecksum("wrong");

        assertThatThrownBy(() -> tamperDetector.assertIntegrity(kv))
                .isInstanceOf(KeyIntegrityException.class);

        ArgumentCaptor<String> reasonCaptor = ArgumentCaptor.forClass(String.class);
        verify(auditLogger).logFailure(any(), any(), any(), any(), any(), reasonCaptor.capture(), any());
        assertThat(reasonCaptor.getValue()).contains(KEY_ID.toString());
    }

    @Test
    void assertIntegrity_allZeroChecksum_throwsKeyIntegrityException() {
        KeyVersion kv = buildKeyVersion(KEY_ID, "kms-key-arn", KeyStatus.ACTIVE, Instant.EPOCH);
        kv.initializeChecksum("0000000000000000000000000000000000000000000000000000000000000000");

        assertThatThrownBy(() -> tamperDetector.assertIntegrity(kv))
                .isInstanceOf(KeyIntegrityException.class);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /**
     * Builds a {@link KeyVersion} with the given parameters and sets its JPA-generated
     * {@code id} via reflection. The initial checksum is set to {@code "pending"} —
     * tests that need a real checksum should call
     * {@link KeyVersion#initializeChecksum(String)} after construction.
     */
    private KeyVersion buildKeyVersion(UUID id, String kmsKeyId, KeyStatus status, Instant activatedAt) {
        KeyVersion kv = KeyVersion.builder()
                .kmsKeyId(kmsKeyId)
                .kmsProvider("LOCAL_DEV")
                .keyAlias("test-key")
                .encryptedKekBlob("local-dev-key")
                .status(status)
                .activatedAt(activatedAt)
                .rotateBy(activatedAt.plusSeconds(365L * 24 * 60 * 60))
                .createdBy("test")
                .checksum("pending")
                .build();
        try {
            Field idField = KeyVersion.class.getDeclaredField("id");
            idField.setAccessible(true);
            idField.set(kv, id);
        } catch (ReflectiveOperationException reflectionException) {
            throw new RuntimeException("Failed to set id on KeyVersion in test", reflectionException);
        }
        return kv;
    }
}
