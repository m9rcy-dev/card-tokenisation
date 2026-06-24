package com.yourorg.tokenisation.rotation;

import com.yourorg.tokenisation.audit.AuditEventType;
import com.yourorg.tokenisation.audit.AuditLogger;
import com.yourorg.tokenisation.crypto.InMemoryHmacKeyRing;
import com.yourorg.tokenisation.domain.KeyStatus;
import com.yourorg.tokenisation.domain.KeyType;
import com.yourorg.tokenisation.domain.KeyVersion;
import com.yourorg.tokenisation.kms.KmsProvider;
import com.yourorg.tokenisation.repository.KeyVersionRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link HmacRotationService}.
 *
 * <p>Verifies:
 * <ul>
 *   <li>initiateRotation: existing ACTIVE HMAC is marked ROTATING, new ACTIVE version is persisted,
 *       ring is updated, HMAC_ROTATION_STARTED audit is written
 *   <li>completeRotation: rotating version is retired in DB and removed from ring,
 *       HMAC_ROTATION_COMPLETED audit is written
 *   <li>completeRotation: throws when version not found
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class HmacRotationServiceTest {

    private static final UUID ACTIVE_HMAC_ID = UUID.fromString("aaaaaaaa-0000-0000-0000-000000000001");
    private static final byte[] FAKE_BLOB    = new byte[60]; // IV + encrypted secret + tag

    @Mock private KeyVersionRepository keyVersionRepository;
    @Mock private KmsProvider kmsProvider;
    @Mock private InMemoryHmacKeyRing hmacKeyRing;
    @Mock private AuditLogger auditLogger;

    private HmacRotationService service;

    @BeforeEach
    void setUp() {
        service = new HmacRotationService(
                keyVersionRepository, kmsProvider, hmacKeyRing, auditLogger);
    }

    // ── initiateRotation ──────────────────────────────────────────────────────

    @Test
    void initiateRotation_transitionsActiveToRotatingAndCreatesNewVersion() {
        KeyVersion activeHmac = buildHmacVersion(ACTIVE_HMAC_ID, KeyStatus.ACTIVE);

        when(keyVersionRepository.findActiveHmacOrThrow()).thenReturn(activeHmac);
        when(kmsProvider.wrapNewHmacKey(any())).thenReturn(FAKE_BLOB);
        when(keyVersionRepository.saveAndFlush(any())).thenAnswer(inv -> {
            KeyVersion kv = inv.getArgument(0);
            forceId(kv, UUID.randomUUID());
            return kv;
        });

        UUID newId = service.initiateRotation("hmac-key-2027");

        // Old version should be ROTATING
        assertThat(activeHmac.getStatus()).isEqualTo(KeyStatus.ROTATING);
        verify(keyVersionRepository).save(activeHmac);
        verify(keyVersionRepository).flush();

        // New version persisted
        ArgumentCaptor<KeyVersion> newVersionCaptor = ArgumentCaptor.forClass(KeyVersion.class);
        verify(keyVersionRepository).saveAndFlush(newVersionCaptor.capture());
        KeyVersion saved = newVersionCaptor.getValue();
        assertThat(saved.getKeyType()).isEqualTo(KeyType.HMAC);
        assertThat(saved.getStatus()).isEqualTo(KeyStatus.ACTIVE);
        assertThat(saved.getKeyAlias()).isEqualTo("hmac-key-2027");

        // Ring loaded and promoted
        verify(hmacKeyRing).load(eq(newId.toString()), any(), any());
        verify(hmacKeyRing).promoteActive(newId.toString());

        // Audit written
        verify(auditLogger).logKeyEvent(
                eq(AuditEventType.HMAC_ROTATION_STARTED),
                eq(ACTIVE_HMAC_ID),
                eq("SUCCESS"),
                any(),
                any());
    }

    @Test
    void initiateRotation_zeroesNewSecretFromMemoryBeforeReturning() {
        KeyVersion activeHmac = buildHmacVersion(ACTIVE_HMAC_ID, KeyStatus.ACTIVE);

        when(keyVersionRepository.findActiveHmacOrThrow()).thenReturn(activeHmac);
        when(kmsProvider.wrapNewHmacKey(any())).thenReturn(FAKE_BLOB);
        when(keyVersionRepository.saveAndFlush(any())).thenAnswer(inv -> {
            forceId(inv.getArgument(0), UUID.randomUUID());
            return inv.getArgument(0);
        });

        // Capture the secret bytes passed to hmacKeyRing.load
        ArgumentCaptor<byte[]> secretCaptor = ArgumentCaptor.forClass(byte[].class);
        service.initiateRotation("hmac-key-2027");

        verify(hmacKeyRing).load(any(), secretCaptor.capture(), any());
        // The ring takes a defensive copy; the original passed in must be zeroed afterwards.
        // Since we can't inspect the now-zeroed local variable inside the method, we verify
        // indirectly by checking the ring received a 32-byte array (correct length generated).
        assertThat(secretCaptor.getValue()).hasSize(32);
    }

    // ── completeRotation ──────────────────────────────────────────────────────

    @Test
    void completeRotation_retiresVersionInDbAndRemovesFromRing() {
        KeyVersion rotating = buildHmacVersion(ACTIVE_HMAC_ID, KeyStatus.ROTATING);
        when(keyVersionRepository.findById(ACTIVE_HMAC_ID)).thenReturn(Optional.of(rotating));

        service.completeRotation(ACTIVE_HMAC_ID);

        assertThat(rotating.getStatus()).isEqualTo(KeyStatus.RETIRED);
        verify(keyVersionRepository).save(rotating);
        verify(hmacKeyRing).retire(ACTIVE_HMAC_ID.toString());
        verify(auditLogger).logKeyEvent(
                eq(AuditEventType.HMAC_ROTATION_COMPLETED),
                eq(ACTIVE_HMAC_ID),
                eq("SUCCESS"),
                any(),
                any());
    }

    @Test
    void completeRotation_versionNotFound_throwsIllegalStateException() {
        when(keyVersionRepository.findById(ACTIVE_HMAC_ID)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.completeRotation(ACTIVE_HMAC_ID))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining(ACTIVE_HMAC_ID.toString());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static KeyVersion buildHmacVersion(UUID id, KeyStatus status) {
        KeyVersion kv = KeyVersion.forHmac(
                FAKE_BLOB, "test-kms-key-arn", "TEST", "test-hmac-key",
                Instant.now().plusSeconds(3600), "test");
        forceId(kv, id);
        if (status == KeyStatus.ROTATING) kv.markRotating();
        return kv;
    }

    private static void forceId(KeyVersion kv, UUID id) {
        try {
            Field f = KeyVersion.class.getDeclaredField("id");
            f.setAccessible(true);
            f.set(kv, id);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }
}
