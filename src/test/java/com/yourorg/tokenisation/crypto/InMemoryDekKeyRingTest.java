package com.yourorg.tokenisation.crypto;

import com.yourorg.tokenisation.domain.KeyStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link InMemoryDekKeyRing}.
 *
 * <p>No Spring context. Tests cover: load, promote, get-by-version, retire,
 * mark-compromised, and concurrent load correctness.
 */
class InMemoryDekKeyRingTest {

    private static final String KEY_VERSION_1 = "version-1-uuid";
    private static final String KEY_VERSION_2 = "version-2-uuid";
    private static final byte[] VALID_DEK = new byte[32];
    private static final Instant EXPIRES_AT = Instant.now().plusSeconds(86400);

    static {
        Arrays.fill(VALID_DEK, (byte) 0xAA);
    }

    private InMemoryDekKeyRing dekRing;

    @BeforeEach
    void setUp() {
        dekRing = new InMemoryDekKeyRing();
    }

    // ── load ─────────────────────────────────────────────────────────────────

    @Test
    void load_validKeyMaterial_keepsVersionInRing() {
        dekRing.load(KEY_VERSION_1, VALID_DEK.clone(), EXPIRES_AT);

        assertThat(dekRing.contains(KEY_VERSION_1)).isTrue();
    }

    @Test
    void load_sameVersionTwice_replacesExistingEntry() {
        dekRing.load(KEY_VERSION_1, VALID_DEK.clone(), EXPIRES_AT);
        byte[] updatedDek = new byte[32];
        Arrays.fill(updatedDek, (byte) 0xBB);
        dekRing.load(KEY_VERSION_1, updatedDek.clone(), EXPIRES_AT.plusSeconds(3600));

        dekRing.promoteActive(KEY_VERSION_1);
        byte[] returnedDek = dekRing.getActive().copyDek();
        assertThat(returnedDek).isEqualTo(updatedDek);
    }

    // ── promoteActive ────────────────────────────────────────────────────────

    @Test
    void promoteActive_loadedVersion_getActiveReturnsCorrectMaterial() {
        dekRing.load(KEY_VERSION_1, VALID_DEK.clone(), EXPIRES_AT);
        dekRing.promoteActive(KEY_VERSION_1);

        KeyMaterial activeMaterial = dekRing.getActive();

        assertThat(activeMaterial).isNotNull();
        assertThat(activeMaterial.keyVersionId()).isEqualTo(KEY_VERSION_1);
    }

    @Test
    void promoteActive_notLoadedVersion_throwsIllegalState() {
        assertThatThrownBy(() -> dekRing.promoteActive("nonexistent-version"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not loaded");
    }

    @Test
    void promoteActive_version2AfterVersion1_getActiveReturnsVersion2() {
        dekRing.load(KEY_VERSION_1, VALID_DEK.clone(), EXPIRES_AT);
        byte[] dek2 = new byte[32];
        Arrays.fill(dek2, (byte) 0xBB);
        dekRing.load(KEY_VERSION_2, dek2.clone(), EXPIRES_AT);

        dekRing.promoteActive(KEY_VERSION_1);
        dekRing.promoteActive(KEY_VERSION_2);

        KeyMaterial activeMaterial = dekRing.getActive();
        assertThat(activeMaterial.keyVersionId()).isEqualTo(KEY_VERSION_2);
    }

    // ── getActive ────────────────────────────────────────────────────────────

    @Test
    void getActive_noVersionPromoted_throwsIllegalState() {
        assertThatThrownBy(() -> dekRing.getActive())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("No active DEK version");
    }

    @Test
    void getActive_returnsCopyOfDek_notDirectReference() {
        dekRing.load(KEY_VERSION_1, VALID_DEK.clone(), EXPIRES_AT);
        dekRing.promoteActive(KEY_VERSION_1);

        byte[] firstCopy = dekRing.getActive().copyDek();
        byte[] secondCopy = dekRing.getActive().copyDek();

        firstCopy[0] = (byte) 0xFF;
        assertThat(secondCopy[0]).isNotEqualTo((byte) 0xFF);
    }

    // ── getByVersion ─────────────────────────────────────────────────────────

    @Test
    void getByVersion_loadedVersion_returnsMaterial() {
        dekRing.load(KEY_VERSION_1, VALID_DEK.clone(), EXPIRES_AT);

        KeyMaterial material = dekRing.getByVersion(KEY_VERSION_1);

        assertThat(material).isNotNull();
        assertThat(material.keyVersionId()).isEqualTo(KEY_VERSION_1);
    }

    @Test
    void getByVersion_retiredVersion_remainsAccessible() {
        dekRing.load(KEY_VERSION_1, VALID_DEK.clone(), EXPIRES_AT);
        dekRing.retire(KEY_VERSION_1);

        KeyMaterial retiredMaterial = dekRing.getByVersion(KEY_VERSION_1);
        assertThat(retiredMaterial.status()).isEqualTo(KeyStatus.RETIRED);
    }

    @Test
    void getByVersion_nonExistentVersion_throwsKeyVersionNotFoundException() {
        assertThatThrownBy(() -> dekRing.getByVersion("nonexistent-version"))
                .isInstanceOf(KeyVersionNotFoundException.class)
                .hasMessageContaining("nonexistent-version");
    }

    // ── retire ───────────────────────────────────────────────────────────────

    @Test
    void retire_activeVersion_setsStatusToRetiredButKeepsInRing() {
        dekRing.load(KEY_VERSION_1, VALID_DEK.clone(), EXPIRES_AT);
        dekRing.retire(KEY_VERSION_1);

        assertThat(dekRing.contains(KEY_VERSION_1)).isTrue();
        assertThat(dekRing.getByVersion(KEY_VERSION_1).status()).isEqualTo(KeyStatus.RETIRED);
    }

    @Test
    void retire_nonExistentVersion_isIdempotentAndDoesNotThrow() {
        dekRing.retire("version-that-was-never-loaded");
    }

    // ── markCompromised ──────────────────────────────────────────────────────

    @Test
    void markCompromised_loadedVersion_setsStatusToCompromised() {
        dekRing.load(KEY_VERSION_1, VALID_DEK.clone(), EXPIRES_AT);
        dekRing.markCompromised(KEY_VERSION_1);

        assertThat(dekRing.getByVersion(KEY_VERSION_1).status()).isEqualTo(KeyStatus.COMPROMISED);
    }

    @Test
    void markCompromised_notInRing_throwsIllegalState() {
        assertThatThrownBy(() -> dekRing.markCompromised("not-in-ring"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not in ring");
    }

    // ── Concurrent load ──────────────────────────────────────────────────────

    @Test
    void load_concurrentLoadsOfDifferentVersions_allVersionsAccessibleAfterwards()
            throws InterruptedException {
        int threadCount = 50;
        List<String> versionIds = new ArrayList<>();
        for (int index = 0; index < threadCount; index++) {
            versionIds.add("concurrent-version-" + index);
        }

        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch finishLatch = new CountDownLatch(threadCount);
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);

        for (String versionId : versionIds) {
            executor.submit(() -> {
                try {
                    startLatch.await();
                    byte[] dek = new byte[32];
                    dekRing.load(versionId, dek, EXPIRES_AT);
                } catch (InterruptedException interruptedException) {
                    Thread.currentThread().interrupt();
                } finally {
                    finishLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        finishLatch.await();
        executor.shutdown();

        for (String versionId : versionIds) {
            assertThat(dekRing.contains(versionId))
                    .as("Version %s must be in ring after concurrent load", versionId)
                    .isTrue();
        }
    }
}
