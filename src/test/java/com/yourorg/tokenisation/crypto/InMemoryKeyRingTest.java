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
 * Unit tests for {@link InMemoryKeyRing}.
 *
 * <p>No Spring context. Tests cover: load, promote, get-by-version, retire,
 * mark-compromised, and concurrent load correctness.
 */
class InMemoryKeyRingTest {

    private static final String KEY_VERSION_1 = "version-1-uuid";
    private static final String KEY_VERSION_2 = "version-2-uuid";
    private static final byte[] VALID_KEK = new byte[32];
    private static final Instant EXPIRES_AT = Instant.now().plusSeconds(86400);

    static {
        Arrays.fill(VALID_KEK, (byte) 0xAA);
    }

    private InMemoryKeyRing keyRing;

    @BeforeEach
    void setUp() {
        keyRing = new InMemoryKeyRing();
    }

    // ── load ─────────────────────────────────────────────────────────────────

    @Test
    void load_validKeyMaterial_keepsVersionInRing() {
        keyRing.load(KEY_VERSION_1, VALID_KEK.clone(), EXPIRES_AT);

        assertThat(keyRing.contains(KEY_VERSION_1)).isTrue();
    }

    @Test
    void load_sameVersionTwice_replacesExistingEntry() {
        keyRing.load(KEY_VERSION_1, VALID_KEK.clone(), EXPIRES_AT);
        byte[] updatedKek = new byte[32];
        Arrays.fill(updatedKek, (byte) 0xBB);
        keyRing.load(KEY_VERSION_1, updatedKek.clone(), EXPIRES_AT.plusSeconds(3600));

        keyRing.promoteActive(KEY_VERSION_1);
        byte[] returnedKek = keyRing.getActive().copyKek();
        assertThat(returnedKek).isEqualTo(updatedKek);
    }

    // ── promoteActive ────────────────────────────────────────────────────────

    @Test
    void promoteActive_loadedVersion_getActiveReturnsCorrectMaterial() {
        keyRing.load(KEY_VERSION_1, VALID_KEK.clone(), EXPIRES_AT);
        keyRing.promoteActive(KEY_VERSION_1);

        KeyMaterial activeMaterial = keyRing.getActive();

        assertThat(activeMaterial).isNotNull();
        assertThat(activeMaterial.keyVersionId()).isEqualTo(KEY_VERSION_1);
    }

    @Test
    void promoteActive_notLoadedVersion_throwsIllegalState() {
        assertThatThrownBy(() -> keyRing.promoteActive("nonexistent-version"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not loaded");
    }

    @Test
    void promoteActive_version2AfterVersion1_getActiveReturnsVersion2() {
        keyRing.load(KEY_VERSION_1, VALID_KEK.clone(), EXPIRES_AT);
        byte[] kek2 = new byte[32];
        Arrays.fill(kek2, (byte) 0xBB);
        keyRing.load(KEY_VERSION_2, kek2.clone(), EXPIRES_AT);

        keyRing.promoteActive(KEY_VERSION_1);
        keyRing.promoteActive(KEY_VERSION_2);

        KeyMaterial activeMaterial = keyRing.getActive();
        assertThat(activeMaterial.keyVersionId()).isEqualTo(KEY_VERSION_2);
    }

    // ── getActive ────────────────────────────────────────────────────────────

    @Test
    void getActive_noVersionPromoted_throwsIllegalState() {
        assertThatThrownBy(() -> keyRing.getActive())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("No active key version");
    }

    @Test
    void getActive_returnsCopyOfKek_notDirectReference() {
        keyRing.load(KEY_VERSION_1, VALID_KEK.clone(), EXPIRES_AT);
        keyRing.promoteActive(KEY_VERSION_1);

        byte[] firstCopy = keyRing.getActive().copyKek();
        byte[] secondCopy = keyRing.getActive().copyKek();

        // Modifying the first copy must not affect the second
        firstCopy[0] = (byte) 0xFF;
        assertThat(secondCopy[0]).isNotEqualTo((byte) 0xFF);
    }

    // ── getByVersion ─────────────────────────────────────────────────────────

    @Test
    void getByVersion_loadedVersion_returnsMaterial() {
        keyRing.load(KEY_VERSION_1, VALID_KEK.clone(), EXPIRES_AT);

        KeyMaterial material = keyRing.getByVersion(KEY_VERSION_1);

        assertThat(material).isNotNull();
        assertThat(material.keyVersionId()).isEqualTo(KEY_VERSION_1);
    }

    @Test
    void getByVersion_retiredVersion_remainsAccessible() {
        keyRing.load(KEY_VERSION_1, VALID_KEK.clone(), EXPIRES_AT);
        keyRing.retire(KEY_VERSION_1);

        // Retired versions must stay in ring for detokenisation of pre-rotation tokens
        KeyMaterial retiredMaterial = keyRing.getByVersion(KEY_VERSION_1);
        assertThat(retiredMaterial.status()).isEqualTo(KeyStatus.RETIRED);
    }

    @Test
    void getByVersion_nonExistentVersion_throwsKeyVersionNotFoundException() {
        assertThatThrownBy(() -> keyRing.getByVersion("nonexistent-version"))
                .isInstanceOf(KeyVersionNotFoundException.class)
                .hasMessageContaining("nonexistent-version");
    }

    // ── retire ───────────────────────────────────────────────────────────────

    @Test
    void retire_activeVersion_setsStatusToRetiredButKeepsInRing() {
        keyRing.load(KEY_VERSION_1, VALID_KEK.clone(), EXPIRES_AT);
        keyRing.retire(KEY_VERSION_1);

        assertThat(keyRing.contains(KEY_VERSION_1)).isTrue();
        assertThat(keyRing.getByVersion(KEY_VERSION_1).status()).isEqualTo(KeyStatus.RETIRED);
    }

    @Test
    void retire_nonExistentVersion_isIdempotentAndDoesNotThrow() {
        // retire on a missing version must not throw — it's a no-op
        keyRing.retire("version-that-was-never-loaded");
        // Passes if no exception is thrown
    }

    // ── markCompromised ──────────────────────────────────────────────────────

    @Test
    void markCompromised_loadedVersion_setsStatusToCompromised() {
        keyRing.load(KEY_VERSION_1, VALID_KEK.clone(), EXPIRES_AT);
        keyRing.markCompromised(KEY_VERSION_1);

        assertThat(keyRing.getByVersion(KEY_VERSION_1).status()).isEqualTo(KeyStatus.COMPROMISED);
    }

    @Test
    void markCompromised_notInRing_throwsIllegalState() {
        assertThatThrownBy(() -> keyRing.markCompromised("not-in-ring"))
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
                    byte[] kek = new byte[32];
                    keyRing.load(versionId, kek, EXPIRES_AT);
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
            assertThat(keyRing.contains(versionId))
                    .as("Version %s must be in ring after concurrent load", versionId)
                    .isTrue();
        }
    }
}
