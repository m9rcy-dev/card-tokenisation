package com.yourorg.tokenisation.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link InMemoryHmacKeyRing}.
 *
 * <p>Verifies: load/get semantics, active pointer promotion, defensive copies,
 * retire (secret zeroing), and the dual-lookup helper {@link InMemoryHmacKeyRing#findRotatingVersionId}.
 */
class InMemoryHmacKeyRingTest {

    private static final String V1 = "aaaaaaaa-0000-0000-0000-000000000001";
    private static final String V2 = "bbbbbbbb-0000-0000-0000-000000000002";
    private static final byte[] SECRET_1 = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
    private static final byte[] SECRET_2 = new byte[]{9, 10, 11, 12};
    private static final Instant EXPIRES_AT = Instant.now().plusSeconds(3600);

    private InMemoryHmacKeyRing ring;

    @BeforeEach
    void setUp() {
        ring = new InMemoryHmacKeyRing();
    }

    // ── load / getActiveSecret ────────────────────────────────────────────────

    @Test
    void load_thenPromoteActive_secretIsRetrievable() {
        ring.load(V1, SECRET_1, EXPIRES_AT);
        ring.promoteActive(V1);

        byte[] returned = ring.getActiveSecret();
        assertThat(returned).isEqualTo(SECRET_1);
    }

    @Test
    void getActiveSecret_returnsDefensiveCopy() {
        ring.load(V1, SECRET_1, EXPIRES_AT);
        ring.promoteActive(V1);

        byte[] copy1 = ring.getActiveSecret();
        byte[] copy2 = ring.getActiveSecret();
        assertThat(copy1).isEqualTo(copy2).isNotSameAs(copy2);
    }

    @Test
    void load_takesDefensiveCopy_mutatingCallerArrayDoesNotAffectRing() {
        byte[] mutableSecret = {10, 20, 30};
        ring.load(V1, mutableSecret, EXPIRES_AT);
        ring.promoteActive(V1);

        mutableSecret[0] = (byte) 0xFF; // mutate caller's array

        assertThat(ring.getActiveSecret()[0]).isEqualTo((byte) 10);
    }

    @Test
    void getActiveSecret_noVersionPromoted_throwsIllegalStateException() {
        ring.load(V1, SECRET_1, EXPIRES_AT); // loaded but not promoted

        assertThatThrownBy(ring::getActiveSecret)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("No active HMAC key version");
    }

    // ── getActiveVersionId ────────────────────────────────────────────────────

    @Test
    void getActiveVersionId_returnsPromotedVersion() {
        ring.load(V1, SECRET_1, EXPIRES_AT);
        ring.promoteActive(V1);

        assertThat(ring.getActiveVersionId()).isEqualTo(V1);
    }

    @Test
    void getActiveVersionId_noVersionPromoted_throws() {
        assertThatThrownBy(ring::getActiveVersionId)
                .isInstanceOf(IllegalStateException.class);
    }

    // ── promoteActive ─────────────────────────────────────────────────────────

    @Test
    void promoteActive_versionNotLoaded_throwsIllegalStateException() {
        assertThatThrownBy(() -> ring.promoteActive("not-loaded-id"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not loaded in the ring");
    }

    @Test
    void promoteActive_replacesPreviousActive() {
        ring.load(V1, SECRET_1, EXPIRES_AT);
        ring.load(V2, SECRET_2, EXPIRES_AT);
        ring.promoteActive(V1);
        ring.promoteActive(V2);

        assertThat(ring.getActiveVersionId()).isEqualTo(V2);
        assertThat(ring.getActiveSecret()).isEqualTo(SECRET_2);
    }

    // ── getSecretByVersion ────────────────────────────────────────────────────

    @Test
    void getSecretByVersion_knownVersion_returnsSecret() {
        ring.load(V1, SECRET_1, EXPIRES_AT);

        assertThat(ring.getSecretByVersion(V1)).isEqualTo(SECRET_1);
    }

    @Test
    void getSecretByVersion_unknownVersion_throwsKeyVersionNotFoundException() {
        assertThatThrownBy(() -> ring.getSecretByVersion("unknown"))
                .isInstanceOf(KeyVersionNotFoundException.class);
    }

    // ── contains ─────────────────────────────────────────────────────────────

    @Test
    void contains_loadedVersion_returnsTrue() {
        ring.load(V1, SECRET_1, EXPIRES_AT);
        assertThat(ring.contains(V1)).isTrue();
    }

    @Test
    void contains_unknownVersion_returnsFalse() {
        assertThat(ring.contains("unknown")).isFalse();
    }

    // ── retire ────────────────────────────────────────────────────────────────

    @Test
    void retire_removesVersionFromRing() {
        ring.load(V1, SECRET_1, EXPIRES_AT);
        ring.retire(V1);

        assertThat(ring.contains(V1)).isFalse();
        assertThatThrownBy(() -> ring.getSecretByVersion(V1))
                .isInstanceOf(KeyVersionNotFoundException.class);
    }

    @Test
    void retire_unknownVersion_doesNotThrow() {
        ring.retire("no-such-version"); // must be silent
    }

    // ── findRotatingVersionId ─────────────────────────────────────────────────

    @Test
    void findRotatingVersionId_noOtherVersionsLoaded_returnsEmpty() {
        ring.load(V1, SECRET_1, EXPIRES_AT);
        ring.promoteActive(V1);

        assertThat(ring.findRotatingVersionId()).isEmpty();
    }

    @Test
    void findRotatingVersionId_oldVersionStillLoaded_returnsIt() {
        ring.load(V1, SECRET_1, EXPIRES_AT);
        ring.promoteActive(V1);
        ring.load(V2, SECRET_2, EXPIRES_AT);
        ring.promoteActive(V2); // V1 still in ring → it is "rotating"

        Optional<String> rotating = ring.findRotatingVersionId();
        assertThat(rotating).isPresent().hasValue(V1);
    }

    @Test
    void findRotatingVersionId_afterRetire_returnsEmpty() {
        ring.load(V1, SECRET_1, EXPIRES_AT);
        ring.promoteActive(V1);
        ring.load(V2, SECRET_2, EXPIRES_AT);
        ring.promoteActive(V2);

        ring.retire(V1);

        assertThat(ring.findRotatingVersionId()).isEmpty();
    }

    @Test
    void load_nullSecret_throwsIllegalArgumentException() {
        assertThatThrownBy(() -> ring.load(V1, null, EXPIRES_AT))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void load_emptySecret_throwsIllegalArgumentException() {
        assertThatThrownBy(() -> ring.load(V1, new byte[0], EXPIRES_AT))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
