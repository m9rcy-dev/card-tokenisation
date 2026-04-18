package com.yourorg.tokenisation.crypto;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link PanHasher}.
 *
 * <p>No Spring context. Tests verify HMAC-SHA256 determinism, collision resistance,
 * and that the hash output does not contain any part of the input PAN.
 */
class PanHasherTest {

    private static final String VALID_HASHING_SECRET = "test-hmac-secret-32-bytes-exactly!!";
    private static final String VISA_PAN = "4111111111111111";
    private static final String MC_PAN = "5500005555555559";

    private final PanHasher panHasher = new PanHasher(VALID_HASHING_SECRET);

    // ── Constructor ──────────────────────────────────────────────────────────

    @Test
    void constructor_nullSecret_throwsIllegalArgument() {
        assertThatThrownBy(() -> new PanHasher(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("null or blank");
    }

    @Test
    void constructor_blankSecret_throwsIllegalArgument() {
        assertThatThrownBy(() -> new PanHasher("   "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("null or blank");
    }

    // ── hash ─────────────────────────────────────────────────────────────────

    @Test
    void hash_samePan_alwaysReturnsSameHash() {
        String firstHash = panHasher.hash(VISA_PAN);
        String secondHash = panHasher.hash(VISA_PAN);

        assertThat(firstHash).isEqualTo(secondHash);
    }

    @Test
    void hash_differentPans_returnDifferentHashes() {
        String visaHash = panHasher.hash(VISA_PAN);
        String mcHash = panHasher.hash(MC_PAN);

        assertThat(visaHash).isNotEqualTo(mcHash);
    }

    @Test
    void hash_validPan_returns64CharLowercaseHex() {
        String hash = panHasher.hash(VISA_PAN);

        assertThat(hash).hasSize(64);
        assertThat(hash).matches("[0-9a-f]{64}");
    }

    @Test
    void hash_outputDoesNotContainInputPan() {
        String hash = panHasher.hash(VISA_PAN);

        assertThat(hash).doesNotContain(VISA_PAN);
        // Also verify no substring of the PAN appears — hash is hex, PAN is digits
        // Check that it doesn't trivially embed the PAN string
        assertThat(hash).doesNotContain("4111");
    }

    @Test
    void hash_differentSecrets_produceDifferentHashesForSamePan() {
        PanHasher anotherHasher = new PanHasher("different-secret-32-bytes-exactly!");
        String firstHash = panHasher.hash(VISA_PAN);
        String secondHash = anotherHasher.hash(VISA_PAN);

        assertThat(firstHash).isNotEqualTo(secondHash);
    }

    @Test
    void hash_nullPan_throwsIllegalArgument() {
        assertThatThrownBy(() -> panHasher.hash(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("null or blank");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   "})
    void hash_blankPan_throwsIllegalArgument(String blankPan) {
        assertThatThrownBy(() -> panHasher.hash(blankPan))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("null or blank");
    }

    @Test
    void hash_pansWithSingleDigitDifference_produceDifferentHashes() {
        // Verify HMAC sensitivity to input changes
        String original = "4111111111111111";
        String modified = "4111111111111112";

        assertThat(panHasher.hash(original)).isNotEqualTo(panHasher.hash(modified));
    }
}
