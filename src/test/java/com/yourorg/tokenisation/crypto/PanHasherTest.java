package com.yourorg.tokenisation.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link PanHasher}.
 *
 * <p>No Spring context. Tests verify HMAC-SHA256 determinism, collision resistance,
 * and that the hash output does not contain any part of the input PAN.
 */
class PanHasherTest {

    private static final String VERSION_A = "aaaaaaaa-0000-0000-0000-000000000001";
    private static final String VERSION_B = "bbbbbbbb-0000-0000-0000-000000000002";
    private static final byte[] SECRET_A = "test-hmac-secret-32-bytes-exactly!!".getBytes(StandardCharsets.UTF_8);
    private static final byte[] SECRET_B = "different-secret-32-bytes-exactly!".getBytes(StandardCharsets.UTF_8);

    private static final String VISA_PAN = "4111111111111111";
    private static final String MC_PAN   = "5500005555555559";

    private InMemoryHmacKeyRing ring;
    private PanHasher panHasher;

    @BeforeEach
    void setUp() {
        ring = new InMemoryHmacKeyRing();
        ring.load(VERSION_A, SECRET_A, Instant.now().plusSeconds(3600));
        ring.promoteActive(VERSION_A);
        panHasher = new PanHasher(ring);
    }

    // ── hash — active version ─────────────────────────────────────────────────

    @Test
    void hash_samePan_alwaysReturnsSameHash() {
        HashResult first = panHasher.hash(VISA_PAN);
        HashResult second = panHasher.hash(VISA_PAN);

        assertThat(first.hash()).isEqualTo(second.hash());
    }

    @Test
    void hash_differentPans_returnDifferentHashes() {
        assertThat(panHasher.hash(VISA_PAN).hash())
                .isNotEqualTo(panHasher.hash(MC_PAN).hash());
    }

    @Test
    void hash_validPan_returns64CharLowercaseHex() {
        String hash = panHasher.hash(VISA_PAN).hash();

        assertThat(hash).hasSize(64);
        assertThat(hash).matches("[0-9a-f]{64}");
    }

    @Test
    void hash_returnsActiveVersionId() {
        assertThat(panHasher.hash(VISA_PAN).hmacVersionId()).isEqualTo(VERSION_A);
    }

    @Test
    void hash_outputDoesNotContainInputPan() {
        String hash = panHasher.hash(VISA_PAN).hash();

        assertThat(hash).doesNotContain(VISA_PAN);
        assertThat(hash).doesNotContain("4111");
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
        String original = "4111111111111111";
        String modified = "4111111111111112";

        assertThat(panHasher.hash(original).hash())
                .isNotEqualTo(panHasher.hash(modified).hash());
    }

    // ── hashWithVersion ───────────────────────────────────────────────────────

    @Test
    void hashWithVersion_differentVersion_producesDifferentHash() {
        ring.load(VERSION_B, SECRET_B, Instant.now().plusSeconds(3600));

        String hashA = panHasher.hashWithVersion(VISA_PAN, VERSION_A);
        String hashB = panHasher.hashWithVersion(VISA_PAN, VERSION_B);

        assertThat(hashA).isNotEqualTo(hashB);
    }

    @Test
    void hashWithVersion_sameVersionAshash_matchesActiveResult() {
        String activeHash = panHasher.hash(VISA_PAN).hash();
        String versionedHash = panHasher.hashWithVersion(VISA_PAN, VERSION_A);

        assertThat(versionedHash).isEqualTo(activeHash);
    }

    @Test
    void hashWithVersion_unknownVersion_throwsKeyVersionNotFound() {
        assertThatThrownBy(() -> panHasher.hashWithVersion(VISA_PAN, "unknown-version-id"))
                .isInstanceOf(KeyVersionNotFoundException.class);
    }
}
