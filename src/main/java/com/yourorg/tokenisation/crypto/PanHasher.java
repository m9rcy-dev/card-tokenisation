package com.yourorg.tokenisation.crypto;

import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * Computes HMAC-SHA256 hashes of PANs for deterministic de-duplication.
 *
 * <p>The hash is used exclusively in {@code token_vault.pan_hash} to answer the question:
 * "does an active token already exist for this PAN?" It does not allow PAN recovery.
 *
 * <p>The hashing secret is loaded from {@link InMemoryHmacKeyRing} at startup by
 * {@code KeyRingInitialiser}. Versioning enables secret rotation without invalidating
 * all existing pan_hash values at once — during the rotation window both the old and
 * new versions are checked for de-duplication.
 *
 * <p>This class is thread-safe: {@code Mac} instances are created per-call (not shared).
 */
@Component
public class PanHasher {

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private final InMemoryHmacKeyRing hmacRing;

    public PanHasher(InMemoryHmacKeyRing hmacRing) {
        this.hmacRing = hmacRing;
    }

    /**
     * Computes the HMAC-SHA256 of the given PAN using the currently active HMAC key version.
     *
     * <p>Returns a {@link HashResult} that carries both the hex-encoded hash and the version ID
     * so that callers can persist which key version produced the hash.
     *
     * @param pan the raw PAN digit string; must not be null or blank
     * @return {@link HashResult} with hash string and active HMAC version ID
     * @throws IllegalArgumentException if {@code pan} is null or blank
     * @throws EncryptionException      if HMAC-SHA256 is unavailable or the secret is invalid
     */
    public HashResult hash(String pan) {
        if (pan == null || pan.isBlank()) {
            throw new IllegalArgumentException("PAN must not be null or blank");
        }
        String versionId = hmacRing.getActiveVersionId();
        byte[] secret = hmacRing.getActiveSecret();
        try {
            String hashValue = compute(pan, secret);
            return new HashResult(hashValue, versionId);
        } finally {
            Arrays.fill(secret, (byte) 0);
        }
    }

    /**
     * Computes the HMAC-SHA256 of the given PAN using a specific HMAC key version.
     *
     * <p>Used during the HMAC rotation window to check for existing tokens hashed with the
     * rotating (old) version — prevents duplicate token issuance mid-batch.
     *
     * @param pan       the raw PAN digit string; must not be null or blank
     * @param versionId UUID string of the HMAC key version to use
     * @return 64-character lowercase hex HMAC-SHA256 of the PAN under the specified version
     * @throws IllegalArgumentException if {@code pan} is null or blank
     * @throws KeyVersionNotFoundException if the version is not loaded in the ring
     * @throws EncryptionException      if HMAC-SHA256 is unavailable or the secret is invalid
     */
    public String hashWithVersion(String pan, String versionId) {
        if (pan == null || pan.isBlank()) {
            throw new IllegalArgumentException("PAN must not be null or blank");
        }
        byte[] secret = hmacRing.getSecretByVersion(versionId);
        try {
            return compute(pan, secret);
        } finally {
            Arrays.fill(secret, (byte) 0);
        }
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    private String compute(String pan, byte[] secret) {
        try {
            Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
            hmac.init(new SecretKeySpec(secret, HMAC_ALGORITHM));
            byte[] hashBytes = hmac.doFinal(pan.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptionException("HMAC-SHA256 algorithm not available", e);
        } catch (InvalidKeyException e) {
            throw new EncryptionException("Invalid hashing secret for HMAC-SHA256", e);
        }
    }
}
