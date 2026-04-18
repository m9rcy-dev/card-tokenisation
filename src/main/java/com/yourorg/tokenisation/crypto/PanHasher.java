package com.yourorg.tokenisation.crypto;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Computes HMAC-SHA256 hashes of PANs for deterministic de-duplication.
 *
 * <p>The hash is used exclusively in {@code token_vault.pan_hash} to answer the question:
 * "does an active RECURRING token already exist for this PAN and merchant?"
 * It does not allow PAN recovery — it is a one-way function keyed with a secret
 * that is separate from the KEK.
 *
 * <p>The hashing secret is loaded from {@code tokenisation.pan-hash-secret} in configuration.
 * It must be kept confidential: if an attacker obtains the hashing secret and a list of
 * candidate PANs, they could confirm which PANs have tokens in the vault via offline lookup.
 *
 * <p>This class is thread-safe: {@code Mac} instances are created per-call (not shared).
 */
@Component
public class PanHasher {

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private final byte[] hashingSecretBytes;

    /**
     * Constructs a {@code PanHasher} with the HMAC secret from configuration.
     *
     * @param hashingSecret the HMAC-SHA256 hashing secret from {@code tokenisation.pan-hash-secret};
     *                      must not be null or blank; used as the HMAC key
     * @throws IllegalArgumentException if {@code hashingSecret} is null or blank
     */
    public PanHasher(@Value("${tokenisation.pan-hash-secret}") String hashingSecret) {
        if (hashingSecret == null || hashingSecret.isBlank()) {
            throw new IllegalArgumentException("PAN hashing secret must not be null or blank");
        }
        this.hashingSecretBytes = hashingSecret.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Computes the HMAC-SHA256 of the given PAN using the configured hashing secret.
     *
     * <p>The result is a 64-character lowercase hex string (32 bytes = 256 bits).
     * Two calls with the same PAN always produce the same hash — this determinism
     * is what enables de-duplication of RECURRING tokens without storing the PAN.
     *
     * @param pan the raw PAN digit string (e.g. {@code "4111111111111111"}); must not be null or blank
     * @return 64-character lowercase hex HMAC-SHA256 of the PAN
     * @throws IllegalArgumentException if {@code pan} is null or blank
     * @throws EncryptionException      if the HMAC algorithm is unavailable (should not occur on any standard JDK)
     */
    public String hash(String pan) {
        if (pan == null || pan.isBlank()) {
            throw new IllegalArgumentException("PAN must not be null or blank");
        }
        try {
            Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
            hmac.init(new SecretKeySpec(hashingSecretBytes, HMAC_ALGORITHM));
            byte[] hashBytes = hmac.doFinal(pan.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException algorithmException) {
            // HmacSHA256 is required by the JDK specification — this should never occur
            throw new EncryptionException("HMAC-SHA256 algorithm not available", algorithmException);
        } catch (InvalidKeyException invalidKeyException) {
            throw new EncryptionException("Invalid hashing secret for HMAC-SHA256", invalidKeyException);
        }
    }
}
