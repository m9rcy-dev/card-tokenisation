package com.yourorg.tokenisation.crypto;

import com.yourorg.tokenisation.audit.AuditEventType;
import com.yourorg.tokenisation.audit.AuditLogger;
import com.yourorg.tokenisation.config.TamperDetectionProperties;
import com.yourorg.tokenisation.domain.KeyVersion;
import com.yourorg.tokenisation.exception.KeyIntegrityException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Computes and verifies HMAC-SHA256 integrity checksums on {@code key_versions} rows.
 *
 * <p>The checksum covers the fields that must never change after initial activation:
 * {@code id}, {@code kmsKeyId}, {@code status}, and {@code activatedAt}. Any DB-level
 * mutation to these fields is detected on the next {@link #assertIntegrity} call.
 *
 * <p>Because the UUID ({@code id}) is JPA-generated and therefore unavailable until after
 * the first {@code save()}, a two-step initialisation pattern is required:
 * <ol>
 *   <li>Persist the entity with a placeholder checksum (e.g. {@code "pending"}).
 *   <li>Compute the real checksum via {@link #computeChecksum(KeyVersion)}.
 *   <li>Call {@link KeyVersion#initializeChecksum(String)} and save again.
 * </ol>
 *
 * <p><strong>The signing secret must never appear in any log statement or exception message.</strong>
 */
@Component
@Slf4j
public class TamperDetector {

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private final byte[] signingSecretBytes;
    private final AuditLogger auditLogger;

    /**
     * Constructs the tamper detector with its signing secret and audit logger.
     *
     * @param properties  tamper-detection configuration containing the signing secret
     * @param auditLogger audit event writer for TAMPER_ALERT events
     */
    public TamperDetector(TamperDetectionProperties properties, AuditLogger auditLogger) {
        this.signingSecretBytes = properties.getSigningSecret().getBytes(StandardCharsets.UTF_8);
        this.auditLogger = auditLogger;
    }

    /**
     * Computes an HMAC-SHA256 checksum over the integrity-critical fields of a key version.
     *
     * <p>The payload is the concatenation (no separator) of:
     * {@code id.toString() + kmsKeyId + status.name() + activatedAt.toString()}.
     *
     * <p>This method can only be called after the entity has been persisted and its UUID
     * assigned — calling it with a null {@code id} will throw {@link NullPointerException}.
     *
     * @param kv the key version to checksum; {@code id} must not be null
     * @return lowercase hex-encoded HMAC-SHA256, 64 characters
     * @throws IllegalStateException if the HMAC algorithm is unavailable (should never happen)
     */
    public String computeChecksum(KeyVersion kv) {
        String payload = kv.getId().toString()
                + kv.getKmsKeyId()
                + kv.getStatus().name()
                + kv.getActivatedAt().toString();
        return hmacSha256Hex(payload);
    }

    /**
     * Verifies that the stored checksum on a key version row matches the expected value.
     *
     * <p>Uses {@link MessageDigest#isEqual} for constant-time comparison to prevent
     * timing side-channel attacks.
     *
     * <p>On mismatch, a {@code TAMPER_ALERT} audit event is written via the audit logger
     * before throwing. The key version ID is logged at ERROR level; the signing secret
     * and expected/actual checksum values are never logged.
     *
     * @param kv the key version to verify
     * @throws KeyIntegrityException if the stored checksum does not match the computed value
     */
    public void assertIntegrity(KeyVersion kv) {
        String expected = computeChecksum(kv);
        String stored = kv.getChecksum();

        boolean intact = MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                stored.getBytes(StandardCharsets.UTF_8));

        if (!intact) {
            log.error("Key version integrity check FAILED for id [{}] — possible tamper detected",
                    kv.getId());
            auditLogger.logFailure(
                    AuditEventType.TAMPER_ALERT,
                    null,
                    null,
                    null,
                    null,
                    "key_versions row checksum mismatch for id: " + kv.getId(),
                    null);
            throw new KeyIntegrityException(
                    "Key version integrity check failed: " + kv.getId());
        }

        log.debug("Key version integrity verified for id [{}]", kv.getId());
    }

    // ── Private ──────────────────────────────────────────────────────────────

    /**
     * Computes HMAC-SHA256 of the given payload with the configured signing secret.
     *
     * @param payload the plaintext payload to sign
     * @return lowercase hex-encoded digest, 64 characters
     */
    private String hmacSha256Hex(String payload) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(signingSecretBytes, HMAC_ALGORITHM));
            byte[] digest = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException algorithmException) {
            // HmacSHA256 is mandated by the Java SE specification — this cannot happen
            throw new IllegalStateException("HmacSHA256 algorithm unavailable", algorithmException);
        } catch (InvalidKeyException keyException) {
            throw new IllegalStateException("Invalid signing key for HmacSHA256", keyException);
        }
    }
}
