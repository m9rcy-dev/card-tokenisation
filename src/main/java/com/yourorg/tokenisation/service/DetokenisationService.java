package com.yourorg.tokenisation.service;

import com.yourorg.tokenisation.api.response.DetokeniseResponse;
import com.yourorg.tokenisation.audit.AuditEventType;
import com.yourorg.tokenisation.audit.AuditLogger;
import com.yourorg.tokenisation.crypto.AesGcmCipher;
import com.yourorg.tokenisation.crypto.EncryptionException;
import com.yourorg.tokenisation.crypto.InMemoryKeyRing;
import com.yourorg.tokenisation.crypto.KeyMaterial;
import com.yourorg.tokenisation.domain.KeyStatus;
import com.yourorg.tokenisation.domain.TokenVault;
import com.yourorg.tokenisation.exception.KeyIntegrityException;
import com.yourorg.tokenisation.exception.MerchantScopeException;
import com.yourorg.tokenisation.exception.TokenNotFoundException;
import com.yourorg.tokenisation.exception.TokenisationException;
import com.yourorg.tokenisation.repository.TokenVaultRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.AEADBadTagException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;

/**
 * Core business logic for detokenising tokens back to their original PANs.
 *
 * <p>Detokenisation flow:
 * <ol>
 *   <li>Look up the active {@link TokenVault} record by token value — 404 if absent or inactive.
 *   <li>Verify the requesting merchant ID matches the token's merchant scope — 403 on mismatch.
 *   <li>Retrieve {@link KeyMaterial} from the {@link InMemoryKeyRing} by the vault's key version ID.
 *   <li>If key status is {@code COMPROMISED} — write {@code TAMPER_ALERT} audit record,
 *       throw {@link KeyIntegrityException} (caller receives 500).
 *   <li>Copy the KEK bytes and decrypt the PAN via {@link AesGcmCipher#decrypt}.
 *       GCM authentication tag failure means the ciphertext has been tampered with —
 *       write {@code TAMPER_ALERT} and throw {@link KeyIntegrityException}.
 *   <li>Zero the KEK copy in a {@code finally} block regardless of outcome.
 *   <li>Build the {@link DetokeniseResponse}, zero the PAN byte array.
 *   <li>Write {@code DETOKENISE} success audit record.
 *   <li>Return the response.
 * </ol>
 *
 * <p>On any exception, a failure audit record is written before propagating.
 *
 * <p><strong>The recovered PAN must never appear in any log statement, exception message,
 * audit log field, or error response produced by this class.</strong>
 */
@Service
@Slf4j
public class DetokenisationService {

    private final AesGcmCipher cipher;
    private final InMemoryKeyRing keyRing;
    private final TokenVaultRepository tokenVaultRepository;
    private final AuditLogger auditLogger;

    /**
     * Constructs the service with all required collaborators.
     *
     * @param cipher               AES-256-GCM cipher for PAN decryption; must not be null
     * @param keyRing              in-memory key ring loaded at startup; must not be null
     * @param tokenVaultRepository persistence for token vault records; must not be null
     * @param auditLogger          audit event writer; must not be null
     */
    public DetokenisationService(AesGcmCipher cipher,
                                 InMemoryKeyRing keyRing,
                                 TokenVaultRepository tokenVaultRepository,
                                 AuditLogger auditLogger) {
        this.cipher = cipher;
        this.keyRing = keyRing;
        this.tokenVaultRepository = tokenVaultRepository;
        this.auditLogger = auditLogger;
    }

    /**
     * Detokenises a token and returns the original PAN.
     *
     * <p>The returned {@link DetokeniseResponse} contains the plain-text PAN. The caller
     * must not log, cache, or persist it. The PAN byte array is zeroed immediately after
     * the response is built — the string object in the response is the only remaining
     * reference and must be handled as sensitive by the caller.
     *
     * @param token      the opaque token value to detokenise; must not be null or blank
     * @param merchantId the merchant requesting detokenisation; must match the token's scope
     * @return the detokenisation response containing the plain-text PAN and card metadata
     * @throws TokenNotFoundException  if the token is not found or is inactive
     * @throws MerchantScopeException  if {@code merchantId} does not match the token's scope
     * @throws KeyIntegrityException   if the key is compromised or the GCM auth tag fails
     * @throws TokenisationException   if decryption fails for any other reason
     */
    @Transactional(readOnly = true)
    public DetokeniseResponse detokenise(String token, String merchantId) {
        Objects.requireNonNull(token, "token must not be null");
        Objects.requireNonNull(merchantId, "merchantId must not be null");

        TokenVault vault = findActiveVaultOrThrow(token);
        verifyMerchantScope(vault, merchantId);

        String keyVersionId = vault.getKeyVersion().getId().toString();
        KeyMaterial keyMaterial = keyRing.getByVersion(keyVersionId);

        checkKeyNotCompromised(keyMaterial, vault);

        byte[] kek = keyMaterial.copyKek();
        byte[] panBytes = null;
        try {
            panBytes = decryptPan(vault, kek, vault.getTokenId(), merchantId);
            String pan = new String(panBytes, StandardCharsets.UTF_8);
            DetokeniseResponse responseValue = buildResponse(pan, vault);

            log.debug("Detokenised token for merchant [{}], keyVersion [{}]",
                    merchantId, keyVersionId);
            auditLogger.logSuccess(AuditEventType.DETOKENISE, vault.getTokenId(),
                    merchantId, null, null, null);

            return responseValue;
        } finally {
            Arrays.fill(kek, (byte) 0);
            if (panBytes != null) {
                Arrays.fill(panBytes, (byte) 0);
            }
        }
    }

    // ── Private — detokenisation steps ───────────────────────────────────────

    /**
     * Looks up the token vault record by token value, asserting it exists and is active.
     *
     * @param token the opaque token value
     * @return the active vault record
     * @throws TokenNotFoundException if the token is not found or is inactive
     */
    private TokenVault findActiveVaultOrThrow(String token) {
        return tokenVaultRepository.findActiveByToken(token)
                .orElseThrow(() -> new TokenNotFoundException(token));
    }

    /**
     * Verifies that the requesting merchant ID matches the token's merchant scope.
     *
     * @param vault      the token vault record
     * @param merchantId the requesting merchant ID
     * @throws MerchantScopeException if the merchant IDs do not match
     */
    private void verifyMerchantScope(TokenVault vault, String merchantId) {
        if (!merchantId.equals(vault.getMerchantId())) {
            // Log at WARN — this event is significant but the detail must not leak to the response
            log.warn("Merchant scope violation: token belongs to a different merchant");
            auditLogger.logFailure(AuditEventType.MERCHANT_SCOPE_VIOLATION,
                    vault.getTokenId(), merchantId, null, null,
                    "Requesting merchant does not match token's merchant scope", null);
            throw new MerchantScopeException(
                    "Token does not belong to the requesting merchant");
        }
    }

    /**
     * Checks that the key material is not in a COMPROMISED state.
     *
     * <p>A compromised key means the KEK may have been exposed. Detokenisation is
     * blocked immediately to prevent further data exposure. A {@code TAMPER_ALERT}
     * audit event is written before throwing.
     *
     * @param keyMaterial the key material loaded from the ring
     * @param vault       the vault record (for audit tokenId)
     * @throws KeyIntegrityException if the key is compromised
     */
    private void checkKeyNotCompromised(KeyMaterial keyMaterial, TokenVault vault) {
        if (keyMaterial.status() == KeyStatus.COMPROMISED) {
            log.error("Detokenisation blocked — key version [{}] is COMPROMISED",
                    keyMaterial.keyVersionId());
            auditLogger.logFailure(AuditEventType.TAMPER_ALERT,
                    vault.getTokenId(), null, null, null,
                    "Detokenisation blocked: key version is COMPROMISED", null);
            throw new KeyIntegrityException(
                    "Key version is COMPROMISED — detokenisation blocked");
        }
    }

    /**
     * Decrypts the PAN bytes from the vault record.
     *
     * <p>A GCM authentication tag failure ({@link AEADBadTagException} wrapped in
     * {@link EncryptionException}) means the ciphertext or IV has been tampered with.
     * A {@code TAMPER_ALERT} audit event is written before rethrowing as
     * {@link KeyIntegrityException}.
     *
     * @param vault      the vault record containing ciphertext, IV, auth tag, encrypted DEK
     * @param kek        the KEK bytes (caller is responsible for zeroing after use)
     * @param tokenId    the token vault UUID (for logging; may be null in unit tests)
     * @param merchantId the merchant scope (for audit)
     * @return the decrypted PAN bytes — caller is responsible for zeroing after use
     * @throws KeyIntegrityException   if the GCM auth tag fails (tamper detected)
     * @throws TokenisationException   if decryption fails for any other reason
     */
    private byte[] decryptPan(TokenVault vault, byte[] kek, UUID tokenId, String merchantId) {
        try {
            return cipher.decrypt(
                    vault.getEncryptedPan(),
                    vault.getIv(),
                    vault.getAuthTag(),
                    vault.getEncryptedDek(),
                    kek);
        } catch (EncryptionException encryptionException) {
            if (encryptionException.getCause() instanceof AEADBadTagException) {
                log.error("GCM authentication tag failure for token [{}] — ciphertext may be tampered",
                        tokenId);
                auditLogger.logFailure(AuditEventType.TAMPER_ALERT,
                        vault.getTokenId(), merchantId, null, null,
                        "GCM authentication tag verification failed — ciphertext may be tampered", null);
                throw new KeyIntegrityException(
                        "GCM authentication tag verification failed — detokenisation blocked");
            }
            auditLogger.logFailure(AuditEventType.DETOKENISE_FAILURE,
                    vault.getTokenId(), merchantId, null, null,
                    "Decryption failed", null);
            throw encryptionException;
        }
    }

    /**
     * Builds the detokenisation response from the plain-text PAN and vault metadata.
     *
     * <p>The {@code expiryMonth} and {@code expiryYear} are stored as {@code Short} in
     * the vault entity and widened to {@code Integer} in the response for JSON compatibility.
     *
     * @param pan   the decrypted PAN string
     * @param vault the vault record containing card metadata
     * @return the response to return to the caller
     */
    private DetokeniseResponse buildResponse(String pan, TokenVault vault) {
        return DetokeniseResponse.builder()
                .pan(pan)
                .expiryMonth(vault.getExpiryMonth() != null ? vault.getExpiryMonth().intValue() : null)
                .expiryYear(vault.getExpiryYear() != null ? vault.getExpiryYear().intValue() : null)
                .cardScheme(vault.getCardScheme())
                .lastFour(vault.getLastFour())
                .tokenType(vault.getTokenType())
                .build();
    }
}
