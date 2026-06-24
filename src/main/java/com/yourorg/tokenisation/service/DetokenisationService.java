package com.yourorg.tokenisation.service;

import com.yourorg.tokenisation.api.response.DetokeniseResponse;
import com.yourorg.tokenisation.audit.AuditEventType;
import com.yourorg.tokenisation.audit.AuditLogger;
import com.yourorg.tokenisation.crypto.AesGcmCipher;
import com.yourorg.tokenisation.crypto.EncryptionException;
import com.yourorg.tokenisation.crypto.InMemoryDekKeyRing;
import com.yourorg.tokenisation.crypto.KeyMaterial;
import com.yourorg.tokenisation.domain.KeyStatus;
import com.yourorg.tokenisation.domain.TokenVault;
import com.yourorg.tokenisation.exception.KeyIntegrityException;
import com.yourorg.tokenisation.exception.TokenNotFoundException;
import com.yourorg.tokenisation.exception.TokenisationException;
import com.yourorg.tokenisation.repository.TokenVaultRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.AEADBadTagException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;

/**
 * Core business logic for detokenising tokens back to their original PANs.
 *
 * <p>Detokenisation flow:
 * <ol>
 *   <li>Look up the active {@link TokenVault} record by token value — 404 if absent or inactive.
 *   <li>Check expiry: if {@code expires_at} is in the past, return 404.
 *   <li>Retrieve {@link KeyMaterial} from {@link InMemoryDekKeyRing} by the vault's key version ID.
 *   <li>If key status is {@code COMPROMISED} — write {@code TAMPER_ALERT} and throw.
 *   <li>Copy the DEK bytes and decrypt the PAN via {@link AesGcmCipher#decrypt}.
 *   <li>Zero the DEK copy in a {@code finally} block.
 *   <li>Build response, zero PAN bytes.
 * </ol>
 */
@Service
@Slf4j
public class DetokenisationService {

    private final AesGcmCipher cipher;
    private final InMemoryDekKeyRing dekRing;
    private final TokenVaultRepository tokenVaultRepository;
    private final AuditLogger auditLogger;

    public DetokenisationService(AesGcmCipher cipher,
                                 InMemoryDekKeyRing dekRing,
                                 TokenVaultRepository tokenVaultRepository,
                                 AuditLogger auditLogger) {
        this.cipher = cipher;
        this.dekRing = dekRing;
        this.tokenVaultRepository = tokenVaultRepository;
        this.auditLogger = auditLogger;
    }

    @Transactional(readOnly = true)
    public DetokeniseResponse detokenise(String token) {
        Objects.requireNonNull(token, "token must not be null");

        TokenVault vault = findActiveVaultOrThrow(token);
        checkNotExpired(vault, token);

        String keyVersionId = vault.getKeyVersion().getId().toString();
        KeyMaterial keyMaterial = dekRing.getByVersion(keyVersionId);

        checkKeyNotCompromised(keyMaterial, vault);

        byte[] dek = keyMaterial.copyDek();
        byte[] panBytes = null;
        try {
            panBytes = decryptPan(vault, dek, vault.getTokenId());
            String pan = new String(panBytes, StandardCharsets.UTF_8);
            DetokeniseResponse responseValue = buildResponse(pan, vault);

            log.debug("Detokenised token, keyVersion [{}]", keyVersionId);
            auditLogger.logSuccess(AuditEventType.DETOKENISE, vault.getTokenId(), null, null, null);

            return responseValue;
        } finally {
            Arrays.fill(dek, (byte) 0);
            if (panBytes != null) {
                Arrays.fill(panBytes, (byte) 0);
            }
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private TokenVault findActiveVaultOrThrow(String token) {
        return tokenVaultRepository.findActiveByToken(token)
                .orElseThrow(() -> new TokenNotFoundException(token));
    }

    private void checkNotExpired(TokenVault vault, String token) {
        if (vault.getExpiresAt() != null && Instant.now().isAfter(vault.getExpiresAt())) {
            throw new TokenNotFoundException(token);
        }
    }

    private void checkKeyNotCompromised(KeyMaterial keyMaterial, TokenVault vault) {
        if (keyMaterial.status() == KeyStatus.COMPROMISED) {
            log.error("Detokenisation blocked — key version [{}] is COMPROMISED",
                    keyMaterial.keyVersionId());
            auditLogger.logFailure(AuditEventType.TAMPER_ALERT,
                    vault.getTokenId(), null, null,
                    "Detokenisation blocked: key version is COMPROMISED", null);
            throw new KeyIntegrityException(
                    "Key version is COMPROMISED — detokenisation blocked");
        }
    }

    private byte[] decryptPan(TokenVault vault, byte[] dek, UUID tokenId) {
        try {
            return cipher.decrypt(
                    vault.getEncryptedPan(),
                    vault.getIv(),
                    vault.getAuthTag(),
                    dek);
        } catch (EncryptionException encryptionException) {
            if (encryptionException.getCause() instanceof AEADBadTagException) {
                log.error("GCM authentication tag failure for token [{}] — ciphertext may be tampered",
                        tokenId);
                auditLogger.logFailure(AuditEventType.TAMPER_ALERT,
                        vault.getTokenId(), null, null,
                        "GCM authentication tag verification failed — ciphertext may be tampered", null);
                throw new KeyIntegrityException(
                        "GCM authentication tag verification failed — detokenisation blocked");
            }
            auditLogger.logFailure(AuditEventType.DETOKENISE_FAILURE,
                    vault.getTokenId(), null, null,
                    "Decryption failed", null);
            throw encryptionException;
        }
    }

    private DetokeniseResponse buildResponse(String pan, TokenVault vault) {
        return DetokeniseResponse.builder()
                .pan(pan)
                .expiryMonth(vault.getExpiryMonth() != null ? vault.getExpiryMonth().intValue() : null)
                .expiryYear(vault.getExpiryYear() != null ? vault.getExpiryYear().intValue() : null)
                .cardScheme(vault.getCardScheme())
                .lastFour(vault.getLastFour())
                .build();
    }
}
