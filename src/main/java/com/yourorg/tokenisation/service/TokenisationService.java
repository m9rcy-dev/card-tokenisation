package com.yourorg.tokenisation.service;

import com.yourorg.tokenisation.api.request.CardReplacementRequest;
import com.yourorg.tokenisation.api.request.TokeniseRequest;
import com.yourorg.tokenisation.api.response.TokeniseResponse;
import com.yourorg.tokenisation.audit.AuditEventType;
import com.yourorg.tokenisation.audit.AuditLogger;
import com.yourorg.tokenisation.crypto.*;
import com.yourorg.tokenisation.domain.KeyVersion;
import com.yourorg.tokenisation.domain.TokenVault;
import com.yourorg.tokenisation.exception.CardAlreadyTokenisedException;
import com.yourorg.tokenisation.exception.PanValidationException;
import com.yourorg.tokenisation.exception.TokenNotFoundException;
import com.yourorg.tokenisation.exception.TokenisationException;
import com.yourorg.tokenisation.repository.KeyVersionRepository;
import com.yourorg.tokenisation.repository.TokenVaultRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Core business logic for tokenising and revoking PANs.
 *
 * <p>Tokenisation flow:
 * <ol>
 *   <li>Validate the PAN: non-null, non-blank, numeric, Luhn-valid.
 *   <li>Compute the PAN hash (HMAC-SHA256) for de-duplication.
 *   <li>Check for an existing active token for the same PAN hash — return it if found.
 *   <li>Retrieve the active {@link KeyMaterial} from the {@link InMemoryDekKeyRing}.
 *   <li>Encrypt the PAN using {@link AesGcmCipher}: uses the in-memory DEK + fresh IV.
 *   <li>Persist the {@link TokenVault} record.
 *   <li>Write audit record and return {@link TokeniseResponse}.
 * </ol>
 */
@Service
@Slf4j
public class TokenisationService {

    private final AesGcmCipher cipher;
    private final PanHasher panHasher;
    private final InMemoryDekKeyRing dekRing;
    private final InMemoryHmacKeyRing hmacKeyRing;
    private final TokenVaultRepository tokenVaultRepository;
    private final KeyVersionRepository keyVersionRepository;
    private final AuditLogger auditLogger;
    private final long defaultTokenTtlDays;

    public TokenisationService(
            AesGcmCipher cipher,
            PanHasher panHasher,
            InMemoryDekKeyRing dekRing,
            InMemoryHmacKeyRing hmacKeyRing,
            TokenVaultRepository tokenVaultRepository,
            KeyVersionRepository keyVersionRepository,
            AuditLogger auditLogger,
            @Value("${tokenisation.default-token-ttl-days:1825}") long defaultTokenTtlDays) {
        this.cipher = cipher;
        this.panHasher = panHasher;
        this.dekRing = dekRing;
        this.hmacKeyRing = hmacKeyRing;
        this.tokenVaultRepository = tokenVaultRepository;
        this.keyVersionRepository = keyVersionRepository;
        this.auditLogger = auditLogger;
        this.defaultTokenTtlDays = defaultTokenTtlDays;
    }

    @Transactional
    public TokeniseResponse tokenise(TokeniseRequest request) {
        Objects.requireNonNull(request, "TokeniseRequest must not be null");

        try {
            validatePan(request.getPan());

            HashResult hashResult = panHasher.hash(request.getPan());

            Optional<TokenVault> existingToken = tokenVaultRepository.findActiveByPanHash(hashResult.hash());

            if (existingToken.isEmpty()) {
                Optional<String> rotatingHmacId = hmacKeyRing.findRotatingVersionId();
                if (rotatingHmacId.isPresent()) {
                    String oldHash = panHasher.hashWithVersion(request.getPan(), rotatingHmacId.get());
                    existingToken = tokenVaultRepository.findActiveByPanHash(oldHash);
                }
            }

            if (existingToken.isPresent()) {
                return handleDeduplicated(existingToken.get());
            }
            return createNewToken(request, hashResult);
        } catch (TokenisationException tokenisationException) {
            writeFailureAudit(tokenisationException.getMessage());
            throw tokenisationException;
        } catch (Exception unexpectedException) {
            writeFailureAudit("Unexpected error during tokenisation");
            throw new TokenisationException("Tokenisation failed due to an internal error", unexpectedException);
        }
    }

    @Transactional
    public void revokeToken(String token) {
        Objects.requireNonNull(token, "token must not be null");

        TokenVault vault = tokenVaultRepository.findActiveByToken(token)
                .orElseThrow(() -> new TokenNotFoundException(token));

        vault.deactivate();
        tokenVaultRepository.save(vault);

        log.debug("Token revoked: [{}]", vault.getTokenId());
        auditLogger.logSuccess(AuditEventType.TOKEN_REVOKED, vault.getTokenId(), null, null, null);
    }

    @Transactional
    public TokeniseResponse replaceCard(String token, CardReplacementRequest request) {
        Objects.requireNonNull(token, "token must not be null");
        Objects.requireNonNull(request, "CardReplacementRequest must not be null");

        validatePan(request.getPan());

        HashResult newHashResult = panHasher.hash(request.getPan());

        TokenVault vault = tokenVaultRepository.findActiveByToken(token)
                .orElseThrow(() -> new TokenNotFoundException(token));

        tokenVaultRepository.findActiveByPanHash(newHashResult.hash()).ifPresent(existing -> {
            if (!existing.getToken().equals(vault.getToken())) {
                throw new CardAlreadyTokenisedException(
                        "The new PAN already has an active token in the vault");
            }
        });

        try {
            KeyMaterial activeKeyMaterial = dekRing.getActive();
            KeyVersion activeKeyVersion = keyVersionRepository.findById(
                    UUID.fromString(activeKeyMaterial.keyVersionId()))
                    .orElseThrow(() -> new IllegalStateException(
                            "Active key version from ring not found in DB: " + activeKeyMaterial.keyVersionId()));

            byte[] dek = activeKeyMaterial.copyDek();
            byte[] panBytes = request.getPan().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            try {
                EncryptResult encryptResult = cipher.encrypt(panBytes, dek);

                String newLastFour = request.getPan().substring(request.getPan().length() - 4);
                Instant newExpiresAt = Instant.now().plus(defaultTokenTtlDays, java.time.temporal.ChronoUnit.DAYS);

                vault.replacePanFields(
                        encryptResult.ciphertext(),
                        encryptResult.iv(),
                        encryptResult.authTag(),
                        activeKeyVersion,
                        newHashResult.hash(),
                        newLastFour,
                        request.getCardScheme(),
                        request.getExpiryMonth() != null ? request.getExpiryMonth().shortValue() : null,
                        request.getExpiryYear() != null ? request.getExpiryYear().shortValue() : null,
                        newExpiresAt);
                vault.updatePanHash(newHashResult.hash(), UUID.fromString(newHashResult.hmacVersionId()));

                tokenVaultRepository.save(vault);

                log.debug("Card replaced on token [{}]", vault.getTokenId());
                auditLogger.logSuccess(AuditEventType.CARD_REPLACED, vault.getTokenId(), null, null, null);

                return buildResponse(vault);
            } finally {
                Arrays.fill(dek, (byte) 0);
                Arrays.fill(panBytes, (byte) 0);
            }
        } catch (CardAlreadyTokenisedException | TokenNotFoundException | PanValidationException e) {
            throw e;
        } catch (TokenisationException e) {
            throw e;
        } catch (Exception e) {
            throw new TokenisationException("Card replacement failed due to an internal error", e);
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private TokeniseResponse handleDeduplicated(TokenVault existingVault) {
        log.debug("Returning existing token for de-duplicated PAN");
        auditLogger.logSuccess(AuditEventType.TOKENISE, existingVault.getTokenId(), null, null, null);
        return buildResponse(existingVault);
    }

    private TokeniseResponse createNewToken(TokeniseRequest request, HashResult hashResult) {
        KeyMaterial activeKeyMaterial = dekRing.getActive();
        KeyVersion activeKeyVersion = keyVersionRepository.findById(
                UUID.fromString(activeKeyMaterial.keyVersionId()))
                .orElseThrow(() -> new IllegalStateException(
                        "Active key version from ring not found in DB: " + activeKeyMaterial.keyVersionId()));

        byte[] dek = activeKeyMaterial.copyDek();
        byte[] panBytes = request.getPan().getBytes(StandardCharsets.UTF_8);
        try {
            EncryptResult encryptResult = cipher.encrypt(panBytes, dek);

            TokenVault newVault = buildVaultRecord(request, hashResult, encryptResult, activeKeyVersion);
            tokenVaultRepository.save(newVault);

            log.debug("Created new token");
            auditLogger.logSuccess(AuditEventType.TOKENISE, newVault.getTokenId(), null, null, null);

            return buildResponse(newVault);
        } finally {
            Arrays.fill(dek, (byte) 0);
            Arrays.fill(panBytes, (byte) 0);
        }
    }

    private TokenVault buildVaultRecord(TokeniseRequest request,
                                        HashResult hashResult,
                                        EncryptResult encryptResult,
                                        KeyVersion activeKeyVersion) {
        Instant now = Instant.now();
        String lastFour = request.getPan().substring(request.getPan().length() - 4);

        return TokenVault.builder()
                .token(UUID.randomUUID().toString())
                .encryptedPan(encryptResult.ciphertext())
                .iv(encryptResult.iv())
                .authTag(encryptResult.authTag())
                .keyVersion(activeKeyVersion)
                .panHash(hashResult.hash())
                .hmacKeyVersionId(UUID.fromString(hashResult.hmacVersionId()))
                .lastFour(lastFour)
                .cardScheme(request.getCardScheme())
                .expiryMonth(request.getExpiryMonth() != null
                        ? request.getExpiryMonth().shortValue() : null)
                .expiryYear(request.getExpiryYear() != null
                        ? request.getExpiryYear().shortValue() : null)
                .createdAt(now)
                .expiresAt(now.plus(defaultTokenTtlDays, ChronoUnit.DAYS))
                .build();
    }

    private TokeniseResponse buildResponse(TokenVault vault) {
        return TokeniseResponse.builder()
                .token(vault.getToken())
                .lastFour(vault.getLastFour())
                .cardScheme(vault.getCardScheme())
                .createdAt(vault.getCreatedAt())
                .build();
    }

    private void validatePan(String pan) {
        if (pan == null || pan.isBlank()) {
            throw new PanValidationException("PAN must not be null or blank");
        }
        if (!pan.matches("\\d{12,19}")) {
            throw new PanValidationException("PAN must be 12 to 19 decimal digits");
        }
        if (!isLuhnValid(pan)) {
            throw new PanValidationException("PAN failed Luhn validation");
        }
    }

    private boolean isLuhnValid(String pan) {
        int total = 0;
        boolean doubleDigit = false;

        for (int index = pan.length() - 1; index >= 0; index--) {
            int digit = pan.charAt(index) - '0';
            if (doubleDigit) {
                digit *= 2;
                if (digit > 9) {
                    digit -= 9;
                }
            }
            total += digit;
            doubleDigit = !doubleDigit;
        }
        return total % 10 == 0;
    }

    private void writeFailureAudit(String failureReason) {
        auditLogger.logFailure(AuditEventType.TOKENISE_FAILURE, null, null, null, failureReason, null);
    }
}
