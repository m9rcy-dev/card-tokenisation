package com.yourorg.tokenisation.service;

import com.yourorg.tokenisation.api.request.TokeniseRequest;
import com.yourorg.tokenisation.api.response.TokeniseResponse;
import com.yourorg.tokenisation.audit.AuditEventType;
import com.yourorg.tokenisation.audit.AuditLogger;
import com.yourorg.tokenisation.crypto.AesGcmCipher;
import com.yourorg.tokenisation.crypto.EncryptResult;
import com.yourorg.tokenisation.crypto.InMemoryKeyRing;
import com.yourorg.tokenisation.crypto.KeyMaterial;
import com.yourorg.tokenisation.crypto.PanHasher;
import com.yourorg.tokenisation.domain.KeyVersion;
import com.yourorg.tokenisation.domain.TokenType;
import com.yourorg.tokenisation.domain.TokenVault;
import com.yourorg.tokenisation.exception.PanValidationException;
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
 * Core business logic for tokenising PANs.
 *
 * <p>Tokenisation flow:
 * <ol>
 *   <li>Validate the PAN: non-null, non-blank, numeric, Luhn-valid.
 *   <li>Compute the PAN hash (HMAC-SHA256) for de-duplication.
 *   <li>If the token type is {@code RECURRING}, check for an existing active token
 *       for the same PAN hash and merchant — return it without creating a new record.
 *   <li>Retrieve the active {@link KeyMaterial} from the {@link InMemoryKeyRing}.
 *   <li>Encrypt the PAN using {@link AesGcmCipher}: generates a fresh DEK,
 *       wraps it with the KEK, encrypts the PAN with the DEK. The DEK is zeroed on exit.
 *   <li>Generate a random UUID token value.
 *   <li>Persist the {@link TokenVault} record.
 *   <li>Write a {@code TOKENISE} success or failure audit record.
 *   <li>Return {@link TokeniseResponse}.
 * </ol>
 *
 * <p>On any exception, a {@code TOKENISE_FAILURE} audit record is written
 * (in a separate transaction via {@link AuditLogger}) before the exception propagates.
 * Key material in local scope is always zeroed in {@code finally} blocks.
 *
 * <p><strong>PAN must never appear in any log statement, exception message,
 * or audit log field produced by this class.</strong>
 */
@Service
@Slf4j
public class TokenisationService {

    private final AesGcmCipher cipher;
    private final PanHasher panHasher;
    private final InMemoryKeyRing keyRing;
    private final TokenVaultRepository tokenVaultRepository;
    private final KeyVersionRepository keyVersionRepository;
    private final AuditLogger auditLogger;
    private final long defaultTokenTtlDays;

    /**
     * Constructs the service with all required collaborators.
     *
     * @param cipher                 AES-256-GCM cipher for PAN encryption; must not be null
     * @param panHasher              HMAC hasher for PAN de-duplication; must not be null
     * @param keyRing                in-memory key ring loaded at startup; must not be null
     * @param tokenVaultRepository   persistence for token vault records; must not be null
     * @param keyVersionRepository   persistence for key version records; must not be null
     * @param auditLogger            audit event writer; must not be null
     * @param defaultTokenTtlDays    TTL in days for issued tokens from configuration
     */
    public TokenisationService(
            AesGcmCipher cipher,
            PanHasher panHasher,
            InMemoryKeyRing keyRing,
            TokenVaultRepository tokenVaultRepository,
            KeyVersionRepository keyVersionRepository,
            AuditLogger auditLogger,
            @Value("${tokenisation.default-token-ttl-days:1825}") long defaultTokenTtlDays) {
        this.cipher = cipher;
        this.panHasher = panHasher;
        this.keyRing = keyRing;
        this.tokenVaultRepository = tokenVaultRepository;
        this.keyVersionRepository = keyVersionRepository;
        this.auditLogger = auditLogger;
        this.defaultTokenTtlDays = defaultTokenTtlDays;
    }

    /**
     * Tokenises a PAN and returns an opaque token.
     *
     * <p>For {@code RECURRING} token types, an existing active token for the same
     * PAN-merchant combination is returned without creating a new vault record.
     * For {@code ONE_TIME} types, a fresh token is always generated.
     *
     * @param request the tokenisation request with PAN, token type, and merchant scope; must not be null
     * @return the token response with the opaque token value and display metadata
     * @throws PanValidationException  if the PAN is null, blank, non-numeric, or Luhn-invalid
     * @throws TokenisationException   if the key ring has no active key, or encryption fails
     */
    @Transactional
    public TokeniseResponse tokenise(TokeniseRequest request) {
        Objects.requireNonNull(request, "TokeniseRequest must not be null");

        try {
            validatePan(request.getPan());

            String panHash = panHasher.hash(request.getPan());

            Optional<TokenVault> existingToken = findExistingRecurringToken(request, panHash);
            if (existingToken.isPresent()) {
                return handleDeduplicated(existingToken.get(), request);
            }
            return createNewToken(request, panHash);
        } catch (TokenisationException tokenisationException) {
            writeFailureAudit(request.getMerchantId(), tokenisationException.getMessage());
            throw tokenisationException;
        } catch (Exception unexpectedException) {
            writeFailureAudit(request.getMerchantId(), "Unexpected error during tokenisation");
            throw new TokenisationException("Tokenisation failed due to an internal error", unexpectedException);
        }
    }

    // ── Private — tokenisation steps ─────────────────────────────────────────

    /**
     * Looks up an existing active RECURRING token for the PAN hash and merchant.
     * Returns empty for ONE_TIME requests (de-dup never applies).
     *
     * @param request the tokenisation request
     * @param panHash the HMAC-SHA256 of the PAN
     * @return the existing token vault record, or empty
     */
    private Optional<TokenVault> findExistingRecurringToken(TokeniseRequest request, String panHash) {
        if (request.getTokenType() != TokenType.RECURRING) {
            return Optional.empty();
        }
        return tokenVaultRepository.findActiveRecurringByPanHashAndMerchant(panHash, request.getMerchantId());
    }

    /**
     * Returns a response for a de-duplicated RECURRING token and writes the success audit.
     *
     * @param existingVault the existing active token vault record
     * @param request       the original tokenisation request
     * @return the token response built from the existing vault record
     */
    private TokeniseResponse handleDeduplicated(TokenVault existingVault, TokeniseRequest request) {
        log.debug("Returning existing RECURRING token for merchant [{}]", request.getMerchantId());
        auditLogger.logSuccess(AuditEventType.TOKENISE, existingVault.getTokenId(),
                request.getMerchantId(), null, null, null);
        return buildResponse(existingVault);
    }

    /**
     * Creates a new token vault record and persists it.
     *
     * @param request the tokenisation request
     * @param panHash the HMAC-SHA256 of the PAN
     * @return the newly created token response
     */
    private TokeniseResponse createNewToken(TokeniseRequest request, String panHash) {
        KeyMaterial activeKeyMaterial = keyRing.getActive();
        KeyVersion activeKeyVersion = keyVersionRepository.findActiveOrThrow();

        byte[] kek = activeKeyMaterial.copyKek();
        byte[] panBytes = request.getPan().getBytes(StandardCharsets.UTF_8);
        try {
            EncryptResult encryptResult = cipher.encrypt(panBytes, kek);

            TokenVault newVault = buildVaultRecord(request, panHash, encryptResult, activeKeyVersion);
            tokenVaultRepository.save(newVault);

            log.debug("Created new token for merchant [{}], type [{}]",
                    request.getMerchantId(), request.getTokenType());
            auditLogger.logSuccess(AuditEventType.TOKENISE, newVault.getTokenId(),
                    request.getMerchantId(), null, null, null);

            return buildResponse(newVault);
        } finally {
            Arrays.fill(kek, (byte) 0);
            Arrays.fill(panBytes, (byte) 0);
        }
    }

    /**
     * Builds a {@link TokenVault} entity from the encryption result and request metadata.
     *
     * @param request          the tokenisation request
     * @param panHash          the HMAC-SHA256 of the PAN
     * @param encryptResult    the AES-GCM encryption output
     * @param activeKeyVersion the key version whose KEK wrapped the DEK
     * @return a fully populated, unsaved vault record
     */
    private TokenVault buildVaultRecord(TokeniseRequest request,
                                        String panHash,
                                        EncryptResult encryptResult,
                                        KeyVersion activeKeyVersion) {
        Instant now = Instant.now();
        String lastFour = request.getPan().substring(request.getPan().length() - 4);

        return TokenVault.builder()
                .token(UUID.randomUUID().toString())
                .encryptedPan(encryptResult.ciphertext())
                .iv(encryptResult.iv())
                .authTag(encryptResult.authTag())
                .encryptedDek(encryptResult.encryptedDek())
                .keyVersion(activeKeyVersion)
                .panHash(panHash)
                .tokenType(request.getTokenType())
                .lastFour(lastFour)
                .cardScheme(request.getCardScheme())
                .expiryMonth(request.getExpiryMonth() != null
                        ? request.getExpiryMonth().shortValue() : null)
                .expiryYear(request.getExpiryYear() != null
                        ? request.getExpiryYear().shortValue() : null)
                .merchantId(request.getMerchantId())
                .createdAt(now)
                .expiresAt(now.plus(defaultTokenTtlDays, ChronoUnit.DAYS))
                .build();
    }

    /**
     * Builds a {@link TokeniseResponse} from a persisted vault record.
     *
     * @param vault the persisted (or de-duplicated) vault record
     * @return the response to return to the caller
     */
    private TokeniseResponse buildResponse(TokenVault vault) {
        return TokeniseResponse.builder()
                .token(vault.getToken())
                .tokenType(vault.getTokenType())
                .lastFour(vault.getLastFour())
                .cardScheme(vault.getCardScheme())
                .createdAt(vault.getCreatedAt())
                .build();
    }

    // ── Private — PAN validation ─────────────────────────────────────────────

    /**
     * Validates PAN format: non-null, non-blank, numeric, 12–19 digits, Luhn-valid.
     *
     * @param pan the raw PAN string
     * @throws PanValidationException if any check fails; the message never includes the PAN digits
     */
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

    /**
     * Validates a numeric string using the Luhn algorithm.
     *
     * <p>The Luhn algorithm doubles every second digit from the right,
     * subtracts 9 from any doubled value above 9, then sums all digits.
     * A valid PAN produces a sum divisible by 10.
     *
     * @param pan the all-digit PAN string
     * @return {@code true} if the PAN passes the Luhn check
     */
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

    // ── Private — audit helpers ───────────────────────────────────────────────

    /**
     * Writes a tokenisation failure audit record.
     *
     * @param merchantId    the merchant scope; may be null
     * @param failureReason the reason; must not contain PAN
     */
    private void writeFailureAudit(String merchantId, String failureReason) {
        auditLogger.logFailure(AuditEventType.TOKENISE_FAILURE, null, merchantId,
                null, null, failureReason, null);
    }
}
