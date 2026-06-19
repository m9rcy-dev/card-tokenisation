package com.yourorg.tokenisation.service;

import com.yourorg.tokenisation.api.request.CardReplacementRequest;
import com.yourorg.tokenisation.api.request.TokeniseRequest;
import com.yourorg.tokenisation.api.response.TokeniseResponse;
import com.yourorg.tokenisation.audit.AuditEventType;
import com.yourorg.tokenisation.audit.AuditLogger;
import com.yourorg.tokenisation.crypto.AesGcmCipher;
import com.yourorg.tokenisation.crypto.EncryptResult;
import com.yourorg.tokenisation.crypto.HashResult;
import com.yourorg.tokenisation.crypto.InMemoryHmacKeyRing;
import com.yourorg.tokenisation.crypto.InMemoryKekKeyRing;
import com.yourorg.tokenisation.crypto.KeyMaterial;
import com.yourorg.tokenisation.crypto.PanHasher;
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
 *   <li>Check for an existing active token for the same PAN hash — return it if found
 *       (deterministic: one PAN always maps to one token).
 *   <li>Retrieve the active {@link KeyMaterial} from the {@link InMemoryKekKeyRing}.
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
    private final InMemoryKekKeyRing keyRing;
    private final InMemoryHmacKeyRing hmacKeyRing;
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
            InMemoryKekKeyRing keyRing,
            InMemoryHmacKeyRing hmacKeyRing,
            TokenVaultRepository tokenVaultRepository,
            KeyVersionRepository keyVersionRepository,
            AuditLogger auditLogger,
            @Value("${tokenisation.default-token-ttl-days:1825}") long defaultTokenTtlDays) {
        this.cipher = cipher;
        this.panHasher = panHasher;
        this.keyRing = keyRing;
        this.hmacKeyRing = hmacKeyRing;
        this.tokenVaultRepository = tokenVaultRepository;
        this.keyVersionRepository = keyVersionRepository;
        this.auditLogger = auditLogger;
        this.defaultTokenTtlDays = defaultTokenTtlDays;
    }

    /**
     * Tokenises a PAN and returns an opaque token.
     *
     * <p>The vault is deterministic: the same PAN always returns the same token.
     * An existing active token is returned without creating a new vault record.
     *
     * @param request the tokenisation request with PAN and card metadata; must not be null
     * @return the token response with the opaque token value and display metadata
     * @throws PanValidationException  if the PAN is null, blank, non-numeric, or Luhn-invalid
     * @throws TokenisationException   if the key ring has no active key, or encryption fails
     */
    @Transactional
    public TokeniseResponse tokenise(TokeniseRequest request) {
        Objects.requireNonNull(request, "TokeniseRequest must not be null");

        try {
            validatePan(request.getPan());

            HashResult hashResult = panHasher.hash(request.getPan());

            // Primary lookup with new (current active) HMAC hash
            Optional<TokenVault> existingToken = tokenVaultRepository.findActiveByPanHash(hashResult.hash());

            // During HMAC rotation, some tokens may still carry the old hash — fall back to it
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

    /**
     * Revokes an active token, permanently preventing further detokenisation.
     *
     * <p>Deactivates the vault record ({@code is_active = false}) and writes a
     * {@code TOKEN_REVOKED} audit event. Used when a card is reported lost or stolen.
     *
     * @param token the opaque token value to revoke; must not be null or blank
     * @throws TokenNotFoundException if the token is not found or is already inactive
     */
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

    /**
     * Replaces the PAN bound to an existing token with the PAN of a replacement card.
     *
     * <p>The token value is unchanged. All PAN-related fields in the vault record are
     * re-encrypted with a fresh DEK and IV under the currently active KEK. Downstream
     * systems that already hold the token require no updates.
     *
     * <p>Returns 409 if the new PAN already has a different active token in the vault,
     * preserving the one-PAN-one-active-token invariant. Returns 200 if the new PAN
     * matches the current card (identity replacement — harmless re-encryption).
     *
     * @param token   the existing opaque token value to update; must not be null
     * @param request the new card's PAN and metadata; must not be null
     * @return token response with updated last four, card scheme, and creation timestamp
     * @throws TokenNotFoundException         if the token is not found or is inactive
     * @throws CardAlreadyTokenisedException  if the new PAN already has a different active token
     * @throws PanValidationException         if the new PAN fails Luhn or format checks
     * @throws TokenisationException          if encryption fails or the key ring has no active key
     */
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
            KeyMaterial activeKeyMaterial = keyRing.getActive();
            KeyVersion activeKeyVersion = keyVersionRepository.findActiveOrThrow();

            byte[] kek = activeKeyMaterial.copyKek();
            byte[] panBytes = request.getPan().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            try {
                EncryptResult encryptResult = cipher.encrypt(panBytes, kek);

                String newLastFour = request.getPan().substring(request.getPan().length() - 4);
                Instant newExpiresAt = Instant.now().plus(defaultTokenTtlDays, java.time.temporal.ChronoUnit.DAYS);

                vault.replacePanFields(
                        encryptResult.ciphertext(),
                        encryptResult.iv(),
                        encryptResult.authTag(),
                        encryptResult.encryptedDek(),
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
                Arrays.fill(kek, (byte) 0);
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

    // ── Private — tokenisation steps ─────────────────────────────────────────

    /**
     * Returns a response for a de-duplicated token and writes the success audit.
     *
     * @param existingVault the existing active token vault record
     * @return the token response built from the existing vault record
     */
    private TokeniseResponse handleDeduplicated(TokenVault existingVault) {
        log.debug("Returning existing token for de-duplicated PAN");
        auditLogger.logSuccess(AuditEventType.TOKENISE, existingVault.getTokenId(), null, null, null);
        return buildResponse(existingVault);
    }

    /**
     * Creates a new token vault record and persists it.
     *
     * @param request    the tokenisation request
     * @param hashResult the PAN hash and HMAC version ID from {@link PanHasher#hash}
     * @return the newly created token response
     */
    private TokeniseResponse createNewToken(TokeniseRequest request, HashResult hashResult) {
        KeyMaterial activeKeyMaterial = keyRing.getActive();
        KeyVersion activeKeyVersion = keyVersionRepository.findActiveOrThrow();

        byte[] kek = activeKeyMaterial.copyKek();
        byte[] panBytes = request.getPan().getBytes(StandardCharsets.UTF_8);
        try {
            EncryptResult encryptResult = cipher.encrypt(panBytes, kek);

            TokenVault newVault = buildVaultRecord(request, hashResult, encryptResult, activeKeyVersion);
            tokenVaultRepository.save(newVault);

            log.debug("Created new token");
            auditLogger.logSuccess(AuditEventType.TOKENISE, newVault.getTokenId(), null, null, null);

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
     * @param hashResult       the PAN hash and HMAC version ID
     * @param encryptResult    the AES-GCM encryption output
     * @param activeKeyVersion the key version whose KEK wrapped the DEK
     * @return a fully populated, unsaved vault record
     */
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
                .encryptedDek(encryptResult.encryptedDek())
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

    /**
     * Builds a {@link TokeniseResponse} from a persisted vault record.
     *
     * @param vault the persisted (or de-duplicated) vault record
     * @return the response to return to the caller
     */
    private TokeniseResponse buildResponse(TokenVault vault) {
        return TokeniseResponse.builder()
                .token(vault.getToken())
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
     * @param failureReason the reason; must not contain PAN
     */
    private void writeFailureAudit(String failureReason) {
        auditLogger.logFailure(AuditEventType.TOKENISE_FAILURE, null, null, null, failureReason, null);
    }
}
