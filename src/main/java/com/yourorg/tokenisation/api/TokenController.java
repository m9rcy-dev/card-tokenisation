package com.yourorg.tokenisation.api;

import com.yourorg.tokenisation.api.request.CardReplacementRequest;
import com.yourorg.tokenisation.api.request.TokeniseRequest;
import com.yourorg.tokenisation.api.response.DetokeniseResponse;
import com.yourorg.tokenisation.api.response.TokeniseResponse;
import com.yourorg.tokenisation.service.DetokenisationService;
import com.yourorg.tokenisation.service.TokenisationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

/**
 * REST controller for the token vault API.
 *
 * <p>Exposes three operations:
 * <ul>
 *   <li>{@code POST /api/v1/tokens} — tokenise a PAN and receive an opaque token
 *   <li>{@code GET /api/v1/tokens/{token}} — detokenise a token to recover the PAN
 *   <li>{@code DELETE /api/v1/tokens/{token}} — revoke a token (card lost/stolen)
 * </ul>
 *
 * <p>All request bodies are validated via Bean Validation ({@code @Valid}) before
 * reaching the service layer. Error responses are produced by {@link GlobalExceptionHandler}.
 */
@RestController
@RequestMapping("/api/v1/tokens")
@Tag(name = "Tokens", description = "Tokenisation and detokenisation operations")
@Slf4j
public class TokenController {

    private final TokenisationService tokenisationService;
    private final DetokenisationService detokenisationService;

    /**
     * Constructs the controller with both service collaborators.
     *
     * @param tokenisationService    the service that performs tokenisation; must not be null
     * @param detokenisationService  the service that performs detokenisation; must not be null
     */
    public TokenController(TokenisationService tokenisationService,
                           DetokenisationService detokenisationService) {
        this.tokenisationService = tokenisationService;
        this.detokenisationService = detokenisationService;
    }

    /**
     * Tokenises a PAN and returns an opaque token.
     *
     * <p>The same PAN always returns the same token (deterministic de-duplication).
     * A de-dup match is returned with HTTP 201, identical to a newly created token.
     *
     * @param request the tokenisation request; all fields are validated by {@code @Valid}
     * @return the token response containing the opaque token value and display metadata
     */
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Tokenise a PAN",
            description = "Replaces a PAN with an opaque token. "
                    + "The same PAN always returns the same token (deterministic de-duplication).")
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "Token created or de-dup match returned"),
            @ApiResponse(responseCode = "400", description = "Validation failure or invalid PAN"),
            @ApiResponse(responseCode = "500", description = "Internal error (crypto or KMS failure)")
    })
    public TokeniseResponse tokenise(@Valid @RequestBody TokeniseRequest request) {
        log.debug("Tokenise request received");
        return tokenisationService.tokenise(request);
    }

    /**
     * Detokenises an opaque token and returns the original PAN.
     *
     * <p>Rate limiting is applied by {@link com.yourorg.tokenisation.security.RateLimitInterceptor}
     * before this method is invoked.
     *
     * @param token the opaque token value from the URL path; must not be null
     * @return the detokenisation response containing the plain-text PAN and card metadata
     */
    @GetMapping("/{token}")
    @Operation(summary = "Detokenise a token",
            description = "Recovers the original PAN from an opaque token.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "PAN recovered successfully"),
            @ApiResponse(responseCode = "404", description = "Token not found, inactive, or expired"),
            @ApiResponse(responseCode = "429", description = "Rate limit exceeded"),
            @ApiResponse(responseCode = "500", description = "Crypto failure or compromised key")
    })
    public DetokeniseResponse detokenise(
            @Parameter(description = "Opaque token value", required = true)
            @PathVariable String token) {
        log.debug("Detokenise request received");
        return detokenisationService.detokenise(token);
    }

    /**
     * Replaces the PAN bound to an existing token with a new card's PAN.
     *
     * <p>Use when a customer's card is replaced (lost/stolen, renewal, upgrade).
     * The token value is unchanged — all downstream systems that hold this token
     * continue to work with no changes. Subsequent detokenisation returns the
     * new card's PAN.
     *
     * <p>Returns 409 if the new PAN already has a different active token in the vault.
     *
     * @param token   the existing opaque token to rebind
     * @param request the new card's PAN and metadata
     * @return updated token metadata (last four, card scheme, creation timestamp); no PAN
     */
    @PatchMapping("/{token}")
    @Operation(summary = "Replace the card behind a token",
            description = "Rebinds an existing token to a new card PAN. "
                    + "The token value is unchanged — downstream systems require no updates.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Card replaced successfully"),
            @ApiResponse(responseCode = "400", description = "Validation failure or invalid PAN"),
            @ApiResponse(responseCode = "404", description = "Token not found or inactive"),
            @ApiResponse(responseCode = "409", description = "New PAN already has a different active token")
    })
    public TokeniseResponse replaceCard(
            @Parameter(description = "Opaque token value to rebind", required = true)
            @PathVariable String token,
            @Valid @RequestBody CardReplacementRequest request) {
        log.debug("Card replacement request received");
        return tokenisationService.replaceCard(token, request);
    }

    /**
     * Revokes an active token, permanently preventing further detokenisation.
     *
     * <p>Use this endpoint when a card is reported lost or stolen. The token record
     * is deactivated ({@code is_active = false}) and a {@code TOKEN_REVOKED} audit
     * event is written. The record itself is retained for audit purposes.
     *
     * @param token the opaque token value to revoke; must not be null
     */
    @DeleteMapping("/{token}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(summary = "Revoke a token",
            description = "Permanently deactivates a token. Use when the card is lost or stolen. "
                    + "The token cannot be used for detokenisation after revocation.")
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "Token revoked successfully"),
            @ApiResponse(responseCode = "404", description = "Token not found or already inactive")
    })
    public void revokeToken(
            @Parameter(description = "Opaque token value to revoke", required = true)
            @PathVariable String token) {
        log.debug("Revoke request received");
        tokenisationService.revokeToken(token);
    }
}
