package com.yourorg.tokenisation.api;

import com.yourorg.tokenisation.api.request.TokeniseRequest;
import com.yourorg.tokenisation.api.response.DetokeniseResponse;
import com.yourorg.tokenisation.api.response.TokeniseResponse;
import com.yourorg.tokenisation.service.DetokenisationService;
import com.yourorg.tokenisation.service.TokenisationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller for the token vault API.
 *
 * <p>Handles HTTP requests for tokenisation operations.
 * All request bodies are validated via Bean Validation ({@code @Valid}) before
 * reaching the service layer. Authentication and merchant scope are enforced
 * by the security filter chain (full JWT enforcement added in Phase 2 — currently
 * merchant ID is taken from the request body).
 *
 * <p>Error responses are produced by {@link GlobalExceptionHandler}.
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
     * <p>For {@code RECURRING} token types, an existing active token for the same
     * PAN and merchant is returned if one exists (de-duplication).
     * For {@code ONE_TIME} types, a fresh token is always created.
     *
     * <p>Returns HTTP 201 for both new tokens and de-duplicated recurring tokens.
     *
     * @param request the tokenisation request; all fields are validated by {@code @Valid}
     * @return the token response containing the opaque token value and display metadata
     */
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Tokenise a PAN",
            description = "Replaces a PAN with an opaque token. "
                    + "RECURRING tokens are deduplicated — the same PAN and merchant always "
                    + "return the same token. ONE_TIME tokens are always unique.")
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "Token created or dedup match returned"),
            @ApiResponse(responseCode = "400", description = "Validation failure or invalid PAN"),
            @ApiResponse(responseCode = "500", description = "Internal error (crypto or KMS failure)")
    })
    public TokeniseResponse tokenise(@Valid @RequestBody TokeniseRequest request) {
        log.debug("Tokenise request received for merchant [{}], tokenType [{}]",
                request.getMerchantId(), request.getTokenType());
        return tokenisationService.tokenise(request);
    }

    /**
     * Detokenises an opaque token and returns the original PAN.
     *
     * <p>The {@code X-Merchant-ID} header is used to enforce merchant scoping —
     * a token issued for merchant A cannot be detokenised by merchant B.
     * Rate limiting is applied by {@link com.yourorg.tokenisation.security.RateLimitInterceptor}
     * before this method is invoked.
     *
     * @param token      the opaque token value from the URL path; must not be null
     * @param merchantId the requesting merchant ID from the {@code X-Merchant-ID} header
     * @return the detokenisation response containing the plain-text PAN and card metadata
     */
    @GetMapping("/{token}")
    @Operation(summary = "Detokenise a token",
            description = "Recovers the original PAN from an opaque token. "
                    + "Requires `X-Merchant-ID` header matching the merchant that created the token.",
            security = @SecurityRequirement(name = "merchantId"))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "PAN recovered successfully"),
            @ApiResponse(responseCode = "403", description = "Token belongs to a different merchant"),
            @ApiResponse(responseCode = "404", description = "Token not found or inactive"),
            @ApiResponse(responseCode = "429", description = "Rate limit exceeded"),
            @ApiResponse(responseCode = "500", description = "Crypto failure or compromised key")
    })
    public DetokeniseResponse detokenise(
            @Parameter(description = "Opaque token value", required = true)
            @PathVariable String token,
            @Parameter(description = "Merchant ID that owns the token", required = true)
            @RequestHeader("X-Merchant-ID") String merchantId) {
        log.debug("Detokenise request received for merchant [{}]", merchantId);
        return detokenisationService.detokenise(token, merchantId);
    }
}
