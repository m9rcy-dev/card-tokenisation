package com.yourorg.tokenisation.api.response;

import com.yourorg.tokenisation.domain.TokenType;
import lombok.Builder;
import lombok.Getter;

import java.time.Instant;

/**
 * Response body for {@code POST /api/v1/tokens}.
 *
 * <p>Returned with HTTP 201 on successful tokenisation and HTTP 200 when
 * a de-dup match is found for a {@code RECURRING} token.
 *
 * <p>The response contains no PAN digits — only the last four digits
 * ({@code lastFour}) are included as a cardholder display hint.
 */
@Getter
@Builder
public class TokeniseResponse {

    /**
     * The opaque token value assigned to the PAN.
     *
     * <p>For the default token format this is a UUID string.
     * The token is safe to store and transmit — it cannot be reversed
     * without access to the vault.
     */
    private final String token;

    /**
     * The token lifecycle type ({@code RECURRING} or {@code ONE_TIME}).
     *
     * @see TokenType
     */
    private final TokenType tokenType;

    /**
     * The last four digits of the original PAN.
     *
     * <p>Included as a display hint only (e.g. "ending in 1111").
     * No other PAN digits appear in the response.
     */
    private final String lastFour;

    /**
     * The card network scheme associated with the token (e.g. {@code VISA}).
     */
    private final String cardScheme;

    /**
     * The timestamp when the token record was created in the vault.
     */
    private final Instant createdAt;
}
