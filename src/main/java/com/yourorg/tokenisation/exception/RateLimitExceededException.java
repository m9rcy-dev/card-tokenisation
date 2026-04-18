package com.yourorg.tokenisation.exception;

/**
 * Thrown when a detokenisation request exceeds the configured rate limit.
 *
 * <p>The message is safe to include in the HTTP response — it contains only the
 * exceeded limit type (per-merchant or per-service) and the configured threshold,
 * never any sensitive material.
 *
 * <p>Mapped to HTTP 429 by {@link com.yourorg.tokenisation.api.GlobalExceptionHandler}.
 */
public class RateLimitExceededException extends TokenisationException {

    /**
     * Constructs a {@code RateLimitExceededException} with the given message.
     *
     * @param message describes which limit was exceeded and the threshold; must not contain PAN
     */
    public RateLimitExceededException(String message) {
        super(message);
    }
}
