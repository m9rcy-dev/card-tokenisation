package com.yourorg.tokenisation.exception;

/**
 * Base class for all domain exceptions in the card tokenisation system.
 *
 * <p>All business-logic failures thrown by the service layer extend this class.
 * Callers that need to handle any tokenisation-level error uniformly can catch
 * {@code TokenisationException}; callers that need precise handling should catch
 * the appropriate subtype directly.
 *
 * <p><strong>PAN must never appear in any exception message.</strong> Use token IDs,
 * masked PAN hints (e.g. {@code ****1234}), or generic descriptions only.
 */
public class TokenisationException extends RuntimeException {

    /**
     * Constructs a {@code TokenisationException} with a descriptive message.
     *
     * @param message description of the failure; must not contain PAN or key material
     */
    public TokenisationException(String message) {
        super(message);
    }

    /**
     * Constructs a {@code TokenisationException} wrapping a lower-level cause.
     *
     * @param message description of the failure; must not contain PAN or key material
     * @param cause   the underlying exception
     */
    public TokenisationException(String message, Throwable cause) {
        super(message, cause);
    }
}
