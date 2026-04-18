package com.yourorg.tokenisation.exception;

/**
 * Thrown when a detokenisation attempt is rejected because the requesting merchant
 * does not own the token.
 *
 * <p>Tokens are scoped to the merchant that created them. A merchant attempting to
 * detokenise a token belonging to a different merchant triggers this exception.
 * This is a security boundary — the event must always be written to the audit log
 * as {@code MERCHANT_SCOPE_VIOLATION} before this exception propagates.
 *
 * <p>The exception message must not reveal the token's true owner.
 * Use generic wording (e.g. "merchant scope violation") only.
 */
public class MerchantScopeException extends TokenisationException {

    /**
     * Constructs a {@code MerchantScopeException} with a descriptive message.
     *
     * @param message description of the scope violation;
     *                must not reveal the token's true owner merchant ID
     */
    public MerchantScopeException(String message) {
        super(message);
    }

    /**
     * Constructs a {@code MerchantScopeException} wrapping a lower-level cause.
     *
     * @param message description of the scope violation
     * @param cause   the underlying exception
     */
    public MerchantScopeException(String message, Throwable cause) {
        super(message, cause);
    }
}
