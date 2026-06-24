package com.yourorg.tokenisation.exception;

/**
 * Thrown when a card replacement is attempted with a PAN that already has a different
 * active token in the vault.
 *
 * <p>The vault enforces a one-PAN-one-active-token invariant. If the new PAN already
 * belongs to a different token, the replacement is rejected rather than silently
 * creating a duplicate or overwriting an unrelated token.
 *
 * <p>Maps to HTTP 409 Conflict in {@code GlobalExceptionHandler}.
 */
public class CardAlreadyTokenisedException extends TokenisationException {

    /**
     * Constructs the exception with a safe message (no PAN included).
     *
     * @param message description of the conflict; must not contain PAN digits
     */
    public CardAlreadyTokenisedException(String message) {
        super(message);
    }
}
