package com.yourorg.tokenisation.exception;

/**
 * Thrown when a token lookup fails because the token does not exist in the vault
 * or its status is not {@code ACTIVE}.
 *
 * <p>Raised by the detokenisation service when:
 * <ul>
 *   <li>The token UUID is not found in {@code token_vault}.
 *   <li>The matching record has status {@code INACTIVE} or {@code SUSPENDED}.
 * </ul>
 *
 * <p>The token UUID may be included in the message — it is an opaque identifier
 * with no sensitive content.
 */
public class TokenNotFoundException extends TokenisationException {

    /**
     * Constructs a {@code TokenNotFoundException} for the given token identifier.
     *
     * @param tokenId the token UUID that was not found or is inactive;
     *                safe to include as it contains no sensitive material
     */
    public TokenNotFoundException(String tokenId) {
        super("Token not found or inactive: " + tokenId);
    }

    /**
     * Constructs a {@code TokenNotFoundException} with a custom message.
     *
     * @param message description of the lookup failure
     * @param cause   the underlying exception, if any
     */
    public TokenNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
