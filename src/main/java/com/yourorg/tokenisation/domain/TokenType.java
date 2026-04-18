package com.yourorg.tokenisation.domain;

/**
 * Classifies the lifecycle and de-duplication behaviour of an issued token.
 *
 * <p>{@code RECURRING} tokens are deterministic: if a token has already been issued
 * for a given PAN and merchant, the same token value is returned on subsequent calls.
 * This supports recurring billing scenarios where the downstream system must recognise
 * the same card across multiple transactions.
 *
 * <p>{@code ONE_TIME} tokens are non-deterministic: a fresh token is generated on every
 * tokenise call regardless of whether a token for that PAN already exists.
 */
public enum TokenType {

    /**
     * Deterministic — same PAN and merchant always produce the same token.
     * Used for recurring billing and subscription payments.
     */
    RECURRING,

    /**
     * Non-deterministic — a new token is generated for every tokenise call.
     * Used for one-off payment authorisations.
     */
    ONE_TIME
}
