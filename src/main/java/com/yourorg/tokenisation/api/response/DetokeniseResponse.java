package com.yourorg.tokenisation.api.response;

import com.yourorg.tokenisation.domain.TokenType;
import lombok.Builder;
import lombok.Getter;

/**
 * Response body for {@code GET /api/v1/tokens/{token}}.
 *
 * <p>Returns the plain-text PAN and card metadata to the authenticated caller.
 *
 * <p><strong>The {@code pan} field contains the raw PAN digits and must be handled
 * with care by the caller.</strong> It must not be logged, cached, or persisted.
 *
 * <p>{@link #toString()} masks the PAN to prevent accidental logging by Spring's
 * MVC request/response debug infrastructure.
 */
@Getter
@Builder
public class DetokeniseResponse {

    /**
     * The plain-text PAN recovered from the vault.
     * Sensitive — must not be logged or persisted by the caller.
     */
    private final String pan;

    /** Card expiry month (1–12). May be {@code null} if not recorded at tokenise time. */
    private final Integer expiryMonth;

    /** Card expiry year (e.g. 2027). May be {@code null} if not recorded at tokenise time. */
    private final Integer expiryYear;

    /**
     * Payment card scheme (e.g. {@code VISA}, {@code MC}, {@code AMEX}).
     * May be {@code null} if not recorded at tokenise time.
     */
    private final String cardScheme;

    /**
     * Last four digits of the PAN, stored in clear text.
     * Safe to log and display — does not allow PAN recovery.
     */
    private final String lastFour;

    /** Whether the token was issued for recurring billing or a one-off payment. */
    private final TokenType tokenType;

    /**
     * Returns a masked representation of this response.
     *
     * <p>The PAN is replaced with {@code ****XXXX} (last four only) to prevent
     * accidental PAN logging via Spring debug infrastructure, {@code toString()} calls
     * in logging frameworks, or developer tooling.
     *
     * @return a string representation with the PAN masked
     */
    @Override
    public String toString() {
        String maskedPan = (pan != null && pan.length() >= 4)
                ? "****" + pan.substring(pan.length() - 4)
                : "****";
        return "DetokeniseResponse{pan=" + maskedPan
                + ", expiryMonth=" + expiryMonth
                + ", expiryYear=" + expiryYear
                + ", cardScheme=" + cardScheme
                + ", lastFour=" + lastFour
                + ", tokenType=" + tokenType + "}";
    }
}
