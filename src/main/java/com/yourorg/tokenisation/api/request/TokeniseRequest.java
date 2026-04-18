package com.yourorg.tokenisation.api.request;

import com.yourorg.tokenisation.domain.TokenType;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Request body for {@code POST /api/v1/tokens}.
 *
 * <p>All fields are validated by Bean Validation before the request reaches the service layer.
 * The controller must annotate the parameter with {@code @Valid} to trigger validation.
 *
 * <p><strong>PAN must never appear in logs.</strong> The {@link #toString()} method
 * returns a masked representation — never call {@code pan} directly in log statements.
 */
@Getter
@Setter
@NoArgsConstructor
public class TokeniseRequest {

    /**
     * The Primary Account Number to tokenise.
     *
     * <p>Must be 12–19 decimal digits. The Luhn check is performed in the service layer;
     * Bean Validation here rejects structurally invalid values early.
     */
    @NotBlank(message = "PAN must not be blank")
    @Pattern(
            regexp = "\\d{12,19}",
            message = "PAN must be 12 to 19 decimal digits"
    )
    private String pan;

    /**
     * Card expiry month (1–12).
     */
    @NotNull(message = "Expiry month must not be null")
    @Min(value = 1, message = "Expiry month must be between 1 and 12")
    @Max(value = 12, message = "Expiry month must be between 1 and 12")
    private Integer expiryMonth;

    /**
     * Card expiry year (four digits, not before 2024).
     *
     * <p>A floor of 2024 prevents obviously invalid values while allowing test data
     * with near-future expiry years. Precise expiry date validation (month + year
     * combination) is performed in the service layer.
     */
    @NotNull(message = "Expiry year must not be null")
    @Min(value = 2024, message = "Expiry year must not be before 2024")
    @Max(value = 9999, message = "Expiry year must be a valid four-digit year")
    private Integer expiryYear;

    /**
     * Card network scheme (e.g. {@code VISA}, {@code MASTERCARD}, {@code AMEX}).
     *
     * <p>Stored as-is; no scheme-specific routing logic is performed by this service.
     */
    @NotBlank(message = "Card scheme must not be blank")
    private String cardScheme;

    /**
     * Whether to issue a deterministic token (RECURRING) or a fresh one per call (ONE_TIME).
     *
     * @see TokenType
     */
    @NotNull(message = "Token type must not be null")
    private TokenType tokenType;

    /**
     * The merchant identity under whose scope the token is created.
     *
     * <p>Tokens are scoped per merchant — a token created for merchant A cannot be
     * detokenised by merchant B.
     */
    @NotBlank(message = "Merchant ID must not be blank")
    private String merchantId;

    /**
     * Returns a safe string representation of this request for logging.
     *
     * <p>The {@code pan} field is replaced with a masked form (last 4 digits only)
     * to comply with PCI-DSS requirements. Never modify this method to include the raw PAN.
     *
     * @return a loggable representation with the PAN masked
     */
    @Override
    public String toString() {
        String maskedPan = (pan != null && pan.length() >= 4)
                ? "****" + pan.substring(pan.length() - 4)
                : "****";
        return "TokeniseRequest{"
                + "pan='" + maskedPan + '\''
                + ", expiryMonth=" + expiryMonth
                + ", expiryYear=" + expiryYear
                + ", cardScheme='" + cardScheme + '\''
                + ", tokenType=" + tokenType
                + ", merchantId='" + merchantId + '\''
                + '}';
    }
}
