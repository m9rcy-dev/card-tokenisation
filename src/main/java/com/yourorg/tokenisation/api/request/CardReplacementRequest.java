package com.yourorg.tokenisation.api.request;

import com.yourorg.tokenisation.security.ValidCardScheme;
import jakarta.validation.constraints.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Request body for {@code PATCH /api/v1/tokens/{token}}.
 *
 * <p>Carries the new card's PAN and metadata to rebind to an existing token.
 * All fields are validated by Bean Validation before reaching the service layer.
 *
 * <p><strong>PAN must never appear in logs.</strong> The {@link #toString()} method
 * returns a masked representation — never call {@code pan} directly in log statements.
 */
@Getter
@Setter
@NoArgsConstructor
public class CardReplacementRequest {

    /**
     * The new card's PAN. Must be 12–19 decimal digits; Luhn validity is checked
     * in the service layer.
     */
    @NotBlank(message = "PAN must not be blank")
    @Pattern(
            regexp = "\\d{12,19}",
            message = "PAN must be 12 to 19 decimal digits"
    )
    private String pan;

    /** New card expiry month (1–12). */
    @NotNull(message = "Expiry month must not be null")
    @Min(value = 1, message = "Expiry month must be between 1 and 12")
    @Max(value = 12, message = "Expiry month must be between 1 and 12")
    private Integer expiryMonth;

    /**
     * New card expiry year (four digits, not before 2024).
     */
    @NotNull(message = "Expiry year must not be null")
    @Min(value = 2024, message = "Expiry year must not be before 2024")
    @Max(value = 9999, message = "Expiry year must be a valid four-digit year")
    private Integer expiryYear;

    /**
     * New card scheme. Must be present in the {@code tokenisation.allowed-card-schemes}
     * allowlist.
     */
    @NotBlank(message = "Card scheme must not be blank")
    @ValidCardScheme
    private String cardScheme;

    /**
     * Returns a safe string representation for logging with the PAN masked.
     *
     * @return loggable representation with PAN replaced by last-four hint only
     */
    @Override
    public String toString() {
        String maskedPan = (pan != null && pan.length() >= 4)
                ? "****" + pan.substring(pan.length() - 4)
                : "****";
        return "CardReplacementRequest{"
                + "pan='" + maskedPan + '\''
                + ", expiryMonth=" + expiryMonth
                + ", expiryYear=" + expiryYear
                + ", cardScheme='" + cardScheme + '\''
                + '}';
    }
}
