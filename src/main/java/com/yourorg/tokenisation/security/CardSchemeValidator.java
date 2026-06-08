package com.yourorg.tokenisation.security;

import com.yourorg.tokenisation.config.TokenisationProperties;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

/**
 * Validates that a card scheme code is present in the configured allowlist.
 *
 * <p>The allowlist is sourced from {@link TokenisationProperties#getAllowedCardSchemes()},
 * bound from {@code tokenisation.allowed-card-schemes} in {@code application.yml}.
 * Spring's {@code SpringConstraintValidatorFactory} injects this bean automatically.
 */
public class CardSchemeValidator implements ConstraintValidator<ValidCardScheme, String> {

    private final TokenisationProperties properties;

    /**
     * Constructs the validator with the tokenisation configuration.
     *
     * @param properties the tokenisation properties containing the allowed schemes; must not be null
     */
    public CardSchemeValidator(TokenisationProperties properties) {
        this.properties = properties;
    }

    /**
     * Returns {@code true} if the value is non-null and present in the configured allowlist.
     *
     * @param value   the card scheme string from the request
     * @param context the constraint validator context (not used)
     * @return {@code true} if valid, {@code false} otherwise
     */
    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null || value.isBlank()) {
            return false;
        }
        return properties.getAllowedCardSchemes().contains(value);
    }
}
