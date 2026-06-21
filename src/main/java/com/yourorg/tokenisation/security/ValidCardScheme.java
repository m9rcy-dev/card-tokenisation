package com.yourorg.tokenisation.security;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

/**
 * Bean Validation constraint that checks a card scheme code against the configured allowlist.
 *
 * <p>The allowed values are driven by {@code tokenisation.allowed-card-schemes} in
 * {@code application.yml}. This means new schemes can be enabled via configuration
 * without code changes.
 *
 * <p>A {@code null} or blank value is rejected — use {@code @NotBlank} alongside this
 * annotation if null rejection is also required (which it is on {@code cardScheme}).
 */
@Documented
@Constraint(validatedBy = CardSchemeValidator.class)
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidCardScheme {

    /** Violation message returned when the scheme is not in the allowlist. */
    String message() default "Card scheme is not supported. Check tokenisation.allowed-card-schemes for accepted values.";

    /** Constraint groups. */
    Class<?>[] groups() default {};

    /** Constraint payload. */
    Class<? extends Payload>[] payload() default {};
}
