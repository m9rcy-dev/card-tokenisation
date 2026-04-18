package com.yourorg.tokenisation.exception;

/**
 * Thrown when a PAN fails format or Luhn validation before tokenisation.
 *
 * <p>This exception is raised by the tokenisation service when the supplied PAN
 * does not meet the minimum structural requirements: non-null, non-blank, numeric,
 * within the accepted length range (12–19 digits), and passing the Luhn check.
 *
 * <p><strong>The exception message must never include the PAN digits.</strong>
 * Use a generic description or a masked hint ({@code ****1234}) only.
 */
public class PanValidationException extends TokenisationException {

    /**
     * Constructs a {@code PanValidationException} with a descriptive message.
     *
     * @param message description of why the PAN failed validation;
     *                must not contain the raw PAN digits
     */
    public PanValidationException(String message) {
        super(message);
    }

    /**
     * Constructs a {@code PanValidationException} wrapping a lower-level cause.
     *
     * @param message description of why the PAN failed validation;
     *                must not contain the raw PAN digits
     * @param cause   the underlying exception (e.g. from a Luhn utility)
     */
    public PanValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
