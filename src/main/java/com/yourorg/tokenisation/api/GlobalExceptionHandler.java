package com.yourorg.tokenisation.api;

import com.yourorg.tokenisation.exception.MerchantScopeException;
import com.yourorg.tokenisation.exception.PanValidationException;
import com.yourorg.tokenisation.exception.RateLimitExceededException;
import com.yourorg.tokenisation.exception.TokenNotFoundException;
import com.yourorg.tokenisation.exception.TokenisationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.net.URI;
import java.util.stream.Collectors;

/**
 * Global exception handler that translates domain exceptions to RFC 7807 Problem Detail responses.
 *
 * <p>Each exception type is mapped to an appropriate HTTP status code:
 * <ul>
 *   <li>{@link MethodArgumentNotValidException} — 400 (Bean Validation constraint failures)
 *   <li>{@link PanValidationException} — 400 (Luhn check or format failure)
 *   <li>{@link TokenNotFoundException} — 404
 *   <li>{@link MerchantScopeException} — 403
 *   <li>{@link TokenisationException} (any unmatched subtype) — 500
 *   <li>Unhandled {@link Exception} — 500
 * </ul>
 *
 * <p><strong>Exception messages must never contain PAN digits.</strong>
 * The domain exception hierarchy enforces this — this handler trusts that messages
 * from the service layer are safe to include in the response.
 */
@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    private static final URI TYPE_VALIDATION = URI.create("urn:tokenisation:error:validation");
    private static final URI TYPE_NOT_FOUND = URI.create("urn:tokenisation:error:not-found");
    private static final URI TYPE_FORBIDDEN = URI.create("urn:tokenisation:error:forbidden");
    private static final URI TYPE_RATE_LIMITED = URI.create("urn:tokenisation:error:rate-limited");
    private static final URI TYPE_INTERNAL = URI.create("urn:tokenisation:error:internal");

    /**
     * Handles Bean Validation failures from {@code @Valid} on request bodies.
     *
     * <p>Returns a 400 response listing all field violations.
     *
     * @param exception the constraint violation exception from Spring MVC
     * @return a 400 Problem Detail listing each invalid field and reason
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ProblemDetail handleValidationException(MethodArgumentNotValidException exception) {
        String detail = exception.getBindingResult().getFieldErrors().stream()
                .map(fieldError -> fieldError.getField() + ": " + fieldError.getDefaultMessage())
                .sorted()
                .collect(Collectors.joining("; "));
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, detail);
        problemDetail.setType(TYPE_VALIDATION);
        problemDetail.setTitle("Validation failed");
        return problemDetail;
    }

    /**
     * Handles PAN format and Luhn check failures.
     *
     * <p>Returns 400 with the sanitised failure message. The message must not include
     * the raw PAN digits — this is enforced by the {@link PanValidationException} contract.
     *
     * @param exception the PAN validation exception
     * @return a 400 Problem Detail
     */
    @ExceptionHandler(PanValidationException.class)
    public ProblemDetail handlePanValidationException(PanValidationException exception) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(
                HttpStatus.BAD_REQUEST, exception.getMessage());
        problemDetail.setType(TYPE_VALIDATION);
        problemDetail.setTitle("PAN validation failed");
        return problemDetail;
    }

    /**
     * Handles token lookup failures (token not found or inactive).
     *
     * <p>Returns 404. The token UUID is safe to include in the message.
     *
     * @param exception the token not found exception
     * @return a 404 Problem Detail
     */
    @ExceptionHandler(TokenNotFoundException.class)
    public ProblemDetail handleTokenNotFoundException(TokenNotFoundException exception) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(
                HttpStatus.NOT_FOUND, exception.getMessage());
        problemDetail.setType(TYPE_NOT_FOUND);
        problemDetail.setTitle("Token not found");
        return problemDetail;
    }

    /**
     * Handles cross-merchant access violations.
     *
     * <p>Returns 403. The response body deliberately omits details about the
     * true owner to avoid information leakage.
     *
     * @param exception the merchant scope exception
     * @return a 403 Problem Detail
     */
    @ExceptionHandler(MerchantScopeException.class)
    public ProblemDetail handleMerchantScopeException(MerchantScopeException exception) {
        log.warn("Merchant scope violation: {}", exception.getMessage());
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(
                HttpStatus.FORBIDDEN, "Access denied");
        problemDetail.setType(TYPE_FORBIDDEN);
        problemDetail.setTitle("Forbidden");
        return problemDetail;
    }

    /**
     * Handles rate limit violations from the detokenisation interceptor.
     *
     * <p>Returns 429 with the limit type and threshold in the detail. The {@code Retry-After}
     * header is not set — clients should back off with exponential jitter.
     *
     * @param exception the rate limit exceeded exception
     * @return a 429 Problem Detail
     */
    @ExceptionHandler(RateLimitExceededException.class)
    public ProblemDetail handleRateLimitExceededException(RateLimitExceededException exception) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(
                HttpStatus.TOO_MANY_REQUESTS, exception.getMessage());
        problemDetail.setType(TYPE_RATE_LIMITED);
        problemDetail.setTitle("Rate limit exceeded");
        return problemDetail;
    }

    /**
     * Handles all other domain exceptions not matched by a more specific handler.
     *
     * <p>Returns 500. The exception cause is logged at ERROR level but not exposed
     * in the response body to avoid information leakage.
     *
     * @param exception the domain exception
     * @return a 500 Problem Detail with a generic message
     */
    @ExceptionHandler(TokenisationException.class)
    public ProblemDetail handleTokenisationException(TokenisationException exception) {
        log.error("Tokenisation operation failed: {}", exception.getMessage(), exception);
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(
                HttpStatus.INTERNAL_SERVER_ERROR, "An internal error occurred");
        problemDetail.setType(TYPE_INTERNAL);
        problemDetail.setTitle("Internal server error");
        return problemDetail;
    }

    /**
     * Handles all unhandled exceptions as a safety net.
     *
     * <p>Returns 500. The exception is logged at ERROR but not exposed in the response.
     *
     * @param exception the unexpected exception
     * @return a 500 Problem Detail
     */
    @ExceptionHandler(Exception.class)
    public ProblemDetail handleUnexpectedException(Exception exception) {
        log.error("Unexpected error: {}", exception.getMessage(), exception);
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(
                HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred");
        problemDetail.setType(TYPE_INTERNAL);
        problemDetail.setTitle("Internal server error");
        return problemDetail;
    }
}
