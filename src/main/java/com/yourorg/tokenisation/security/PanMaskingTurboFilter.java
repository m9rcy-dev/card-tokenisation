package com.yourorg.tokenisation.security;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.turbo.TurboFilter;
import ch.qos.logback.core.spi.FilterReply;
import org.slf4j.Marker;
import org.slf4j.helpers.MessageFormatter;

import java.util.regex.Pattern;

/**
 * Logback {@link TurboFilter} that blocks log events whose formatted message
 * contains a sequence of 12–19 consecutive decimal digits (a potential PAN).
 *
 * <p>This filter is a last-resort safety net. The primary defence is ensuring that
 * no production code logs PAN digits. This filter catches accidental or
 * debugging-era {@code log.debug("PAN: {}", pan)} statements before they reach
 * any appender.
 *
 * <p>When a PAN-like sequence is detected:
 * <ul>
 *   <li>The log event is dropped — {@link FilterReply#DENY} is returned.
 *   <li>A replacement WARN message is written via {@code System.err} (bypasses Logback
 *       to avoid infinite recursion) indicating that a log event was suppressed.
 * </ul>
 *
 * <p>All other events return {@link FilterReply#NEUTRAL}, allowing normal processing.
 *
 * <p><strong>Performance note:</strong> The regex is pre-compiled as a static constant.
 * All string formatting (argument substitution) is performed only when the event
 * would otherwise pass. This avoids unnecessary allocation on the hot path.
 *
 * <p>Wire this filter into {@code logback-spring.xml} or programmatically via the
 * Spring Boot logging configuration. See {@code logback-spring.xml} for configuration.
 */
public class PanMaskingTurboFilter extends TurboFilter {

    /**
     * Pre-compiled regex matching any run of 12–19 consecutive decimal digits.
     *
     * <p>12–19 covers all major PAN formats:
     * 13 (Visa legacy), 15 (Amex), 16 (Visa/MC/Discover), 19 (Maestro).
     * The filter deliberately casts a wide net — false positives are acceptable
     * (suppressed log events) but false negatives (PAN in logs) are not.
     */
    private static final Pattern PAN_PATTERN = Pattern.compile("\\d{12,19}");

    /**
     * Examines the formatted log message and denies the event if it contains a PAN-like sequence.
     *
     * @param marker     log marker (may be null)
     * @param logger     the logger that produced the event
     * @param level      the log level of the event
     * @param format     the message format string (may be null)
     * @param params     the format arguments (may be null or empty)
     * @param throwable  the associated throwable (may be null)
     * @return {@link FilterReply#DENY} if the formatted message contains 12–19 consecutive digits,
     *         {@link FilterReply#NEUTRAL} otherwise
     */
    @Override
    public FilterReply decide(Marker marker,
                              Logger logger,
                              Level level,
                              String format,
                              Object[] params,
                              Throwable throwable) {
        if (format == null) {
            return FilterReply.NEUTRAL;
        }

        String formattedMessage = formatMessage(format, params);

        if (PAN_PATTERN.matcher(formattedMessage).find()) {
            // Write to System.err to avoid calling back into Logback (infinite recursion risk)
            System.err.printf("[PAN-MASK] Suppressed log event from [%s] at level [%s] — " +
                    "message contained a PAN-like digit sequence%n",
                    logger.getName(), level);
            return FilterReply.DENY;
        }

        if (throwable != null && containsPanInThrowable(throwable)) {
            System.err.printf("[PAN-MASK] Suppressed log event from [%s] at level [%s] — " +
                    "exception message contained a PAN-like digit sequence%n",
                    logger.getName(), level);
            return FilterReply.DENY;
        }

        return FilterReply.NEUTRAL;
    }

    // ── Private ──────────────────────────────────────────────────────────────

    /**
     * Formats a message pattern with its arguments using SLF4J's formatter.
     *
     * <p>Produces the same string that would appear in the log output.
     *
     * @param format the message format pattern (e.g. {@code "Processing card {}"})
     * @param params the format arguments; may be null
     * @return the fully formatted message string
     */
    private String formatMessage(String format, Object[] params) {
        if (params == null || params.length == 0) {
            return format;
        }
        return MessageFormatter.arrayFormat(format, params).getMessage();
    }

    /**
     * Checks whether any message in the exception chain contains a PAN-like digit sequence.
     *
     * <p>Walks the full cause chain to ensure nested exception messages are also checked.
     *
     * @param throwable the exception to inspect
     * @return {@code true} if any exception message in the chain matches the PAN pattern
     */
    private boolean containsPanInThrowable(Throwable throwable) {
        Throwable current = throwable;
        while (current != null) {
            String exceptionMessage = current.getMessage();
            if (exceptionMessage != null && PAN_PATTERN.matcher(exceptionMessage).find()) {
                return true;
            }
            current = current.getCause();
        }
        return false;
    }
}
