package com.yourorg.tokenisation.security;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.turbo.TurboFilter;
import ch.qos.logback.core.read.ListAppender;
import com.yourorg.tokenisation.AbstractIntegrationTest;
import com.yourorg.tokenisation.api.request.TokeniseRequest;
import com.yourorg.tokenisation.api.response.TokeniseResponse;
import com.yourorg.tokenisation.domain.TokenType;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies that PAN digits never appear in application log output, with or without
 * the {@link PanMaskingTurboFilter} safety net active.
 *
 * <p>Strategy: the {@code PanMaskingTurboFilter} is removed from the {@link LoggerContext}
 * for the duration of each test so that the {@link ListAppender} can capture every log
 * event that the application actually emits. After the test, the captured messages are
 * inspected for any 12–19-digit sequence matching the test PAN. A clean run proves that
 * production code never logs the PAN — not merely that the filter would have blocked it.
 *
 * <p>The filter is restored unconditionally in {@link #restoreLogbackConfiguration()}.
 */
class PanNeverInLogsTest extends AbstractIntegrationTest {

    /** Luhn-valid 16-digit Visa test PAN — the value we assert never reaches the logs. */
    private static final String VISA_PAN = "4111111111111111";

    /** Luhn-invalid PAN — exercises the service failure path without touching persistence. */
    private static final String LUHN_INVALID_PAN = "4111111111111112";

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    /** Captures all log events during the test. Attached to the root logger. */
    private ListAppender<ILoggingEvent> listAppender;

    /** Saved copy of turbo filters so they can be restored after the test. */
    private List<TurboFilter> savedTurboFilters;

    /**
     * Disables the {@link PanMaskingTurboFilter}, attaches a {@link ListAppender} to the
     * root logger, and ensures the database is clean with a valid seed key.
     */
    @BeforeEach
    void setUpLogCapture() {
        cleanDatabase();
        disableTurboFilters();
        attachListAppender();
    }

    /**
     * Removes the {@link ListAppender} and restores turbo filters in all cases,
     * preventing state from leaking into subsequent test classes.
     */
    @AfterEach
    void restoreLogbackConfiguration() {
        detachListAppender();
        restoreTurboFilters();
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    @Test
    void tokenise_happyPath_panNeverAppearsInAnyLogMessage() {
        TokeniseRequest request = buildRequest(VISA_PAN, TokenType.ONE_TIME, "MERCHANT_A");

        postTokenise(request);

        assertNoPanInLogs(VISA_PAN);
    }

    @Test
    void tokenise_recurringDedup_panNeverAppearsInAnyLogMessage() {
        TokeniseRequest request = buildRequest(VISA_PAN, TokenType.RECURRING, "MERCHANT_A");

        postTokenise(request);
        postTokenise(request); // second call triggers de-dup path

        assertNoPanInLogs(VISA_PAN);
    }

    @Test
    void tokenise_luhnInvalidPan_panNeverAppearsInAnyLogMessage() {
        TokeniseRequest request = buildRequest(LUHN_INVALID_PAN, TokenType.ONE_TIME, "MERCHANT_A");

        restTemplate.postForEntity("/api/v1/tokens", request, String.class);

        assertNoPanInLogs(LUHN_INVALID_PAN);
    }

    // ── Assertion helper ─────────────────────────────────────────────────────

    /**
     * Asserts that no captured log event's formatted message contains the given PAN digits.
     *
     * @param pan the PAN string whose digits must not appear verbatim in any log message
     */
    private void assertNoPanInLogs(String pan) {
        List<String> allMessages = listAppender.list.stream()
                .map(ILoggingEvent::getFormattedMessage)
                .collect(Collectors.toList());

        List<String> messagesWithPan = allMessages.stream()
                .filter(msg -> msg.contains(pan))
                .collect(Collectors.toList());

        assertThat(messagesWithPan)
                .as("Expected PAN [%s****] to never appear in log output, but found it in %d message(s):%n%s",
                        pan.substring(0, pan.length() - 4),
                        messagesWithPan.size(),
                        String.join("\n", messagesWithPan))
                .isEmpty();
    }

    // ── Logback setup / teardown ─────────────────────────────────────────────

    /**
     * Saves and removes all turbo filters from the {@link LoggerContext} so that the
     * {@link ListAppender} receives every log event unfiltered.
     *
     * <p>Removing the {@link PanMaskingTurboFilter} is intentional: the purpose of this
     * test is to verify that production code never logs the PAN, not that the filter
     * would suppress it.
     */
    private void disableTurboFilters() {
        LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
        savedTurboFilters = new ArrayList<>(context.getTurboFilterList());
        context.resetTurboFilterList();
    }

    /**
     * Attaches a fresh {@link ListAppender} to the root logger so all events are captured.
     */
    private void attachListAppender() {
        LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
        listAppender = new ListAppender<>();
        listAppender.setContext(context);
        listAppender.start();
        Logger rootLogger = context.getLogger(Logger.ROOT_LOGGER_NAME);
        rootLogger.addAppender(listAppender);
    }

    /**
     * Stops and detaches the {@link ListAppender} from the root logger.
     */
    private void detachListAppender() {
        if (listAppender == null) {
            return;
        }
        LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
        Logger rootLogger = context.getLogger(Logger.ROOT_LOGGER_NAME);
        rootLogger.detachAppender(listAppender);
        listAppender.stop();
    }

    /**
     * Re-adds all saved turbo filters to the {@link LoggerContext}.
     */
    private void restoreTurboFilters() {
        if (savedTurboFilters == null) {
            return;
        }
        LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
        savedTurboFilters.forEach(context::addTurboFilter);
    }

    // ── Database helpers ─────────────────────────────────────────────────────

    /**
     * Truncates transactional tables and re-seeds the ACTIVE key version so the
     * service can initialise successfully for each test.
     */
    private void cleanDatabase() {
        jdbcTemplate.execute("DELETE FROM token_vault");
        jdbcTemplate.execute("DELETE FROM token_audit_log");
        Timestamp rotateBy = Timestamp.from(Instant.now().plusSeconds(365L * 24 * 60 * 60));
        jdbcTemplate.update("""
                INSERT INTO key_versions (id, kms_key_id, kms_provider, key_alias, encrypted_kek_blob,
                    status, activated_at, rotate_by, created_by, checksum)
                VALUES (?::uuid, ?, ?, ?, ?, ?, now(), ?, ?, ?)
                ON CONFLICT (id) DO NOTHING
                """,
                SEED_KEY_VERSION_ID,
                "local-dev-key",
                "LOCAL_DEV",
                "integration-test-seed-key",
                "ignored",
                "ACTIVE",
                rotateBy,
                "test-seeder",
                "seed-checksum"
        );
    }

    // ── Request helpers ──────────────────────────────────────────────────────

    private ResponseEntity<TokeniseResponse> postTokenise(TokeniseRequest request) {
        return restTemplate.postForEntity("/api/v1/tokens", request, TokeniseResponse.class);
    }

    private TokeniseRequest buildRequest(String pan, TokenType tokenType, String merchantId) {
        TokeniseRequest request = new TokeniseRequest();
        request.setPan(pan);
        request.setTokenType(tokenType);
        request.setMerchantId(merchantId);
        request.setCardScheme("VISA");
        request.setExpiryMonth(12);
        request.setExpiryYear(2027);
        return request;
    }
}
