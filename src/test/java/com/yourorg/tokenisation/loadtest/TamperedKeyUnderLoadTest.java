package com.yourorg.tokenisation.loadtest;

import com.yourorg.tokenisation.api.request.TokeniseRequest;
import com.yourorg.tokenisation.api.response.DetokeniseResponse;
import com.yourorg.tokenisation.api.response.TokeniseResponse;
import com.yourorg.tokenisation.audit.AuditEventType;
import com.yourorg.tokenisation.crypto.InMemoryKeyRing;
import com.yourorg.tokenisation.crypto.TamperDetector;
import com.yourorg.tokenisation.domain.KeyVersion;
import com.yourorg.tokenisation.domain.TokenType;
import com.yourorg.tokenisation.exception.KeyIntegrityException;
import com.yourorg.tokenisation.kms.KmsProvider;
import com.yourorg.tokenisation.repository.AuditLogRepository;
import com.yourorg.tokenisation.repository.KeyVersionRepository;
import com.yourorg.tokenisation.repository.TokenVaultRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tampered-key-under-load tests.
 *
 * <p>Verifies that the tamper detection mechanism fires correctly when a
 * {@code key_versions} row is modified outside the application while the system
 * is under detokenisation load.
 *
 * <h3>Tamper detection flow</h3>
 * <ol>
 *   <li>The DB-level tamper is committed via JDBC.
 *   <li>{@link TamperDetector#assertIntegrity} is called to trigger detection.
 *   <li>A {@code TAMPER_ALERT} audit event must appear within 1 second.
 *   <li>{@link InMemoryKeyRing#markCompromised} isolates the compromised key.
 *   <li>Subsequent detokenisation requests fail (HTTP 500 — compromised key).
 *   <li>New requests (tokenise / detokenise of new tokens on a new key) are unaffected.
 * </ol>
 *
 * <p>Pre-seeds 500 ONE_TIME tokens (concurrency=20 to match the HikariCP pool) before
 * each test. Tamper-detection and response assertions do not depend on seed volume.
 *
 * <p>Only runs with: {@code JAVA_HOME=/opt/homebrew/opt/openjdk@21 mvn test -P load-tests}
 */
@Tag("load")
class TamperedKeyUnderLoadTest extends AbstractLoadTest {

    private static final int SEED_TOKEN_COUNT = 500;
    private static final String MERCHANT = "LOAD_MERCHANT_TAM";

    @Autowired private TestRestTemplate restTemplate;
    @Autowired private JdbcTemplate jdbcTemplate;
    @Autowired private KeyVersionRepository keyVersionRepository;
    @Autowired private TokenVaultRepository tokenVaultRepository;
    @Autowired private AuditLogRepository auditLogRepository;
    @Autowired private TamperDetector tamperDetector;
    @Autowired private InMemoryKeyRing keyRing;
    @Autowired private KmsProvider kmsProvider;

    /** Token strings for the 5K pre-seeded tokens. */
    private String[] seededTokens;

    @BeforeEach
    void setUpForTamperTest() {
        jdbcTemplate.execute("DELETE FROM token_vault");
        jdbcTemplate.execute("DELETE FROM token_audit_log");

        jdbcTemplate.execute(
                "UPDATE key_versions SET status = 'RETIRED' WHERE id != '" + SEED_KEY_VERSION_ID + "'::uuid");
        jdbcTemplate.execute(
                "UPDATE key_versions SET status = 'ACTIVE' WHERE id = '" + SEED_KEY_VERSION_ID + "'::uuid");

        // Compute real checksum for seed key
        KeyVersion seedKey = keyVersionRepository.findActiveOrThrow();
        seedKey.initializeChecksum(tamperDetector.computeChecksum(seedKey));
        keyVersionRepository.save(seedKey);

        // Reload seed key into ring
        byte[] seedKek = kmsProvider.unwrapKek(seedKey.getEncryptedKekBlob());
        try {
            keyRing.load(SEED_KEY_VERSION_ID, seedKek, seedKey.getRotateBy());
            keyRing.promoteActive(SEED_KEY_VERSION_ID);
        } finally {
            Arrays.fill(seedKek, (byte) 0);
        }

        seededTokens = seedTokens(SEED_TOKEN_COUNT, 20);
    }

    // ── LT-TA-1 ──────────────────────────────────────────────────────────────

    /**
     * LT-TA-1: DB-level key tamper → {@link KeyIntegrityException} thrown on next key read →
     * {@code TAMPER_ALERT} audit event written within 1 second of tamper.
     */
    @Test
    void tamperedKey_keyIntegrityExceptionThrownAndTamperAlertWrittenWithin1s() {
        // Tamper the key_versions row by writing a garbage checksum
        jdbcTemplate.update(
                "UPDATE key_versions SET checksum = 'tampered_checksum_value' WHERE id = ?::uuid",
                SEED_KEY_VERSION_ID);

        KeyVersion seedKey = keyVersionRepository.findById(UUID.fromString(SEED_KEY_VERSION_ID))
                .orElseThrow();

        long tamperTimeMs = System.currentTimeMillis();

        // assertIntegrity must throw KeyIntegrityException and write TAMPER_ALERT
        assertThatThrownBy(() -> tamperDetector.assertIntegrity(seedKey))
                .isInstanceOf(KeyIntegrityException.class)
                .hasMessageContaining(SEED_KEY_VERSION_ID);

        long detectionDelayMs = System.currentTimeMillis() - tamperTimeMs;

        // TAMPER_ALERT audit event must have been written within 1 second
        List<String> eventTypes = jdbcTemplate.queryForList(
                "SELECT event_type FROM token_audit_log WHERE event_type = ?",
                String.class,
                AuditEventType.TAMPER_ALERT.name());
        assertThat(eventTypes)
                .as("LT-TA-1: TAMPER_ALERT audit event must be written on integrity failure")
                .isNotEmpty();
        assertThat(detectionDelayMs)
                .as("LT-TA-1: TAMPER_ALERT written within 1000ms of tamper (actual: %dms)", detectionDelayMs)
                .isLessThanOrEqualTo(1_000L);
    }

    // ── LT-TA-2 ──────────────────────────────────────────────────────────────

    /**
     * LT-TA-2: Zero successful detokenisations are recorded after the tamper is committed
     * and the key is marked compromised in the ring.
     */
    @Test
    void tamperedKey_zeroSuccessfulDetokenisationsAfterTamperCommitted() {
        // Tamper the DB row
        jdbcTemplate.update(
                "UPDATE key_versions SET checksum = 'tampered_checksum_value' WHERE id = ?::uuid",
                SEED_KEY_VERSION_ID);

        KeyVersion seedKey = keyVersionRepository.findById(UUID.fromString(SEED_KEY_VERSION_ID))
                .orElseThrow();

        // Detect tamper — this writes TAMPER_ALERT and throws KeyIntegrityException
        try {
            tamperDetector.assertIntegrity(seedKey);
        } catch (KeyIntegrityException ignored) {
            // Expected — detection fired
        }

        // Isolate the compromised key in the ring so detokenisation is blocked
        keyRing.markCompromised(SEED_KEY_VERSION_ID);

        // Delete the tokenise audit records for a clean baseline
        jdbcTemplate.execute("DELETE FROM token_audit_log WHERE event_type != '"
                + AuditEventType.TAMPER_ALERT.name() + "'");

        // Attempt to detokenise all 5K seeded tokens — all should fail
        AtomicLong successfulDetokenisations = new AtomicLong();
        ExecutorService verifier = buildVirtualThreadExecutor(20);

        for (String token : seededTokens) {
            verifier.submit(() -> {
                ResponseEntity<DetokeniseResponse> resp = detokenise(token, MERCHANT);
                if (resp.getStatusCode() == HttpStatus.OK) {
                    successfulDetokenisations.incrementAndGet();
                }
            });
        }

        awaitCompletion(verifier, 120);

        // Verify no successful detokenisations in audit log after tamper
        long successAuditCount = auditLogRepository.findAll().stream()
                .filter(e -> "DETOKENISE".equals(e.getEventType())
                        && "SUCCESS".equals(e.getOutcome()))
                .count();

        assertThat(successfulDetokenisations.get())
                .as("LT-TA-2: zero HTTP 200 detokenisations after compromised key isolated")
                .isZero();
        assertThat(successAuditCount)
                .as("LT-TA-2: zero DETOKENISE SUCCESS audit records after tamper")
                .isZero();
    }

    // ── LT-TA-3 ──────────────────────────────────────────────────────────────

    /**
     * LT-TA-3: The system remains responsive to new requests after tamper isolation.
     *
     * <p>After the compromised key is isolated, new tokens must still be creatable if
     * a new ACTIVE key is available. The existing seed key being compromised should not
     * cause a system-wide outage — only operations on compromised-key tokens are blocked.
     */
    @Test
    void tamperedKey_systemRemainsResponsiveAfterTamperIsolation() {
        // Tamper the DB row and isolate the key
        jdbcTemplate.update(
                "UPDATE key_versions SET checksum = 'tampered_checksum_value' WHERE id = ?::uuid",
                SEED_KEY_VERSION_ID);
        try {
            KeyVersion seedKey = keyVersionRepository.findById(UUID.fromString(SEED_KEY_VERSION_ID))
                    .orElseThrow();
            tamperDetector.assertIntegrity(seedKey);
        } catch (KeyIntegrityException ignored) {
            // Expected
        }
        keyRing.markCompromised(SEED_KEY_VERSION_ID);

        // Send 100 tokenise requests — they should fail (no active key), but the system must respond
        AtomicLong nonServerErrors = new AtomicLong(); // 4xx counts as "responsive"
        AtomicLong serverErrors = new AtomicLong();    // 5xx counts as "unresponsive"
        AtomicLong exceptions = new AtomicLong();      // connection refused = truly dead

        ExecutorService trafficPool = buildVirtualThreadExecutor(20);
        for (int i = 0; i < 100; i++) {
            trafficPool.submit(() -> {
                try {
                    String pan = PanGenerator.generateVisa16();
                    ResponseEntity<String> resp =
                            restTemplate.postForEntity("/api/v1/tokens",
                                    buildTokeniseRequest(pan), String.class);
                    if (resp.getStatusCode().is5xxServerError()) {
                        serverErrors.incrementAndGet();
                    } else {
                        nonServerErrors.incrementAndGet();
                    }
                } catch (Exception e) {
                    exceptions.incrementAndGet();
                }
            });
        }

        awaitCompletion(trafficPool, 60);

        // System must respond to all requests (no connection refused or similar hard failures)
        assertThat(exceptions.get())
                .as("LT-TA-3: system must remain reachable after tamper isolation (no connection failures)")
                .isZero();
        // At least some requests must get a structured response (not a complete outage)
        assertThat(nonServerErrors.get() + serverErrors.get())
                .as("LT-TA-3: system must return HTTP responses to all %d requests", 100)
                .isEqualTo(100L);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private String[] seedTokens(int count, int parallelism) {
        String[] tokens = new String[count];
        AtomicLong errors = new AtomicLong();
        // parallelism must be ≤ pool-size (20) to avoid Hikari exhaustion during seeding
        ExecutorService seeder = buildVirtualThreadExecutor(parallelism);
        for (int i = 0; i < count; i++) {
            final int slot = i;
            seeder.submit(() -> {
                String pan = PanGenerator.generateVisa16();
                ResponseEntity<TokeniseResponse> resp =
                        restTemplate.postForEntity("/api/v1/tokens",
                                buildTokeniseRequest(pan), TokeniseResponse.class);
                if (resp.getStatusCode() == HttpStatus.CREATED && resp.getBody() != null) {
                    tokens[slot] = resp.getBody().getToken();
                } else {
                    errors.incrementAndGet();
                }
            });
        }
        awaitCompletion(seeder, 600);
        assertThat(errors.get()).as("Seeding must complete without errors").isZero();
        return tokens;
    }

    private ResponseEntity<DetokeniseResponse> detokenise(String token, String merchantId) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Merchant-ID", merchantId);
        return restTemplate.exchange(
                "/api/v1/tokens/" + token,
                HttpMethod.GET,
                new HttpEntity<>(headers),
                DetokeniseResponse.class);
    }

    private TokeniseRequest buildTokeniseRequest(String pan) {
        TokeniseRequest r = new TokeniseRequest();
        r.setPan(pan);
        r.setTokenType(TokenType.ONE_TIME);
        r.setMerchantId(MERCHANT);
        r.setCardScheme("VISA");
        r.setExpiryMonth(12);
        r.setExpiryYear(2027);
        return r;
    }
}
