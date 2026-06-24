package com.yourorg.tokenisation.monitoring;

import com.yourorg.tokenisation.api.response.HealthResponse;
import com.yourorg.tokenisation.crypto.InMemoryDekKeyRing;
import com.yourorg.tokenisation.repository.KeyVersionRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Performs liveness sub-checks and assembles a {@link HealthResponse}.
 *
 * <h3>Checks performed</h3>
 * <ul>
 *   <li><strong>database</strong> — executes {@code SELECT 1} via {@link JdbcTemplate}.
 *       A failed query (connection refused, timeout, etc.) marks this check as {@code "DOWN"}.
 *   <li><strong>keyRing</strong> — verifies that an {@code ACTIVE} key version exists in
 *       {@code key_versions}. An absent active key means no new tokenisation is possible.
 * </ul>
 *
 * <p>The overall status is {@code "UP"} only when all checks pass. Any single failure
 * yields {@code "DEGRADED"}.
 */
@Service
@Slf4j
public class HealthService {

    private static final String STATUS_UP = "UP";
    private static final String STATUS_DOWN = "DOWN";
    private static final String STATUS_DEGRADED = "DEGRADED";

    private final JdbcTemplate jdbcTemplate;
    private final KeyVersionRepository keyVersionRepository;
    private final InMemoryDekKeyRing dekRing;

    public HealthService(JdbcTemplate jdbcTemplate,
                         KeyVersionRepository keyVersionRepository,
                         InMemoryDekKeyRing dekRing) {
        this.jdbcTemplate = jdbcTemplate;
        this.keyVersionRepository = keyVersionRepository;
        this.dekRing = dekRing;
    }

    /**
     * Runs all sub-checks and returns the aggregated health response.
     *
     * @return a {@link HealthResponse} with individual check results and overall status
     */
    public HealthResponse check() {
        Map<String, String> checks = new LinkedHashMap<>();
        checks.put("database", checkDatabase());
        checks.put("keyRing", checkKeyRing());

        boolean allUp = checks.values().stream().allMatch(STATUS_UP::equals);
        String overallStatus = allUp ? STATUS_UP : STATUS_DEGRADED;

        return HealthResponse.builder()
                .status(overallStatus)
                .checks(checks)
                .timestamp(Instant.now())
                .build();
    }

    private String checkDatabase() {
        try {
            jdbcTemplate.queryForObject("SELECT 1", Integer.class);
            return STATUS_UP;
        } catch (Exception e) {
            log.error("Database health check failed: {}", e.getMessage());
            return STATUS_DOWN;
        }
    }

    private String checkKeyRing() {
        try {
            if (keyVersionRepository.findActiveDek().isEmpty()) {
                log.error("Key ring health check failed: no ACTIVE DEK version in database");
                return STATUS_DOWN;
            }
            dekRing.getActive(); // throws IllegalStateException if ring is not initialised
            return STATUS_UP;
        } catch (Exception e) {
            log.error("Key ring health check failed: {}", e.getMessage());
            return STATUS_DOWN;
        }
    }
}
