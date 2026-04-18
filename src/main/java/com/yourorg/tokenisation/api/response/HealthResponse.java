package com.yourorg.tokenisation.api.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Getter;

import java.time.Instant;
import java.util.Map;

/**
 * Response body for {@code GET /api/v1/health}.
 *
 * <p>The overall {@link #status} is {@code "UP"} when all sub-checks pass,
 * or {@code "DEGRADED"} when one or more checks fail. The HTTP response
 * status is 200 for {@code "UP"} and 503 for {@code "DEGRADED"}.
 *
 * <p>Example response:
 * <pre>{@code
 * {
 *   "status": "UP",
 *   "checks": {
 *     "database": "UP",
 *     "keyRing": "UP"
 *   },
 *   "timestamp": "2026-04-17T00:00:00Z"
 * }
 * }</pre>
 */
@Getter
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class HealthResponse {

    /**
     * Overall health status: {@code "UP"} if all checks pass; {@code "DEGRADED"} otherwise.
     */
    private final String status;

    /**
     * Individual component check results, keyed by component name.
     *
     * <p>Each value is {@code "UP"} or {@code "DOWN"}.
     */
    private final Map<String, String> checks;

    /**
     * Wall-clock timestamp when this health check was performed.
     */
    private final Instant timestamp;

    /**
     * Returns {@code true} if this response represents a fully healthy system.
     *
     * @return {@code true} when {@code status} is {@code "UP"}
     */
    public boolean isHealthy() {
        return "UP".equals(status);
    }
}
