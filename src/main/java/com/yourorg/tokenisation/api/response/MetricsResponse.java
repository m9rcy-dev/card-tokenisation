package com.yourorg.tokenisation.api.response;

import lombok.Builder;
import lombok.Getter;

import java.time.Instant;

/**
 * Response body for {@code GET /api/v1/metrics}.
 *
 * <p>Contains application-level statistics aggregated since the last restart.
 * All counters are non-negative; they reset to zero on restart.
 *
 * <p>Example response:
 * <pre>{@code
 * {
 *   "uptimeSeconds": 3601,
 *   "tokeniseRequests": 12483,
 *   "detokeniseRequests": 47291,
 *   "serverErrorCount": 3,
 *   "timestamp": "2026-04-17T00:00:00Z"
 * }
 * }</pre>
 */
@Getter
@Builder
public class MetricsResponse {

    /**
     * Seconds elapsed since the application started.
     */
    private final long uptimeSeconds;

    /**
     * Total number of successful tokenisations ({@code POST /api/v1/tokens} → 2xx)
     * since the last restart.
     */
    private final long tokeniseRequests;

    /**
     * Total number of successful detokenisations ({@code GET /api/v1/tokens/{token}} → 200)
     * since the last restart.
     */
    private final long detokeniseRequests;

    /**
     * Total number of HTTP 5xx server error responses across all endpoints
     * since the last restart. Client errors (4xx) are not included.
     */
    private final long serverErrorCount;

    /**
     * Wall-clock timestamp when this snapshot was taken.
     */
    private final Instant timestamp;
}
