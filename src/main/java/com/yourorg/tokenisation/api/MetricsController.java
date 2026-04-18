package com.yourorg.tokenisation.api;

import com.yourorg.tokenisation.api.response.MetricsResponse;
import com.yourorg.tokenisation.monitoring.MetricsCollector;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;

/**
 * Application metrics endpoint for the card tokenisation service.
 *
 * <p>Returns a lightweight snapshot of in-process counters since the last restart.
 * Intended for operational dashboards and alerting; not a replacement for a full
 * APM solution.
 *
 * <p>All counters are reset to zero on restart — no persistence is performed.
 */
@RestController
@RequestMapping("/api/v1/metrics")
@Tag(name = "Monitoring", description = "Health and metrics endpoints")
public class MetricsController {

    private final MetricsCollector metricsCollector;

    /**
     * Constructs the metrics controller.
     *
     * @param metricsCollector the shared counter store; must not be null
     */
    public MetricsController(MetricsCollector metricsCollector) {
        this.metricsCollector = metricsCollector;
    }

    /**
     * Returns a point-in-time snapshot of application metrics.
     *
     * <p>Always returns HTTP 200. The counters reflect totals since the last application restart.
     *
     * @return the current metrics snapshot
     */
    @GetMapping
    @Operation(
            summary = "Application metrics snapshot",
            description = "Returns uptime, tokenise/detokenise request counts, "
                    + "and server error count since the last restart."
    )
    @ApiResponse(responseCode = "200", description = "Metrics snapshot returned successfully")
    public MetricsResponse metrics() {
        return MetricsResponse.builder()
                .uptimeSeconds(metricsCollector.getUptimeSeconds())
                .tokeniseRequests(metricsCollector.getTokeniseRequests())
                .detokeniseRequests(metricsCollector.getDetokeniseRequests())
                .serverErrorCount(metricsCollector.getServerErrorCount())
                .timestamp(Instant.now())
                .build();
    }
}
