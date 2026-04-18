package com.yourorg.tokenisation.api;

import com.yourorg.tokenisation.api.response.HealthResponse;
import com.yourorg.tokenisation.monitoring.HealthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Liveness endpoint for the card tokenisation service.
 *
 * <p>Returns a health summary that checks the database connection and key ring status.
 * Suitable for use as a load-balancer health probe or a Kubernetes liveness/readiness check.
 *
 * <p>Callers should treat HTTP 503 as a signal to stop routing traffic to this instance.
 */
@RestController
@RequestMapping("/api/v1/health")
@Tag(name = "Monitoring", description = "Health and metrics endpoints")
public class HealthController {

    private final HealthService healthService;

    /**
     * Constructs the health controller.
     *
     * @param healthService the service that performs the sub-checks; must not be null
     */
    public HealthController(HealthService healthService) {
        this.healthService = healthService;
    }

    /**
     * Returns the current health status of the service.
     *
     * <p>HTTP 200 is returned when all sub-checks pass ({@code status: "UP"}).
     * HTTP 503 is returned when any sub-check fails ({@code status: "DEGRADED"}).
     *
     * @return the health response with per-component check results
     */
    @GetMapping
    @Operation(
            summary = "Service health check",
            description = "Returns UP (200) when the database and key ring are reachable, "
                    + "DEGRADED (503) when any check fails."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "All components healthy"),
            @ApiResponse(responseCode = "503", description = "One or more components degraded")
    })
    public ResponseEntity<HealthResponse> health() {
        HealthResponse response = healthService.check();
        HttpStatus status = response.isHealthy() ? HttpStatus.OK : HttpStatus.SERVICE_UNAVAILABLE;
        return ResponseEntity.status(status).body(response);
    }
}
