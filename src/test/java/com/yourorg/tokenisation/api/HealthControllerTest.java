package com.yourorg.tokenisation.api;

import com.yourorg.tokenisation.api.response.HealthResponse;
import com.yourorg.tokenisation.config.DetokenisationProperties;
import com.yourorg.tokenisation.config.SecurityConfig;
import com.yourorg.tokenisation.monitoring.HealthService;
import com.yourorg.tokenisation.monitoring.MetricsCollector;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.Map;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Unit tests for {@link HealthController}.
 *
 * <p>Tests verify the HTTP response status and response body shape for both healthy
 * and degraded scenarios. {@link HealthService} is mocked — the actual health checks
 * (DB query, key ring lookup) are not performed.
 */
@WebMvcTest(HealthController.class)
@Import(SecurityConfig.class)
class HealthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private DetokenisationProperties detokenisationProperties;

    @MockBean
    private MetricsCollector metricsCollector;

    @MockBean
    private HealthService healthService;

    @Test
    void health_allChecksPass_returns200WithStatusUp() throws Exception {
        when(healthService.check()).thenReturn(HealthResponse.builder()
                .status("UP")
                .checks(Map.of("database", "UP", "keyRing", "UP"))
                .timestamp(Instant.now())
                .build());

        mockMvc.perform(get("/api/v1/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.checks.database").value("UP"))
                .andExpect(jsonPath("$.checks.keyRing").value("UP"))
                .andExpect(jsonPath("$.timestamp").exists());
    }

    @Test
    void health_databaseDown_returns503WithStatusDegraded() throws Exception {
        when(healthService.check()).thenReturn(HealthResponse.builder()
                .status("DEGRADED")
                .checks(Map.of("database", "DOWN", "keyRing", "UP"))
                .timestamp(Instant.now())
                .build());

        mockMvc.perform(get("/api/v1/health"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.status").value("DEGRADED"))
                .andExpect(jsonPath("$.checks.database").value("DOWN"));
    }

    @Test
    void health_keyRingDown_returns503WithStatusDegraded() throws Exception {
        when(healthService.check()).thenReturn(HealthResponse.builder()
                .status("DEGRADED")
                .checks(Map.of("database", "UP", "keyRing", "DOWN"))
                .timestamp(Instant.now())
                .build());

        mockMvc.perform(get("/api/v1/health"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.status").value("DEGRADED"))
                .andExpect(jsonPath("$.checks.keyRing").value("DOWN"));
    }

    @Test
    void health_allChecksDegraded_returns503() throws Exception {
        when(healthService.check()).thenReturn(HealthResponse.builder()
                .status("DEGRADED")
                .checks(Map.of("database", "DOWN", "keyRing", "DOWN"))
                .timestamp(Instant.now())
                .build());

        mockMvc.perform(get("/api/v1/health"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.status").value("DEGRADED"));
    }

    @Test
    void health_responseContainsTimestamp() throws Exception {
        when(healthService.check()).thenReturn(HealthResponse.builder()
                .status("UP")
                .checks(Map.of("database", "UP", "keyRing", "UP"))
                .timestamp(Instant.parse("2026-04-17T12:00:00Z"))
                .build());

        mockMvc.perform(get("/api/v1/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.timestamp").value("2026-04-17T12:00:00Z"));
    }
}
