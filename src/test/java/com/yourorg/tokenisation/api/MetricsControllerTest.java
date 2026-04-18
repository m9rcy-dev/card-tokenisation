package com.yourorg.tokenisation.api;

import com.yourorg.tokenisation.config.DetokenisationProperties;
import com.yourorg.tokenisation.config.SecurityConfig;
import com.yourorg.tokenisation.monitoring.MetricsCollector;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Unit tests for {@link MetricsController}.
 *
 * <p>Tests verify the HTTP response status and that the response body contains
 * the expected counter values from the mocked {@link MetricsCollector}.
 */
@WebMvcTest(MetricsController.class)
@Import(SecurityConfig.class)
class MetricsControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private DetokenisationProperties detokenisationProperties;

    @MockBean
    private MetricsCollector metricsCollector;

    @Test
    void metrics_returns200WithCorrectCounters() throws Exception {
        when(metricsCollector.getUptimeSeconds()).thenReturn(3600L);
        when(metricsCollector.getTokeniseRequests()).thenReturn(1234L);
        when(metricsCollector.getDetokeniseRequests()).thenReturn(5678L);
        when(metricsCollector.getServerErrorCount()).thenReturn(3L);

        mockMvc.perform(get("/api/v1/metrics"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.uptimeSeconds").value(3600))
                .andExpect(jsonPath("$.tokeniseRequests").value(1234))
                .andExpect(jsonPath("$.detokeniseRequests").value(5678))
                .andExpect(jsonPath("$.serverErrorCount").value(3))
                .andExpect(jsonPath("$.timestamp").exists());
    }

    @Test
    void metrics_zeroCounters_returns200WithZeros() throws Exception {
        when(metricsCollector.getUptimeSeconds()).thenReturn(0L);
        when(metricsCollector.getTokeniseRequests()).thenReturn(0L);
        when(metricsCollector.getDetokeniseRequests()).thenReturn(0L);
        when(metricsCollector.getServerErrorCount()).thenReturn(0L);

        mockMvc.perform(get("/api/v1/metrics"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tokeniseRequests").value(0))
                .andExpect(jsonPath("$.detokeniseRequests").value(0))
                .andExpect(jsonPath("$.serverErrorCount").value(0));
    }

    @Test
    void metrics_largeCounters_serializesCorrectly() throws Exception {
        when(metricsCollector.getUptimeSeconds()).thenReturn(86400L);
        when(metricsCollector.getTokeniseRequests()).thenReturn(1_000_000L);
        when(metricsCollector.getDetokeniseRequests()).thenReturn(5_000_000L);
        when(metricsCollector.getServerErrorCount()).thenReturn(0L);

        mockMvc.perform(get("/api/v1/metrics"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tokeniseRequests").value(1_000_000))
                .andExpect(jsonPath("$.detokeniseRequests").value(5_000_000))
                .andExpect(jsonPath("$.uptimeSeconds").value(86400));
    }
}
