package com.yourorg.tokenisation.api;

import com.yourorg.tokenisation.config.DetokenisationProperties;
import com.yourorg.tokenisation.config.SecurityConfig;
import com.yourorg.tokenisation.monitoring.MetricsCollector;
import com.yourorg.tokenisation.rotation.KeyRotationService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Unit tests for {@link AdminKeyController}.
 *
 * <p>Tests verify:
 * <ul>
 *   <li>GET /admin/keys/active — 200 with {@code activeVersionId}
 *   <li>GET /admin/keys/active — 500 when no active key exists
 *   <li>POST /admin/keys/rotate — 400 when body contains an unparseable UUID
 *   <li>POST /admin/keys/rotate — 400 when service rejects an unknown {@code compromisedVersionId}
 * </ul>
 *
 * <p>{@link KeyRotationService} is mocked — no DB or KMS interaction.
 */
@WebMvcTest(AdminKeyController.class)
@Import(SecurityConfig.class)
class AdminKeyControllerTest {

    private static final UUID ACTIVE_KEY_ID = UUID.fromString("aaaaaaaa-0000-0000-0000-000000000001");

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private KeyRotationService keyRotationService;

    @MockBean
    private DetokenisationProperties detokenisationProperties;

    @MockBean
    private MetricsCollector metricsCollector;

    // ── GET /api/v1/admin/keys/active ─────────────────────────────────────────

    @Test
    void getActive_activeKeyExists_returns200WithVersionId() throws Exception {
        when(keyRotationService.getActiveKeyVersionId()).thenReturn(ACTIVE_KEY_ID);

        mockMvc.perform(get("/api/v1/admin/keys/active"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.activeVersionId").value(ACTIVE_KEY_ID.toString()));
    }

    @Test
    void getActive_noActiveKeyInRing_returns500() throws Exception {
        when(keyRotationService.getActiveKeyVersionId())
                .thenThrow(new IllegalStateException("No ACTIVE key version found"));

        mockMvc.perform(get("/api/v1/admin/keys/active"))
                .andExpect(status().isInternalServerError());
    }

    // ── POST /api/v1/admin/keys/rotate — exception handler coverage ───────────

    @Test
    void rotate_invalidUuidInBody_returns400() throws Exception {
        mockMvc.perform(post("/api/v1/admin/keys/rotate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "reason": "COMPROMISE",
                                  "compromisedVersionId": "not-a-uuid"
                                }
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.title").value("Invalid request body"));
    }

    @Test
    void rotate_unknownCompromisedVersionId_returns400() throws Exception {
        UUID unknownId = UUID.randomUUID();
        doThrow(new IllegalArgumentException("Key version not found: " + unknownId))
                .when(keyRotationService).initiateEmergencyRotation(unknownId, "emergency-key");

        mockMvc.perform(post("/api/v1/admin/keys/rotate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "reason": "COMPROMISE",
                                  "compromisedVersionId": "%s",
                                  "newKeyAlias": "emergency-key"
                                }
                                """.formatted(unknownId)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.title").value("Invalid argument"));
    }
}
