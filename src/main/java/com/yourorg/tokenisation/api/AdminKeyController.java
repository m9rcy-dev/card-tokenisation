package com.yourorg.tokenisation.api;

import com.yourorg.tokenisation.api.request.RotateKeyRequest;
import com.yourorg.tokenisation.domain.RotationReason;
import com.yourorg.tokenisation.rotation.KeyRotationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Admin REST controller for key rotation operations.
 *
 * <p>Exposes {@code POST /api/v1/admin/keys/rotate} for initiating both scheduled and
 * emergency key rotations.
 *
 * <p>In production this endpoint must be protected by strong authentication
 * (e.g. mutual TLS or an internal admin JWT) — it is not accessible via the public API gateway.
 * Spring Security configuration for admin endpoints is added as part of Pre-Production Hardening.
 *
 * <h3>Rotation flows</h3>
 * <ul>
 *   <li>{@link RotationReason#SCHEDULED} or {@link RotationReason#MANUAL} — triggers
 *       {@link KeyRotationService#initiateScheduledRotation}. The old key transitions to
 *       {@code ROTATING}; a new {@code ACTIVE} key is created immediately.
 *   <li>{@link RotationReason#COMPROMISE} — triggers
 *       {@link KeyRotationService#initiateEmergencyRotation}. The specified key is blocked
 *       for detokenisation immediately. A security alert event is published.
 * </ul>
 *
 * <p>Returns HTTP 202 (Accepted) on success — the batch re-encryption continues
 * asynchronously in the background via {@link com.yourorg.tokenisation.rotation.RotationJob}.
 */
@RestController
@RequestMapping("/api/v1/admin/keys")
@Tag(name = "Admin — Key Management", description = "Key rotation operations (admin-only)")
@Slf4j
public class AdminKeyController {

    private final KeyRotationService keyRotationService;

    /**
     * Constructs the admin key controller.
     *
     * @param keyRotationService the rotation orchestrator; must not be null
     */
    public AdminKeyController(KeyRotationService keyRotationService) {
        this.keyRotationService = keyRotationService;
    }

    /**
     * Initiates a key rotation.
     *
     * <p>For compromise rotations, the compromised key is blocked synchronously before
     * this method returns. The batch re-encryption runs asynchronously.
     *
     * @param request the rotation request specifying reason, alias, and optional compromised key ID
     * @throws ResponseStatusException HTTP 400 if the request is invalid (missing required fields)
     */
    @PostMapping("/rotate")
    @ResponseStatus(HttpStatus.ACCEPTED)
    @Operation(summary = "Initiate key rotation",
            description = "Triggers a scheduled, manual, or emergency key rotation. "
                    + "The old key is blocked synchronously; batch re-encryption runs asynchronously. "
                    + "**This endpoint must be protected in production — admin access only.**")
    @ApiResponses({
            @ApiResponse(responseCode = "202", description = "Rotation accepted; re-encryption in progress"),
            @ApiResponse(responseCode = "400", description = "Missing required fields for the rotation type")
    })
    public void rotate(@Valid @RequestBody RotateKeyRequest request) {
        log.warn("Key rotation requested: reason=[{}], alias=[{}], compromisedVersionId=[{}]",
                request.getReason(), request.getNewKeyAlias(), request.getCompromisedVersionId());

        if (request.getReason() == RotationReason.COMPROMISE) {
            if (request.getCompromisedVersionId() == null) {
                throw new ResponseStatusException(
                        HttpStatus.BAD_REQUEST,
                        "compromisedVersionId is required for COMPROMISE rotation");
            }
            String alias = request.getNewKeyAlias() != null
                    ? request.getNewKeyAlias()
                    : "emergency-rotation-" + System.currentTimeMillis();
            keyRotationService.initiateEmergencyRotation(request.getCompromisedVersionId(), alias);
        } else {
            if (request.getNewKeyAlias() == null || request.getNewKeyAlias().isBlank()) {
                throw new ResponseStatusException(
                        HttpStatus.BAD_REQUEST,
                        "newKeyAlias is required for SCHEDULED and MANUAL rotation");
            }
            keyRotationService.initiateScheduledRotation(request.getNewKeyAlias(), request.getReason());
        }
    }
}
