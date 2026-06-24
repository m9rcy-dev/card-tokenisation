package com.yourorg.tokenisation.api;

import com.yourorg.tokenisation.api.request.RotateHmacKeyRequest;
import com.yourorg.tokenisation.api.request.RotateKeyRequest;
import com.yourorg.tokenisation.api.response.ActiveKeyResponse;
import com.yourorg.tokenisation.domain.RotationReason;
import com.yourorg.tokenisation.rotation.HmacRotationService;
import com.yourorg.tokenisation.rotation.KeyRotationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
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
    private final HmacRotationService hmacRotationService;

    public AdminKeyController(KeyRotationService keyRotationService,
                               HmacRotationService hmacRotationService) {
        this.keyRotationService = keyRotationService;
        this.hmacRotationService = hmacRotationService;
    }

    /**
     * Returns the UUID of the currently active key version.
     *
     * <p>Intended for admin tooling and smoke tests that need to reference the active key
     * (e.g. when constructing a COMPROMISE rotation request).
     *
     * @return the active key version UUID
     */
    @GetMapping("/active")
    @Operation(summary = "Get active key version",
            description = "Returns the UUID of the currently active KEK version. "
                    + "**Admin access only — must be protected in production.**")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Active key version returned"),
            @ApiResponse(responseCode = "500", description = "No active key version found")
    })
    public ActiveKeyResponse getActive() {
        return ActiveKeyResponse.builder()
                .activeVersionId(keyRotationService.getActiveKeyVersionId())
                .build();
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

    /**
     * Initiates a scheduled HMAC key rotation.
     *
     * <p>The current ACTIVE HMAC version transitions to ROTATING and a new ACTIVE version is
     * created immediately.  Background re-hashing of vault records is driven by
     * {@code HmacRotationJob} (default schedule: 02:00 UTC daily).
     *
     * @param request the rotation request specifying the new key alias
     */
    @PostMapping("/hmac-keys/rotate")
    @ResponseStatus(HttpStatus.ACCEPTED)
    @Operation(summary = "Initiate HMAC key rotation",
            description = "Rotates the HMAC signing secret used for PAN hash de-duplication. "
                    + "Vault records are re-hashed in a background batch job. "
                    + "**Admin access only — must be protected in production.**")
    @ApiResponses({
            @ApiResponse(responseCode = "202", description = "HMAC rotation accepted; re-hashing in progress"),
            @ApiResponse(responseCode = "400", description = "newKeyAlias is missing or blank")
    })
    public void rotateHmacKey(@Valid @RequestBody RotateHmacKeyRequest request) {
        log.warn("HMAC key rotation requested: alias=[{}]", request.getNewKeyAlias());
        hmacRotationService.initiateRotation(request.getNewKeyAlias());
    }
}
