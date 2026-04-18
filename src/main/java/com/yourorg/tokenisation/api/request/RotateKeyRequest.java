package com.yourorg.tokenisation.api.request;

import com.yourorg.tokenisation.domain.RotationReason;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

import java.util.UUID;

/**
 * Request body for the admin key rotation endpoint: {@code POST /api/v1/admin/keys/rotate}.
 *
 * <p>Two rotation flows are supported, determined by {@link #reason}:
 * <ul>
 *   <li>{@link RotationReason#SCHEDULED} or {@link RotationReason#MANUAL} — normal rotation;
 *       {@link #newKeyAlias} is required; {@link #compromisedVersionId} must be null.
 *   <li>{@link RotationReason#COMPROMISE} — emergency rotation;
 *       {@link #compromisedVersionId} is required and must identify an existing key version.
 * </ul>
 */
@Getter
@Setter
public class RotateKeyRequest {

    /**
     * The reason for initiating rotation. Determines which rotation flow is used.
     * Must not be null.
     */
    @NotNull(message = "reason must not be null")
    private RotationReason reason;

    /**
     * Human-readable alias for the new key version (e.g. {@code "tokenisation-key-2026"}).
     * Required for scheduled and manual rotation. For compromise rotation, if omitted,
     * a default alias is generated.
     */
    @Size(max = 100, message = "newKeyAlias must be 100 characters or fewer")
    private String newKeyAlias;

    /**
     * The UUID of the key version to mark as compromised.
     * Required when {@link #reason} is {@link RotationReason#COMPROMISE}.
     * Must be null for non-compromise rotations.
     */
    private UUID compromisedVersionId;
}
