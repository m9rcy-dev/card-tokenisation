package com.yourorg.tokenisation.api.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

/**
 * Request body for {@code POST /api/v1/admin/hmac-keys/rotate}.
 *
 * <p>Initiates a scheduled HMAC key rotation: the current ACTIVE HMAC version transitions
 * to ROTATING and a new ACTIVE version is created immediately.  Background re-hashing of
 * vault records from the old to the new version is driven by {@code HmacRotationJob}.
 */
@Getter
@Setter
public class RotateHmacKeyRequest {

    /**
     * Human-readable alias for the new HMAC key version (e.g. {@code "hmac-key-2027"}).
     * Stored in {@code key_versions.key_alias} for audit trail and operational visibility.
     * Must not be blank and must be 100 characters or fewer.
     */
    @NotBlank(message = "newKeyAlias must not be blank")
    @Size(max = 100, message = "newKeyAlias must be 100 characters or fewer")
    private String newKeyAlias;
}
