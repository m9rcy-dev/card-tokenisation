package com.yourorg.tokenisation.api.response;

import lombok.Builder;
import lombok.Getter;

import java.util.UUID;

/**
 * Response body for {@code GET /api/v1/admin/keys/active}.
 *
 * <p>Exposes the active key version UUID so that admin tooling and smoke tests
 * can reference the correct key when initiating an emergency rotation.
 */
@Getter
@Builder
public class ActiveKeyResponse {

    /**
     * The UUID of the currently active key version.
     *
     * <p>Pass this value as {@code compromisedVersionId} in a COMPROMISE rotation request.
     */
    private final UUID activeVersionId;
}
