-- V3__create_audit_log.sql
--
-- Append-only audit log for all tokenisation, detokenisation, and key rotation events.
-- Immutability is enforced at the DB role level:
--
--   GRANT INSERT, SELECT ON token_audit_log TO tokenisation_app;
--   REVOKE UPDATE, DELETE ON token_audit_log FROM tokenisation_app;
--
-- The application role must NEVER be granted UPDATE or DELETE on this table.
-- PAN must NEVER appear in any column of this table — use token_id or redacted hints only.

CREATE TABLE token_audit_log (
    id               BIGSERIAL     PRIMARY KEY,
    event_type       VARCHAR(50)   NOT NULL,           -- TOKENISE | DETOKENISE | KEY_ROTATION_STARTED | etc.
    token_id         UUID,                             -- NULL for key-level events (rotation, tamper)
    key_version_id   UUID,
    actor_id         VARCHAR(100),                     -- service or user identity from JWT
    actor_ip         INET,
    merchant_id      VARCHAR(100),
    outcome          VARCHAR(10)   NOT NULL,           -- SUCCESS | FAILURE
    failure_reason   VARCHAR(200),                     -- human-readable reason — NEVER include PAN
    metadata         JSONB,                            -- structured extras (e.g. rotation batch stats)
    created_at       TIMESTAMPTZ   NOT NULL DEFAULT now()
    -- No UPDATE or DELETE — enforced by DB role grants (see PP-1 in progress.md)
);
