-- V6__setup_db_roles.sql
--
-- Creates the tokenisation_app role and pins its privileges to the minimum
-- required for normal application operation.
--
-- Privilege matrix:
--
--   Table               SELECT   INSERT   UPDATE   DELETE
--   key_versions          YES      YES      YES      NO
--   token_vault           YES      YES      YES      YES
--   token_audit_log       YES      YES      NO       NO   ← append-only
--
-- The token_audit_log restriction is the most critical: once an audit event
-- is written it must not be modified or deleted — not even by the application.
-- This provides an independent integrity guarantee at the database layer that
-- complements the HMAC checksums on key_versions rows.
--
-- Sequences
--   token_audit_log_id_seq   USAGE, SELECT
--   token_vault_record_version (internal JPA @Version — no seq)
--
-- In production the application connects as tokenisation_app.
-- In development and CI the container superuser runs migrations; the role
-- grants take effect as soon as tokenisation_app is used as the connection user.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tokenisation_app') THEN
        -- Password intentionally omitted from source control.
        -- Set the password out-of-band after deployment:
        --   ALTER ROLE tokenisation_app PASSWORD '<strong-random-password>';
        -- For local development use: make start-postgres (password set via POSTGRES_PASSWORD env var)
        CREATE ROLE tokenisation_app LOGIN;
    END IF;
END
$$;

-- key_versions: full read/write for key ring initialisation and status transitions.
-- DELETE is never issued — retired key versions are kept for historical DEK unwrapping.
GRANT SELECT, INSERT, UPDATE ON key_versions TO tokenisation_app;

-- token_vault: full DML — tokenisation (INSERT), detokenisation (SELECT),
-- rotation re-encryption (UPDATE), token deactivation (UPDATE is_active).
GRANT SELECT, INSERT, UPDATE, DELETE ON token_vault TO tokenisation_app;

-- token_audit_log: append-only.
-- UPDATE and DELETE are explicitly revoked as defence-in-depth even though
-- the role has never been granted these privileges.
GRANT SELECT, INSERT ON token_audit_log TO tokenisation_app;
REVOKE UPDATE, DELETE ON token_audit_log FROM tokenisation_app;

-- Sequences
GRANT USAGE, SELECT ON SEQUENCE token_audit_log_id_seq TO tokenisation_app;
