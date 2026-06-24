-- =============================================================================
-- schema-init.sql
--
-- Consolidated DDL for the card-tokenisation-system database.
-- This is the final schema state equivalent to running all Flyway migrations
-- V1 through V14 in sequence.
--
-- Use this file when you need a single portable init script, for example:
--   - PostgreSQL initdb / Docker entrypoint (POSTGRES_INITDB_SCRIPTS)
--   - Manual provisioning of a new environment without Flyway
--   - Snapshot reference of the current schema
--
-- When using Flyway (make start, make run-localstack, CI), use the individual
-- migration files under db/migration/ instead — this file is not read by Flyway.
--
-- Tested against PostgreSQL 16.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Extensions
-- ---------------------------------------------------------------------------
-- gen_random_uuid() is available without an extension in PostgreSQL 13+.
-- pgcrypto is NOT required for this schema.

-- ---------------------------------------------------------------------------
-- Table: key_versions
--
-- Unified table for all key material metadata.
-- key_type = 'DEK' rows hold a shared Data Encryption Key generated and
--            protected by AWS KMS (via GenerateDataKey / Decrypt).
-- key_type = 'HMAC' rows hold an HMAC secret encrypted directly by AWS KMS CMK
--            (purpose=hmac-key encryption context).
--
-- DEK rows:  kms_key_id, kms_provider, encrypted_dek_blob populated
--            encrypted_secret NULL
-- HMAC rows: kms_key_id, kms_provider, encrypted_secret populated
--            encrypted_dek_blob NULL
--
-- Both row types populate kms_key_id and kms_provider — they both use the
-- same CMK, with distinct encryption contexts to prevent cross-use.
-- ---------------------------------------------------------------------------
CREATE TABLE key_versions (
    id                 UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    kms_key_id         VARCHAR(255),                    -- ARN or alias; populated for both DEK and HMAC rows
    kms_provider       VARCHAR(50),                     -- 'AWS_KMS' | 'LOCAL_DEV'; populated for both row types
    key_alias          VARCHAR(100)  NOT NULL,
    encrypted_dek_blob BYTEA,                           -- KMS-encrypted DEK blob (raw bytes from GenerateDataKey); NULL for HMAC rows
    key_type           VARCHAR(10)   NOT NULL DEFAULT 'DEK'
                           CHECK (key_type IN ('DEK', 'HMAC')),
    status             VARCHAR(20)   NOT NULL DEFAULT 'ACTIVE'
                           CHECK (status IN ('ACTIVE', 'ROTATING', 'RETIRED', 'COMPROMISED')),
    rotation_reason    VARCHAR(20)
                           CHECK (rotation_reason IS NULL
                               OR rotation_reason IN ('SCHEDULED', 'COMPROMISE', 'MANUAL')),
    activated_at       TIMESTAMPTZ   NOT NULL DEFAULT now(),
    retired_at         TIMESTAMPTZ,
    rotate_by          TIMESTAMPTZ   NOT NULL,
    created_by         VARCHAR(100)  NOT NULL,

    -- HMAC-only columns
    encrypted_secret   BYTEA                            -- KMS.Encrypt(hmac_bytes, ctx=hmac-key); NULL for DEK rows
);

-- One ACTIVE row per key_type — prevents two concurrent ACTIVE DEKs or two ACTIVE HMACs
CREATE UNIQUE INDEX idx_key_versions_single_active_per_type
    ON key_versions(key_type) WHERE status = 'ACTIVE';

-- HMAC startup query: load ACTIVE/ROTATING HMAC versions efficiently
CREATE INDEX idx_key_versions_hmac_status
    ON key_versions(key_type, status) WHERE key_type = 'HMAC';

-- ---------------------------------------------------------------------------
-- Table: token_vault
--
-- One row per issued token.  PAN is never stored in cleartext.
-- Encryption: PAN encrypted directly with the active shared DEK (AES-256-GCM).
-- No per-record DEK is stored — the shared DEK lives in InMemoryDekKeyRing,
-- keyed by key_version_id → key_versions.encrypted_dek_blob (KMS-protected).
-- pan_hash enables deterministic deduplication without storing the PAN.
-- ---------------------------------------------------------------------------
CREATE TABLE token_vault (
    token_id            UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    token               VARCHAR(36)   NOT NULL UNIQUE,  -- surrogate UUID token value
    encrypted_pan       BYTEA         NOT NULL,         -- AES-256-GCM ciphertext of PAN
    iv                  BYTEA         NOT NULL,         -- 12-byte GCM IV, unique per row (MUST be fresh per encrypt)
    auth_tag            BYTEA         NOT NULL,         -- 16-byte GCM authentication tag
    key_version_id      UUID          NOT NULL REFERENCES key_versions(id),
    pan_hash            VARCHAR(64)   NOT NULL,         -- HMAC-SHA256(pan, hmac_secret) for dedup
    hmac_key_version_id UUID          REFERENCES key_versions(id),  -- which HMAC version produced pan_hash
    last_four           VARCHAR(4)    NOT NULL,         -- last 4 digits of PAN; not sensitive
    card_scheme         VARCHAR(10),                    -- VISA | MC | AMEX | EFTPOS
    expiry_month        SMALLINT,
    expiry_year         SMALLINT,
    created_at          TIMESTAMPTZ   NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ,
    is_active           BOOLEAN       NOT NULL DEFAULT TRUE,
    record_version      INTEGER       NOT NULL DEFAULT 1,  -- optimistic locking for rotation updates

    CONSTRAINT chk_token_vault_iv_length
        CHECK (octet_length(iv) = 12),
    CONSTRAINT chk_token_vault_auth_tag_length
        CHECK (octet_length(auth_tag) = 16)
);

-- Detokenisation hot path
CREATE UNIQUE INDEX idx_token_vault_token
    ON token_vault(token);

-- Deduplication: one active token per PAN hash
CREATE UNIQUE INDEX idx_token_vault_pan_hash_active
    ON token_vault(pan_hash) WHERE is_active = TRUE;

-- DEK rotation batch: find active tokens still on the rotating key version
CREATE INDEX idx_token_vault_key_version_active
    ON token_vault(key_version_id) WHERE is_active = TRUE;

-- NOTE: idx_token_vault_hmac_version_active is intentionally omitted here.
-- Create it immediately before triggering an HMAC rotation (see §4 of key-rotation-runbook.md):
--
--   CREATE INDEX CONCURRENTLY idx_token_vault_hmac_version_active
--       ON token_vault(hmac_key_version_id) WHERE is_active = TRUE;
--
-- Keeping it absent avoids ~20% extra WAL write volume during DEK rotation batches
-- (every rotation UPDATE forces index maintenance even though hmac_key_version_id is unchanged).

-- ---------------------------------------------------------------------------
-- Table: token_audit_log
--
-- Append-only.  The application role (tokenisation_app) is granted only
-- SELECT and INSERT — UPDATE and DELETE are explicitly revoked.
-- PAN must NEVER appear in any column of this table.
-- ---------------------------------------------------------------------------
CREATE TABLE token_audit_log (
    id             BIGSERIAL     PRIMARY KEY,
    event_type     VARCHAR(50)   NOT NULL,    -- TOKENISE | DETOKENISE | KEY_ROTATION_STARTED | etc.
    token_id       UUID,                      -- NULL for key-level events (rotation, tamper)
    key_version_id UUID,
    actor_id       VARCHAR(100),              -- service or user identity
    actor_ip       VARCHAR(45),              -- IPv4 (15 chars) or IPv6 (45 chars)
    outcome        VARCHAR(10)   NOT NULL,    -- SUCCESS | FAILURE
    failure_reason VARCHAR(200),             -- human-readable; NEVER include PAN
    metadata       JSONB,                    -- structured extras (e.g. rotation batch stats)
    created_at     TIMESTAMPTZ   NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_log_token_id
    ON token_audit_log(token_id);

CREATE INDEX idx_audit_log_created_at
    ON token_audit_log(created_at);

-- ---------------------------------------------------------------------------
-- Role: tokenisation_app
--
-- Minimum privilege principle.
-- Password is set out-of-band after deployment:
--   ALTER ROLE tokenisation_app PASSWORD '<strong-random-password>';
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tokenisation_app') THEN
        CREATE ROLE tokenisation_app LOGIN;
    END IF;
END
$$;

-- key_versions: read/write for ring init and status transitions; no DELETE (rows are never purged)
GRANT SELECT, INSERT, UPDATE ON key_versions TO tokenisation_app;

-- token_vault: full DML (tokenise INSERT, detokenise SELECT, rotation UPDATE, deactivation UPDATE)
GRANT SELECT, INSERT, UPDATE, DELETE ON token_vault TO tokenisation_app;

-- token_audit_log: append-only — UPDATE and DELETE explicitly revoked
GRANT SELECT, INSERT ON token_audit_log TO tokenisation_app;
REVOKE UPDATE, DELETE ON token_audit_log FROM tokenisation_app;

GRANT USAGE, SELECT ON SEQUENCE token_audit_log_id_seq TO tokenisation_app;
