-- V4__create_indexes.sql
--
-- Performance indexes for all hot-path queries.
-- Each index comment explains which query it serves.

-- Detokenisation hot path: look up token_vault by token value
CREATE UNIQUE INDEX idx_token_vault_token
    ON token_vault(token);

-- Deterministic de-dup: "does this PAN already have an active RECURRING token for this merchant?"
-- Partial index on RECURRING rows only — keeps the index small
CREATE INDEX idx_token_vault_pan_hash_recurring
    ON token_vault(pan_hash, merchant_id)
    WHERE token_type = 'RECURRING';

-- Key rotation batch: "find all active tokens that still use this key version"
-- Partial index on active tokens only — retired tokens are excluded from rotation batches
CREATE INDEX idx_token_vault_key_version_active
    ON token_vault(key_version_id)
    WHERE is_active = TRUE;

-- Merchant scoping queries (detokenisation authorization check)
CREATE INDEX idx_token_vault_merchant
    ON token_vault(merchant_id);

-- Audit log queries: look up events for a specific token (investigation / compliance)
CREATE INDEX idx_audit_log_token_id
    ON token_audit_log(token_id);

-- Audit log queries: time-range scans (PCI audit trail, retention job)
CREATE INDEX idx_audit_log_created_at
    ON token_audit_log(created_at);

-- Key version lookups: enforce at most one ACTIVE key at any point in time.
-- This unique partial index makes concurrent activation impossible at the DB level.
CREATE UNIQUE INDEX idx_key_versions_single_active
    ON key_versions(status)
    WHERE status = 'ACTIVE';
