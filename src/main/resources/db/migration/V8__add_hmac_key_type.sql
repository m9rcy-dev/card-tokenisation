-- V8__add_hmac_key_type.sql
--
-- Unifies KEK and HMAC key versions into the key_versions table.
-- Adds key_type discriminator, encrypted_secret and encrypting_kek_id columns for HMAC rows.
-- Drops the checksum column (TamperDetector removed — DB-level access controls enforce integrity).
-- Replaces the single-ACTIVE partial index with a per-type uniqueness constraint.

-- Add type discriminator; all existing rows are KEK versions
ALTER TABLE key_versions
    ADD COLUMN key_type VARCHAR(10) NOT NULL DEFAULT 'KEK'
        CHECK (key_type IN ('KEK', 'HMAC'));

-- IV-prefix AES-GCM blob of the HMAC secret wrapped under the active KEK; NULL for KEK rows
ALTER TABLE key_versions
    ADD COLUMN encrypted_secret BYTEA;

-- Self-referential FK: which KEK encrypted this HMAC secret; NULL for KEK rows
ALTER TABLE key_versions
    ADD COLUMN encrypting_kek_id UUID REFERENCES key_versions(id);

-- Drop TamperDetector checksum column
ALTER TABLE key_versions
    DROP COLUMN IF EXISTS checksum;

-- Replace old single-ACTIVE partial index (allowed only one ACTIVE row across all types)
-- with a per-type uniqueness constraint (one ACTIVE KEK, one ACTIVE HMAC).
DROP INDEX IF EXISTS idx_key_versions_single_active;
CREATE UNIQUE INDEX idx_key_versions_single_active_per_type
    ON key_versions(key_type) WHERE status = 'ACTIVE';

-- Index for fast HMAC-type startup query
CREATE INDEX idx_key_versions_hmac_status
    ON key_versions(key_type, status) WHERE key_type = 'HMAC';
