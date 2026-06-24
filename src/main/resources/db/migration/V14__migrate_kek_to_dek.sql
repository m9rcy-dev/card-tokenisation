-- Feature 07: 2-layer KMS-DEK architecture
-- Rename key_type 'KEK' → 'DEK', replace encrypted_kek_blob (TEXT) with encrypted_dek_blob (BYTEA),
-- and drop the per-record encrypted_dek column from token_vault.

-- 1. Rename existing KEK rows to DEK
UPDATE key_versions SET key_type = 'DEK' WHERE key_type = 'KEK';

-- 2. Update key_type check constraint
ALTER TABLE key_versions DROP CONSTRAINT IF EXISTS key_versions_key_type_check;
ALTER TABLE key_versions ADD CONSTRAINT key_versions_key_type_check
    CHECK (key_type IN ('DEK', 'HMAC'));

-- 3. Add BYTEA column for the KMS-encrypted DEK blob
ALTER TABLE key_versions ADD COLUMN encrypted_dek_blob BYTEA;

-- 4. Drop the old TEXT/Base64 encrypted_kek_blob column
ALTER TABLE key_versions DROP COLUMN IF EXISTS encrypted_kek_blob;

-- 5. Drop per-record DEK wrapper from token_vault
ALTER TABLE token_vault DROP COLUMN IF EXISTS encrypted_dek;

-- 6. Recreate the single-active-per-type unique index with updated key_type values
DROP INDEX IF EXISTS idx_key_versions_single_active_per_type;
CREATE UNIQUE INDEX idx_key_versions_single_active_per_type
    ON key_versions(key_type) WHERE status = 'ACTIVE';
