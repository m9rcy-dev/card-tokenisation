-- V5__simplify_token_vault.sql
--
-- Removes token_type and merchant_id from token_vault (single-tenant vault,
-- always-deterministic de-duplication). Removes merchant_id from token_audit_log.
-- Replaces the RECURRING partial index with a unique active-token-per-PAN guarantee.

-- Remove token_type
ALTER TABLE token_vault DROP CONSTRAINT IF EXISTS chk_token_vault_token_type;
ALTER TABLE token_vault DROP COLUMN IF EXISTS token_type;

-- Remove merchant_id from token_vault
DROP INDEX IF EXISTS idx_token_vault_merchant;
DROP INDEX IF EXISTS idx_token_vault_pan_hash_recurring;
ALTER TABLE token_vault DROP COLUMN IF EXISTS merchant_id;

-- Remove merchant_id from audit log
ALTER TABLE token_audit_log DROP COLUMN IF EXISTS merchant_id;

-- One active token per PAN — enforced at DB level
CREATE UNIQUE INDEX idx_token_vault_pan_hash_active
    ON token_vault(pan_hash) WHERE is_active = TRUE;
