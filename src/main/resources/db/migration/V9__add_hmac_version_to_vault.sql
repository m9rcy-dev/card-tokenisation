-- V9__add_hmac_version_to_vault.sql
--
-- Records which HMAC key version produced each token's pan_hash.
-- Required by PanHashBatchProcessor to re-hash tokens during HMAC rotation.
-- Nullable initially — HmacKeyBootstrapService backfills existing rows on first boot.

ALTER TABLE token_vault
    ADD COLUMN hmac_key_version_id UUID REFERENCES key_versions(id);

-- Index for batch query: find active vault rows still on the rotating HMAC version
CREATE INDEX idx_token_vault_hmac_version_active
    ON token_vault(hmac_key_version_id) WHERE is_active = TRUE;
