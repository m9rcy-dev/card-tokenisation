-- V11__defer_hmac_version_index.sql
--
-- Drop idx_token_vault_hmac_version_active (added prematurely in V9).
--
-- PostgreSQL must maintain ALL B-tree indexes on a row whenever that row is updated,
-- even when the indexed column did not change.  During KEK rotation the batch processor
-- updates 'key_version_id' and 'encrypted_dek' for every active vault row — a change that
-- makes HOT (heap-only tuple) updates impossible for those rows.  This forces maintenance of
-- idx_token_vault_hmac_version_active on every rotation UPDATE, adding ~20% to WAL write
-- volume and degrading live-traffic throughput during rotation by roughly 25%.
--
-- The index is re-created by a DBA immediately before the first HMAC rotation is triggered
-- (when the performance trade-off is justified by the batch query benefit):
--
--   CREATE INDEX CONCURRENTLY idx_token_vault_hmac_version_active
--       ON token_vault(hmac_key_version_id) WHERE is_active = TRUE;
--
-- See docs/key-rotation-runbook.md §4 for the full pre-rotation checklist.

DROP INDEX IF EXISTS idx_token_vault_hmac_version_active;
