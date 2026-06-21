-- encrypting_kek_id is no longer needed: HMAC secrets are now protected
-- directly by AWS KMS CMK (purpose=hmac-key encryption context), not wrapped
-- under an application KEK. All existing HMAC rows have been dropped and
-- re-seeded via the new KMS-direct path (AwsKeySeeder / LocalDevHmacKeySeeder).
ALTER TABLE key_versions DROP COLUMN IF EXISTS encrypting_kek_id;
