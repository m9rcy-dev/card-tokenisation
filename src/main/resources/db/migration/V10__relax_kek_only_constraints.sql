-- V10__relax_kek_only_constraints.sql
--
-- V1 created kms_key_id, kms_provider, and encrypted_kek_blob as NOT NULL because the
-- table only held KEK rows at that time. V8 unified HMAC rows into the same table; HMAC
-- rows deliberately leave those columns NULL (they use encrypted_secret and encrypting_kek_id
-- instead). This migration removes the NOT NULL constraints so HMAC rows can be inserted.

ALTER TABLE key_versions ALTER COLUMN kms_key_id       DROP NOT NULL;
ALTER TABLE key_versions ALTER COLUMN kms_provider     DROP NOT NULL;
ALTER TABLE key_versions ALTER COLUMN encrypted_kek_blob DROP NOT NULL;
