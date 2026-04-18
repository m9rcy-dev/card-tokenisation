-- V2__create_token_vault.sql
--
-- The token vault stores one row per issued token.
-- The PAN is never stored in clear — only AES-256-GCM ciphertext (encrypted_pan),
-- the per-record IV (iv), the GCM authentication tag (auth_tag), and the
-- KEK-wrapped DEK (encrypted_dek) used to encrypt this specific record.
--
-- pan_hash is HMAC-SHA256(PAN, hashingSecret) — enables deterministic RECURRING token
-- de-duplication without storing the PAN in any readable form.
--
-- record_version supports optimistic locking during key rotation re-encryption.

CREATE TABLE token_vault (
    token_id         UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    token            VARCHAR(36)   NOT NULL UNIQUE,    -- surrogate: UUID or Luhn-valid 16-digit
    encrypted_pan    BYTEA         NOT NULL,           -- AES-256-GCM ciphertext of PAN
    iv               BYTEA         NOT NULL,           -- 12-byte (96-bit) GCM IV, unique per row
    auth_tag         BYTEA         NOT NULL,           -- 16-byte (128-bit) GCM authentication tag
    encrypted_dek    BYTEA         NOT NULL,           -- 256-bit DEK wrapped by KEK
    key_version_id   UUID          NOT NULL REFERENCES key_versions(id),
    pan_hash         VARCHAR(64)   NOT NULL,           -- HMAC-SHA256 for de-dup lookup
    token_type       VARCHAR(20)   NOT NULL,           -- RECURRING | ONE_TIME
    last_four        VARCHAR(4)    NOT NULL,           -- stored in clear — not sensitive
    card_scheme      VARCHAR(10),                      -- VISA | MC | AMEX | EFTPOS
    expiry_month     SMALLINT,
    expiry_year      SMALLINT,
    merchant_id      VARCHAR(100),                     -- scope: token belongs to this merchant
    created_at       TIMESTAMPTZ   NOT NULL DEFAULT now(),
    expires_at       TIMESTAMPTZ,
    is_active        BOOLEAN       NOT NULL DEFAULT TRUE,
    record_version   INTEGER       NOT NULL DEFAULT 1, -- optimistic locking for rotation updates
    CONSTRAINT chk_token_vault_token_type
        CHECK (token_type IN ('RECURRING', 'ONE_TIME')),
    CONSTRAINT chk_token_vault_iv_length
        CHECK (octet_length(iv) = 12),
    CONSTRAINT chk_token_vault_auth_tag_length
        CHECK (octet_length(auth_tag) = 16)
);
