-- V1__create_key_versions.sql
--
-- Stores all KMS key versions used for wrapping DEKs.
-- Each row represents one KEK lifecycle: ACTIVE → ROTATING → RETIRED (or COMPROMISED).
-- The checksum column holds an HMAC-SHA256 over key fields to detect row-level tampering.
-- Rows are NEVER hard-deleted — retired versions are kept for historical DEK unwrapping.

CREATE TABLE key_versions (
    id               UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    kms_key_id       VARCHAR(255)  NOT NULL,
    kms_provider     VARCHAR(50)   NOT NULL,           -- AWS_KMS | LOCAL_DEV
    key_alias        VARCHAR(100)  NOT NULL,
    encrypted_kek_blob TEXT        NOT NULL,           -- Base64-encoded KEK ciphertext from KMS
    status           VARCHAR(20)   NOT NULL DEFAULT 'ACTIVE',
    rotation_reason  VARCHAR(20),                      -- SCHEDULED | COMPROMISE | MANUAL
    activated_at     TIMESTAMPTZ   NOT NULL DEFAULT now(),
    retired_at       TIMESTAMPTZ,
    rotate_by        TIMESTAMPTZ   NOT NULL,           -- compliance deadline
    created_by       VARCHAR(100)  NOT NULL,
    checksum         VARCHAR(64)   NOT NULL,           -- HMAC-SHA256 integrity guard on this row
    CONSTRAINT chk_key_versions_status
        CHECK (status IN ('ACTIVE', 'ROTATING', 'RETIRED', 'COMPROMISED')),
    CONSTRAINT chk_key_versions_rotation_reason
        CHECK (rotation_reason IS NULL OR rotation_reason IN ('SCHEDULED', 'COMPROMISE', 'MANUAL'))
);
