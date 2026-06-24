# Feature 07 — 2-Layer KMS-DEK Architecture

## Summary

Simplify from 3-layer envelope encryption (`AWS KMS → KEK → per-record DEK → PAN`) to
2-layer direct encryption (`AWS KMS → DEK → PAN`).

**Before (3 layers):**
- KMS decrypts KEK blob at startup → KEK held in `InMemoryKekKeyRing`
- Each tokenise: generate random DEK locally, wrap it under KEK, encrypt PAN with DEK
- Each detokenise: unwrap DEK using KEK, decrypt PAN with DEK
- Each rotation batch record: unwrap DEK from old KEK, rewrap under new KEK (PAN untouched)

**After (2 layers):**
- KMS `GenerateDataKey` at rotation / KMS `Decrypt` at startup → DEK held in `InMemoryDekKeyRing`
- Each tokenise: encrypt PAN directly with DEK + fresh random 96-bit IV (no per-record DEK blob)
- Each detokenise: decrypt PAN directly with DEK (DEK already in ring)
- Each rotation batch record: decrypt PAN with old DEK, re-encrypt with new DEK + fresh IV

---

## Motivation

| Dimension           | Before                              | After                            |
|---------------------|-------------------------------------|----------------------------------|
| AES-GCM ops / tokenise | 2 (PAN encrypt + DEK wrap)       | 1 (PAN encrypt only)             |
| AES-GCM ops / detokenise | 2 (DEK unwrap + PAN decrypt)   | 1 (PAN decrypt only)             |
| Storage per vault row | +60 bytes `encrypted_dek`         | 0 extra bytes                    |
| KMS calls at startup | 1 `Decrypt` (KEK) + 1 `Decrypt` (HMAC) | 1 `Decrypt` (DEK) + 1 `Decrypt` (HMAC) — same |
| KMS calls at rotation | 2 (wrapNewKek + post-commit unwrapKek) | 1 (GenerateDataKey)          |
| API surface          | 6 methods on KmsProvider           | 4 methods (2 removed, 0 added net) |

`GenerateDataKey` is the idiomatic AWS pattern for symmetric envelope encryption. It atomically
generates and encrypts a data key in one round-trip, matching the "bring your own DEK" pattern
used for large-data encryption.

---

## Security Trade-Off

| Property                | Before                              | After                             |
|-------------------------|-------------------------------------|-----------------------------------|
| Rotation blast radius   | Only DEK rewrapped (PAN never leaves storage layer) | PAN briefly in memory during rotation |
| Mitigations             | n/a                                 | `Arrays.fill(panBytes, 0)` in `finally`; same pattern as HMAC rotation already uses |
| DEK compromise blast radius | One PAN (per-record DEK)       | All PANs on that version (shared DEK) |
| Mitigations             | n/a                                 | DEK is KMS-protected; rotation retires old DEK immediately |

---

## Interface Design

The `KmsProvider` interface remains generic — no AWS-specific types or methods on the interface.
Provider portability:

| Provider    | `generateDataKey()`                        | `decryptDataKey()`               |
|-------------|--------------------------------------------|----------------------------------|
| AWS (prod)  | `kms.generateDataKey(AES_256)` native call | `kms.decrypt()` native call      |
| LocalDev    | `SecureRandom.nextBytes(32)` + AES-GCM wrap | AES-GCM unwrap with local key  |
| GCP         | `SecureRandom.nextBytes(32)` + CloudKMS encrypt | CloudKMS decrypt             |
| Azure       | `SecureRandom.nextBytes(32)` + wrapKey     | unwrapKey                        |
| HashiCorp   | Vault `/transit/datakey` native call       | `/transit/decrypt` native call   |

HMAC key handling (`wrapNewHmacKey`, `unwrapHmacKey`, `describeKey`) is completely unaffected.

---

## Data Model Changes

### `key_versions` table

| Column          | Before                                    | After                              |
|-----------------|-------------------------------------------|------------------------------------|
| `key_type`      | `CHECK (key_type IN ('KEK','HMAC'))`      | `CHECK (key_type IN ('DEK','HMAC'))` |
| `encrypted_kek_blob` | TEXT (Base64-encoded KMS ciphertext) | **Dropped**                        |
| `encrypted_dek_blob` | (new column)                         | BYTEA (raw bytes from GenerateDataKey) |

Existing rows: `key_type = 'KEK'` → renamed to `'DEK'` by migration.

### `token_vault` table

| Column          | Before                                    | After                              |
|-----------------|-------------------------------------------|------------------------------------|
| `encrypted_dek` | BYTEA (60 bytes, per-record DEK wrapper)  | **Dropped** (migration V14)        |

---

## New Types

### `DataKey` record (new file)

```java
package com.yourorg.tokenisation.kms;

public record DataKey(byte[] plaintextDek, byte[] encryptedDekBlob) {}
```

Returned by `generateDataKey()`. The `plaintextDek` must be zeroed after use.
The `encryptedDekBlob` is the KMS ciphertext, safe for storage in `key_versions.encrypted_dek_blob`.

---

## KmsProvider Interface Changes

**Remove:** `unwrapKek`, `wrapNewKek`, `wrapDek`, `rewrapDek`

**Add:**

```java
/**
 * Generates a new DEK and returns both the plaintext (for immediate ring load)
 * and the encrypted blob (for storage in key_versions.encrypted_dek_blob).
 *
 * AWS: GenerateDataKey(AES_256) — one atomic KMS call.
 * LocalDev/GCP/Azure: SecureRandom + local encrypt.
 * Callers must zero plaintextDek after loading it into the ring.
 */
DataKey generateDataKey();

/**
 * Decrypts a stored encrypted DEK blob and returns the raw 32-byte DEK.
 * Called at startup per active/rotating DEK version. Caller must zero after ring load.
 */
byte[] decryptDataKey(byte[] encryptedDekBlob);
```

**Keep unchanged:** `wrapNewHmacKey`, `unwrapHmacKey`, `describeKey`

---

## AES-GCM Cipher Changes

### `encrypt(byte[] panBytes, byte[] dek)` — simplified

```
BEFORE: encrypt(panBytes, kek) → generate DEK, wrap DEK under KEK, encrypt PAN with DEK
        → EncryptResult(ciphertext, iv, authTag, encryptedDek)

AFTER:  encrypt(panBytes, dek) → encrypt PAN with caller-supplied DEK + fresh IV
        → EncryptResult(ciphertext, iv, authTag)
```

### `decrypt(byte[] ciphertext, byte[] iv, byte[] authTag, byte[] dek)` — simplified

```
BEFORE: decrypt(ciphertext, iv, authTag, encryptedDek, kek) → unwrap DEK from KEK, decrypt PAN
AFTER:  decrypt(ciphertext, iv, authTag, dek) → decrypt PAN with caller-supplied DEK
```

### Remove public methods

`wrapDek(byte[], byte[])` and `unwrapDek(byte[], byte[])` are removed.
The private `encryptWithDek` and `decryptRaw` helpers remain (used internally).

---

## Rotation Batch Change

The fundamental change in rotation: PAN must now be decrypted and re-encrypted (was: DEK only rewrapped).

```java
// BEFORE — DEK re-wrap, PAN never leaves storage layer
byte[] plaintextDek = cipher.unwrapDek(vault.getEncryptedDek(), oldKek);
byte[] newEncryptedDek = cipher.wrapDek(plaintextDek, newKek);
vault.reencryptDek(newEncryptedDek, newKeyVersion);

// AFTER — PAN re-encryption, PAN briefly in memory
byte[] panBytes = null;
try {
    panBytes = cipher.decrypt(vault.getEncryptedPan(), vault.getIv(), vault.getAuthTag(), oldDek);
    EncryptResult result = cipher.encrypt(panBytes, newDek);
    vault.reencryptPan(result.ciphertext(), result.iv(), result.authTag(), newKeyVersion);
} finally {
    if (panBytes != null) Arrays.fill(panBytes, (byte) 0);
}
```

---

## KMS Call Profile

| Event                  | Before                                      | After                              |
|------------------------|---------------------------------------------|------------------------------------|
| Startup (per DEK version) | `unwrapKek` × n (n = ACTIVE + ROTATING) | `decryptDataKey` × n — same count |
| Startup (HMAC)         | `unwrapHmacKey` × n                         | unchanged                          |
| Tokenise               | 0                                           | 0 — unchanged                      |
| Detokenise             | 0                                           | 0 — unchanged                      |
| Rotation (new key)     | 1 `wrapNewKek` + 1 `unwrapKek` (post-commit) | 1 `generateDataKey` — saves 1 call |
| Rotation (batch record)| 0 (in-memory AES-GCM rewrap)                | 0 (in-memory AES-GCM re-encrypt)   |

---

## Migration V14

```sql
-- Rename key_type 'KEK' → 'DEK'
UPDATE key_versions SET key_type = 'DEK' WHERE key_type = 'KEK';

ALTER TABLE key_versions DROP CONSTRAINT IF EXISTS key_versions_key_type_check;
ALTER TABLE key_versions ADD CONSTRAINT key_versions_key_type_check
    CHECK (key_type IN ('DEK', 'HMAC'));

-- Add BYTEA column for DEK blob (replaces TEXT encrypted_kek_blob)
ALTER TABLE key_versions ADD COLUMN encrypted_dek_blob BYTEA;

-- Drop the old TEXT/Base64 column
ALTER TABLE key_versions DROP COLUMN IF EXISTS encrypted_kek_blob;

-- Remove per-record DEK wrapper from token_vault
ALTER TABLE token_vault DROP COLUMN IF EXISTS encrypted_dek;

-- Recreate active-per-type unique index with updated key_type values
DROP INDEX IF EXISTS idx_key_versions_single_active_per_type;
CREATE UNIQUE INDEX idx_key_versions_single_active_per_type
    ON key_versions(key_type) WHERE status = 'ACTIVE';
```

---

## Startup Sequence

| Order | Bean | Action |
|-------|------|--------|
| `@Order(1)` | `LocalDevKeySeeder` / `AwsKeySeeder` | Seed DEK row via `generateDataKey()`, store `encryptedDekBlob` |
| `@Order(2)` | `LocalDevHmacKeySeeder` | Seed HMAC row — unchanged |
| `@Order(10)` | `KeyRingInitialiser` Phase 1 | `decryptDataKey(encryptedDekBlob)` → load `InMemoryDekKeyRing` |
| `@Order(10)` | `KeyRingInitialiser` Phase 2 | `unwrapHmacKey(encryptedSecret)` → load HMAC ring — unchanged |

---

## Verification Checklist

1. `mvn test` — all unit and integration tests pass
2. `make start` → startup logs show: `Loaded DEK version <uuid> (status: ACTIVE) into ring`
3. `POST /api/v1/tokens` → 201; `SELECT * FROM token_vault` shows no `encrypted_dek` column
4. `GET /api/v1/tokens/<token>` → PAN returned correctly
5. Same PAN twice → same token (HMAC dedup unchanged)
6. `POST /api/v1/admin/keys/rotate` → rotation completes; vault rows updated (new IV + ciphertext)
7. Detokenise after rotation → PAN still returned correctly
8. `make gatling-test GATLING_SIM=com.yourorg.tokenisation.RotationSimulation GATLING_SCALE=20k` → 0 KO

---

## What Does NOT Change

- HMAC ring (`InMemoryHmacKeyRing`), `PanHasher`, HMAC rotation batch — unchanged
- `token_vault.pan_hash`, `token_vault.hmac_key_version_id` — unchanged
- `key_versions.encrypted_secret` (HMAC blob column) — unchanged
- `KmsProvider.wrapNewHmacKey`, `unwrapHmacKey`, `describeKey` — unchanged
- `KeyRingRefreshJob` HMAC refresh path — unchanged
- Rate limiting, audit logging, ShedLock configuration — unchanged
