# Key Rotation Runbook

This runbook covers **DEK rotation** (scheduled and emergency) and **HMAC key rotation** for PAN-hash versioning. Read the entire relevant section before acting.

---

## Table of Contents

1. [Background — What Rotation Does](#1-background--what-rotation-does)
2. [Scheduled DEK Rotation](#2-scheduled-dek-rotation)
3. [Emergency DEK Rotation](#3-emergency-dek-rotation)
4. [HMAC Key Rotation](#4-hmac-key-rotation)
5. [Monitoring Rotation Progress](#5-monitoring-rotation-progress)
6. [Verifying Completion](#6-verifying-completion)
7. [Troubleshooting](#7-troubleshooting)
8. [Rollback Considerations](#8-rollback-considerations)

---

## 1. Background — What Rotation Does

Each token's PAN is encrypted with the active **Data Encryption Key (DEK)** for the current rotation period. The DEK is a 32-byte AES-256 key whose encrypted blob is stored in `key_versions.encrypted_dek_blob`; the plaintext DEK lives only in `InMemoryDekKeyRing` (zeroed after each use).

When we rotate keys, we are generating a new DEK and re-encrypting all PANs under it. The rotation process:

1. Calls `kmsProvider.generateDataKey()` to produce a new DEK (1 KMS call), inserts a new `key_versions` row, and loads the new DEK into the ring.
2. Transitions the old `key_versions` row to `ROTATING` (scheduled) or `COMPROMISED` (emergency).
3. For each token: decrypts the PAN using the old DEK from the ring, re-encrypts it with the new DEK and a **fresh random IV** — all in-process AES-GCM, **zero KMS calls per token**. The plaintext PAN is zeroed from memory immediately after re-encryption.
4. Once all tokens are migrated, the old key is marked `RETIRED`.

This means rotation is safe to run while the service is live — tokens on the old DEK remain readable until they are migrated, and new tokens use the new DEK immediately.

---

## 2. Scheduled DEK Rotation

Use this procedure when the key approaches its compliance TTL (`rotation.compliance.max-key-age-days`, default 365 days) or when a manual rotation is required.

### Step 1 — Verify pre-rotation state

```bash
# Check the current active DEK version
psql $DATABASE_URL -c "SELECT id, key_alias, key_type, status, activated_at, rotate_by FROM key_versions WHERE key_type = 'DEK' ORDER BY activated_at DESC;"
```

Expected: exactly one row with `status = 'ACTIVE'` and `rotate_by` in the future (or past — triggering rotation).

### Step 2 — Trigger rotation

```bash
curl -X POST https://<host>/api/v1/admin/keys/rotate \
  -H 'Content-Type: application/json' \
  -d '{"reason": "SCHEDULED", "newKeyAlias": "vault-key-2026-q2"}'
```

Expected response: `HTTP 202 Accepted` (empty body).

What happens synchronously:
- The old DEK is moved from `ACTIVE` → `ROTATING` in the database.
- A new DEK is generated via `kmsProvider.generateDataKey()`, persisted as a new `ACTIVE` row, and loaded into `InMemoryDekKeyRing`.
- All new tokenisation immediately uses the new DEK.

### Step 3 — Monitor batch re-encryption

The `RotationJob` scheduler picks up the `ROTATING` DEK and re-encrypts PANs in batches every 15 minutes (configurable via `rotation.batch.cron`).

Monitor progress:

```bash
# Count tokens still on the old DEK (replace <old-key-id> with the UUID from step 1)
psql $DATABASE_URL -c "
  SELECT kv.key_alias, COUNT(tv.token_id) AS remaining_tokens
  FROM key_versions kv
  JOIN token_vault tv ON tv.key_version_id = kv.id
  WHERE kv.status = 'ROTATING' AND kv.key_type = 'DEK' AND tv.is_active = TRUE
  GROUP BY kv.key_alias;"
```

When `remaining_tokens` reaches 0, the `RotationJob` will automatically retire the old key.

### Step 4 — Confirm completion

```bash
psql $DATABASE_URL -c "SELECT id, key_alias, status, retired_at FROM key_versions ORDER BY activated_at DESC;"
```

Expected: old key has `status = 'RETIRED'` with a non-null `retired_at`.

Audit log check:
```bash
psql $DATABASE_URL -c "
  SELECT event_type, outcome, created_at
  FROM token_audit_log
  WHERE event_type IN ('KEY_ROTATION_STARTED', 'KEY_ROTATION_COMPLETED')
  ORDER BY created_at DESC LIMIT 10;"
```

---

## 3. Emergency DEK Rotation

Use this procedure when a DEK is suspected or confirmed to be compromised. **Act quickly** — every second of delay is a window for an attacker to decrypt vault records.

### Step 1 — Identify the compromised DEK

Determine the `key_versions.id` UUID of the compromised DEK row. Check:
- Security monitoring alerts (SIEM, CloudTrail anomalies)
- Audit log `TAMPER_ALERT` events:
  ```bash
  psql $DATABASE_URL -c "
    SELECT event_type, failure_reason, created_at
    FROM token_audit_log
    WHERE event_type = 'TAMPER_ALERT'
    ORDER BY created_at DESC LIMIT 5;"
  ```

### Step 2 — Trigger emergency rotation

```bash
curl -X POST https://<host>/api/v1/admin/keys/rotate \
  -H 'Content-Type: application/json' \
  -d '{
    "reason": "COMPROMISE",
    "compromisedVersionId": "<uuid-of-compromised-dek>",
    "newKeyAlias": "emergency-rotation-2026-04-17"
  }'
```

Expected response: `HTTP 202 Accepted`.

What happens synchronously (before the 202 is returned):
- The compromised DEK is immediately marked `COMPROMISED` in `InMemoryDekKeyRing` — all detokenisation attempts using this DEK fail immediately with HTTP 500.
- The DEK row is marked `COMPROMISED` in the database.
- A new DEK is generated via `kmsProvider.generateDataKey()`, persisted as a new `ACTIVE` row, and loaded into the ring.
- A `SecurityAlertEvent` is published internally (triggers webhook/email notification if configured).
- Audit events: `KEY_INTEGRITY_VIOLATION` and `EMERGENCY_ROTATION_STARTED`.

### Step 3 — Verify immediate detokenisation block

```bash
# Try to detokenise any token — expect HTTP 500 (compromised key)
TOKEN=$(psql $DATABASE_URL -t -c "SELECT token FROM token_vault WHERE key_version_id='<compromised-uuid>' AND is_active=TRUE LIMIT 1;")
curl -H "X-Merchant-ID: MERCHANT_001" https://<host>/api/v1/tokens/$TOKEN
# Expected: HTTP 500
```

### Step 4 — Monitor re-encryption

Same as scheduled rotation step 3. Emergency batches use `rotation.batch.emergency-size` (default 100, smaller than the scheduled 500 to prioritise re-encryption speed).

### Step 5 — Confirm re-encryption complete and service restored

After the batch completes:
- Old DEK moves from `COMPROMISED` → `RETIRED`
- All tokens can be detokenised again (now re-encrypted under the new DEK)

```bash
# Verify the previously-failing token now works
curl -H "X-Merchant-ID: MERCHANT_001" https://<host>/api/v1/tokens/$TOKEN
# Expected: HTTP 200 with PAN
```

### Step 6 — Post-incident actions

1. Rotate the KMS CMK in AWS (if the CMK itself was leaked, not just the encrypted DEK blob).
2. Review CloudTrail logs for the window of possible exposure.
3. Assess whether affected merchants need notification (PCI-DSS breach notification requirements apply).
4. Review how the compromise was possible and close the gap.

---

## 4. HMAC Key Rotation

HMAC keys sign the `pan_hash` stored in `token_vault`. Rotating them requires re-hashing every active vault record under the new HMAC key. This is the most data-intensive rotation and must be performed off-peak.

### When to rotate the HMAC key

- Annual compliance rotation (same cadence as DEK, default `rotate_by` is 365 days from activation)
- HMAC secret suspected of leaking

### Step 1 — Verify pre-rotation HMAC key state

```sql
SELECT id, key_alias, status, activated_at, rotate_by
FROM key_versions
WHERE key_type = 'HMAC'
ORDER BY activated_at DESC;
```

Expected: one row with `status = 'ACTIVE'`, `rotate_by` in the past or approaching.

### Step 2 — Trigger HMAC rotation

```bash
curl -X POST https://<host>/api/v1/admin/hmac-keys/rotate \
  -H 'Content-Type: application/json' \
  -d '{"newKeyAlias": "hmac-key-2027-q1"}'
```

What happens synchronously:
- The old HMAC key moves from `ACTIVE` → `ROTATING`.
- A new 32-byte `SecureRandom` HMAC secret is generated and encrypted **directly by AWS KMS CMK** (`purpose=hmac-key` encryption context) — the DEK is not involved. The ciphertext is persisted as a new `ACTIVE` HMAC row (1 KMS call total).
- The new secret is loaded into `InMemoryHmacKeyRing` and promoted to active.
- All new tokenisations immediately use the new secret.

### Step 3 — Monitor re-hashing batch

The `HmacRotationJob` re-hashes vault records every night at 02:00 UTC (configurable via `rotation.hmac-batch.cron`).

```sql
-- Tokens still on the rotating HMAC key
SELECT COUNT(*)
FROM token_vault
WHERE hmac_key_version_id = '<rotating-hmac-uuid>'
  AND is_active = TRUE;
```

During re-hashing, `TokenisationService` performs a dual-lookup: it tries the new hash first, then falls back to the old hash for de-duplication. This prevents duplicate tokens during the transition window.

### Step 4 — Confirm completion

```sql
-- Old HMAC key should be RETIRED
SELECT id, key_alias, status, retired_at
FROM key_versions
WHERE key_type = 'HMAC'
ORDER BY activated_at DESC;

-- Audit confirmation
SELECT event_type, outcome, created_at
FROM token_audit_log
WHERE event_type IN ('HMAC_ROTATION_STARTED', 'HMAC_ROTATION_COMPLETED')
ORDER BY created_at DESC LIMIT 4;
```

---

## 5. Monitoring Rotation Progress

### Health endpoint

```bash
curl https://<host>/api/v1/health
```

During rotation, if the key ring only has a `ROTATING` or `COMPROMISED` key (no `ACTIVE`), the health endpoint returns `"keyRing": "DOWN"` and HTTP 503. This should only occur momentarily during the transition window.

### Metrics endpoint

```bash
curl https://<host>/api/v1/metrics
```

Watch `tokeniseRequests` and `detokeniseRequests` — they should continue to increment normally during a scheduled rotation. A drop in `detokeniseRequests` during emergency rotation is expected (tokens on the compromised key are temporarily blocked).

### Audit log counts

```sql
SELECT event_type, COUNT(*) FROM token_audit_log
WHERE created_at > NOW() - INTERVAL '1 hour'
GROUP BY event_type ORDER BY count DESC;
```

During rotation, expect `TOKEN_REENCRYPTED` to be the highest-volume event type.

---

## 6. Verifying Completion

A rotation is complete when **all** of the following are true:

| Check | SQL / command | Expected result |
|-------|---------------|-----------------|
| Old key retired | `SELECT status FROM key_versions WHERE id='<old-uuid>'` | `RETIRED` |
| No tokens on old key | `SELECT COUNT(*) FROM token_vault WHERE key_version_id='<old-uuid>' AND is_active=TRUE` | `0` |
| Rotation completed audit | `SELECT * FROM token_audit_log WHERE event_type='KEY_ROTATION_COMPLETED'` | One row with `outcome='SUCCESS'` |
| New key active | `SELECT status FROM key_versions WHERE status='ACTIVE'` | One row |

---

## 7. Troubleshooting

### Rotation stuck: tokens not migrating

**Symptom:** `remaining_tokens` stays constant across multiple batch runs.

**Check 1 — RotationJob scheduler disabled:**
```bash
grep "rotation.batch.cron" src/test/resources/application-test.yml
```
The test profile sets `cron: "-"` (disabled). In production this must be a valid cron expression.

**Check 2 — KMS unreachable:**
Check logs for `KMS unavailable` in `RE_ENCRYPTION_FAILURE` audit events:
```sql
SELECT failure_reason FROM token_audit_log WHERE event_type='RE_ENCRYPTION_FAILURE' ORDER BY created_at DESC LIMIT 5;
```

**Check 3 — Self-injection not wired:**
If `RotationBatchProcessor.self` is null (misconfigured Spring context), no tokens will be re-encrypted. Verify by checking that `TOKEN_REENCRYPTED` audit events are being written.

### Emergency rotation: detokenisation still failing after batch completes

**Symptom:** HTTP 500 on detokenise even after old DEK row shows `RETIRED`.

**Cause:** `InMemoryDekKeyRing` still has the DEK marked `COMPROMISED`. The ring status is updated to `RETIRED` by `RotationJob.completeRotation()` via `dekRing.retire()`. If that method was not called (e.g. due to a restart between batch completion and cutover), the ring is out of sync.

**Fix:** Restart the application. `KeyRingInitialiser` reloads all `ACTIVE` and `ROTATING` DEK versions from DB. If the old DEK is `RETIRED`, it is not loaded. The new DEK is loaded and promoted.

### Unexpected DEK decryption failure at startup

**Symptom:** Log line: `KMS InvalidCiphertextException` during `KeyRingInitialiser` Phase 1 (DEK ring load).

**Cause:** The `encrypted_dek_blob` column in a `key_versions` DEK row was modified directly in the database, or the row was copied from a different environment whose CMK does not match the current KMS key. KMS rejects the ciphertext because it was not produced by this CMK (or encryption context mismatch: the stored blob must have been produced with `purpose=data-key`).

**Action:**
1. Do not restart repeatedly — each failed startup attempt logs evidence.
2. Confirm the `kms_key_id` and `kms_provider` columns on the failing DEK row match the currently configured CMK ARN.
3. If DB-level tampering is confirmed, treat as a security incident. Restore the DEK row from a known-good backup and re-seed.
4. Integrity of DEK material is enforced by KMS AES-GCM — the CMK will not decrypt a blob produced by a different key or with a different encryption context.

### Unexpected HMAC decryption failure at startup

**Symptom:** Log line: `KMS InvalidCiphertextException` during `KeyRingInitialiser` Phase 2 (HMAC ring load).

**Cause:** The `encrypted_secret` column in a `key_versions` HMAC row was modified directly in the database, or the row was copied from a different environment whose CMK does not match the current KMS key.

**Action:**
1. Do not restart repeatedly — each failed startup attempt logs evidence.
2. Check who modified the row: `SELECT * FROM token_audit_log WHERE event_type LIKE 'HMAC%' ORDER BY created_at DESC LIMIT 10;`
3. Confirm the `kms_key_id` and `kms_provider` columns on the failing HMAC row match the currently configured CMK ARN.
4. If DB-level tampering is confirmed, treat as a security incident. Restore the HMAC row from a known-good backup and initiate emergency DEK rotation to limit blast radius.
5. Integrity of HMAC key material is enforced by KMS — the CMK will not decrypt a blob produced by a different key or with a different encryption context.

---

## 8. Rollback Considerations

**DEK rotation cannot be rolled back** once tokens have been re-encrypted under the new DEK. The re-encryption is designed to be one-way.

However, the following guarantees hold:
- No data is lost — the old `key_versions` row is never deleted.
- Before re-encryption starts, all existing tokens are still detokenisable using the old DEK.
- After a successful batch, all tokens are detokenisable using the new DEK.

If re-encryption fails midway (e.g. KMS outage), the partially-migrated state is safe:
- Migrated tokens are re-encrypted under the new DEK.
- Un-migrated tokens still use the old DEK (which is still in the ring as `ROTATING`, not yet `RETIRED`).
- The batch will resume on the next `RotationJob` invocation.
