# Key Rotation Runbook

This runbook covers both **scheduled** (compliance-driven) and **emergency** (compromise-driven) key rotation. Read the entire relevant section before acting.

---

## Table of Contents

1. [Background — What Rotation Does](#1-background--what-rotation-does)
2. [Scheduled Rotation](#2-scheduled-rotation)
3. [Emergency Rotation](#3-emergency-rotation)
4. [Monitoring Rotation Progress](#4-monitoring-rotation-progress)
5. [Verifying Completion](#5-verifying-completion)
6. [Troubleshooting](#6-troubleshooting)
7. [Rollback Considerations](#7-rollback-considerations)

---

## 1. Background — What Rotation Does

Each token's PAN is encrypted with a unique **Data Encryption Key (DEK)**. The DEK is stored alongside the token, but it is itself encrypted (wrapped) with a **Key Encryption Key (KEK)** that lives in KMS.

When we rotate keys, we are changing the KEK — not re-encrypting the PAN itself. The rotation process:

1. Creates a new KEK in KMS and a new `key_versions` row.
2. Transitions the old `key_versions` row to `ROTATING` (scheduled) or `COMPROMISED` (emergency).
3. For each token: fetches the old encrypted DEK, asks KMS to decrypt it with the old KEK and re-encrypt with the new KEK (this is the `rewrapDek` operation). The PAN ciphertext is **never touched**.
4. Once all tokens are migrated, the old key is marked `RETIRED`.

This means rotation is safe to run while the service is live — tokens encrypted under the old key remain readable until they are migrated, and new tokens use the new key immediately.

---

## 2. Scheduled Rotation

Use this procedure when the key approaches its compliance TTL (`rotation.compliance.max-key-age-days`, default 365 days) or when a manual rotation is required.

### Step 1 — Verify pre-rotation state

```bash
# Check the current active key version
psql $DATABASE_URL -c "SELECT id, key_alias, status, activated_at, rotate_by FROM key_versions ORDER BY activated_at DESC;"
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
- The old key is moved from `ACTIVE` → `ROTATING` in the database.
- A new `ACTIVE` key is created and loaded into the in-memory key ring.
- All new tokenisation immediately uses the new key.

### Step 3 — Monitor batch re-encryption

The `RotationJob` scheduler picks up the `ROTATING` key and re-encrypts batches every 15 minutes (configurable via `rotation.batch.cron`).

Monitor progress:

```bash
# Count tokens still on the old key (replace <old-key-id> with the UUID from step 1)
psql $DATABASE_URL -c "
  SELECT kv.key_alias, COUNT(tv.token_id) AS remaining_tokens
  FROM key_versions kv
  JOIN token_vault tv ON tv.key_version_id = kv.id
  WHERE kv.status = 'ROTATING' AND tv.is_active = TRUE
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

## 3. Emergency Rotation

Use this procedure when a KEK is suspected or confirmed to be compromised. **Act quickly** — every second of delay is a window for an attacker to decrypt vault records.

### Step 1 — Identify the compromised key

Determine the `key_versions.id` UUID of the compromised key. Check:
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
    "compromisedVersionId": "<uuid-of-compromised-key>",
    "newKeyAlias": "emergency-rotation-2026-04-17"
  }'
```

Expected response: `HTTP 202 Accepted`.

What happens synchronously (before the 202 is returned):
- The compromised key is immediately marked `COMPROMISED` in the **in-memory key ring** — all detokenisation attempts using this key fail immediately with HTTP 500.
- The key is marked `COMPROMISED` in the database.
- A new `ACTIVE` key is created and loaded into the ring.
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
- Old key moves from `COMPROMISED` → `RETIRED`
- All tokens can be detokenised again (now using the new key's DEK wrapping)

```bash
# Verify the previously-failing token now works
curl -H "X-Merchant-ID: MERCHANT_001" https://<host>/api/v1/tokens/$TOKEN
# Expected: HTTP 200 with PAN
```

### Step 6 — Post-incident actions

1. Rotate the KMS CMK in AWS (if the CMK itself was leaked, not just the wrapped KEK blob).
2. Review CloudTrail logs for the window of possible exposure.
3. Assess whether affected merchants need notification (PCI-DSS breach notification requirements apply).
4. Review how the compromise was possible and close the gap.

---

## 4. Monitoring Rotation Progress

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

## 5. Verifying Completion

A rotation is complete when **all** of the following are true:

| Check | SQL / command | Expected result |
|-------|---------------|-----------------|
| Old key retired | `SELECT status FROM key_versions WHERE id='<old-uuid>'` | `RETIRED` |
| No tokens on old key | `SELECT COUNT(*) FROM token_vault WHERE key_version_id='<old-uuid>' AND is_active=TRUE` | `0` |
| Rotation completed audit | `SELECT * FROM token_audit_log WHERE event_type='KEY_ROTATION_COMPLETED'` | One row with `outcome='SUCCESS'` |
| New key active | `SELECT status FROM key_versions WHERE status='ACTIVE'` | One row |

---

## 6. Troubleshooting

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

**Symptom:** HTTP 500 on detokenise even after old key shows `RETIRED`.

**Cause:** The in-memory key ring still has the key marked `COMPROMISED`. The status in the ring is updated to `RETIRED` by `RotationJob.completeRotation()` via `keyRing.retire()`. If that method was not called (e.g. due to a restart between batch completion and cutover), the ring is out of sync.

**Fix:** Restart the application. `KeyRingInitialiser` reloads all `ACTIVE` and `ROTATING` key versions from DB. If the old key is `RETIRED`, it is not loaded. The new key is loaded and promoted.

### Integrity check failure during cutover

**Symptom:** Log line: `Integrity check failed on retiring key [<uuid>]`

**Cause:** The `key_versions` row for the rotating key was modified directly in the database (or the HMAC signing secret changed after the checksum was computed).

**Action:**
1. Check audit log for `TAMPER_ALERT` events.
2. If a DB-level modification occurred, treat this as a security incident and initiate an emergency rotation.
3. If the signing secret (`TAMPER_DETECTION_SECRET`) changed without re-computing checksums, re-compute all checksums using the new secret.

---

## 7. Rollback Considerations

**Key rotation cannot be rolled back** once tokens have been re-encrypted under the new key. The re-encryption is designed to be one-way.

However, the following guarantees hold:
- No data is lost — the old `key_versions` row is never deleted.
- Before re-encryption starts, all existing tokens are still detokenisable using the old key.
- After a successful batch, all tokens are detokenisable using the new key.

If re-encryption fails midway (e.g. KMS outage), the partially-migrated state is safe:
- Migrated tokens use the new key.
- Un-migrated tokens still use the old key (which is still in the ring as `ROTATING`, not yet `RETIRED`).
- The batch will resume on the next `RotationJob` invocation.
