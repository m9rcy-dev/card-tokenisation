# AWS KMS, KEK, and HMAC — How They Fit Together

## The key hierarchy

There are three levels. AWS KMS only appears at the top.

```
AWS KMS Master Key          ← one symmetric key per environment, lives entirely in AWS KMS
        │
        │  KMS.Encrypt / KMS.Decrypt  (called once per startup, not per transaction)
        ▼
   KEK — Key Encryption Key          ← 32 bytes, generated locally by SecureRandom
        │  stored encrypted as Base64 in key_versions.encrypted_kek_blob
        │
        │  AES-256-GCM  (in-process, no KMS call)
        ├───────────────────────────────────────────────┐
        ▼                                               ▼
   DEK — Data Encryption Key                    HMAC Secret
   one per token, generated locally             32 bytes, generated locally
   stored encrypted in                          stored encrypted in
   token_vault.encrypted_dek (BYTEA)            key_versions.encrypted_secret (BYTEA)
        │
        │  AES-256-GCM  (in-process)
        ▼
   PAN ciphertext
   token_vault.encrypted_pan + iv + auth_tag
```

### What AWS provides vs what the app provides

| Material | Who generates it | Where it lives at rest |
|----------|-----------------|----------------------|
| KMS Master Key | AWS KMS | Inside AWS KMS — never leaves |
| KEK (32 bytes) | App — `SecureRandom` | `key_versions.encrypted_kek_blob` (KMS-encrypted, Base64) |
| DEK per token (32 bytes) | App — `SecureRandom` | `token_vault.encrypted_dek` (KEK-wrapped, AES-GCM) |
| HMAC secret (32 bytes) | App — `SecureRandom` | `key_versions.encrypted_secret` (KEK-wrapped, AES-GCM, BYTEA) |

**AWS does not provide the HMAC key.** The HMAC secret is entirely application-generated. AWS KMS protects the KEK, which in turn protects both the DEKs and the HMAC secret. The trust chain is: KMS Master Key → KEK → everything else.

---

## How it starts up

`KeyRingInitialiser` runs in two phases before the app accepts traffic.

**Phase 1 — load KEK ring:**

```
SELECT * FROM key_versions WHERE key_type = 'KEK' AND status IN ('ACTIVE', 'ROTATING')

For each row:
  raw_bytes  = Base64.decode(encrypted_kek_blob)
  kek_bytes  = KmsClient.decrypt(raw_bytes, context = {purpose: "kek-unwrap"})   ← KMS call
  ring.load(version_id, kek_bytes)

ring.promoteActive(active_version_id)
```

**Phase 2 — load HMAC ring:**

```
SELECT * FROM key_versions WHERE key_type = 'HMAC' AND status IN ('ACTIVE', 'ROTATING')

For each row:
  kek_bytes    = ring.getByVersion(encrypting_kek_id)     ← from in-memory ring, no KMS call
  hmac_secret  = AesGcmCipher.decryptBytes(encrypted_secret, kek_bytes)
  hmacRing.load(version_id, hmac_secret)

hmacRing.promoteActive(active_version_id)
```

After startup, KMS is not called again until the next restart or until a new KEK version row is created. All tokenisation, detokenisation, and rotation batches run entirely in JVM memory.

---

## How a token is created

```
pan_bytes        = PAN.getBytes(UTF-8)
dek              = SecureRandom.nextBytes(32)
iv               = SecureRandom.nextBytes(12)
encrypted_pan    = AES-GCM.encrypt(pan_bytes, dek, iv)
encrypted_dek    = AES-GCM.wrap(dek, active_kek)         ← kek from in-memory ring, no KMS
pan_hash         = HMAC-SHA256(pan, active_hmac_secret)   ← hmac secret from in-memory ring
zero(dek)

INSERT token_vault (token_id, token, encrypted_pan, iv, auth_tag, encrypted_dek,
                    key_version_id, pan_hash, hmac_key_version_id, ...)
```

No KMS call. No HMAC key from AWS.

---

## KEK rotation — step by step

**Trigger:** `POST /api/v1/admin/keys/rotate` or compliance cron.

**Step 1 — Initiate:**
```
DB:   UPDATE key_versions SET status = 'ROTATING' WHERE id = v1

App:  new_kek_bytes = SecureRandom.nextBytes(32)           ← genuinely new material
KMS:  new_blob     = KMS.Encrypt(new_kek_bytes,            ← one KMS call
                        context = {purpose: "kek-unwrap"})
      zero(new_kek_bytes)

DB:   INSERT key_versions (encrypted_kek_blob = new_blob, status = 'ACTIVE') → v2
KMS:  kek_bytes    = KMS.Decrypt(new_blob)                 ← one KMS call
Ring: load(v2, kek_bytes); promoteActive(v2)
      zero(kek_bytes)

Audit: KEY_ROTATION_STARTED
```

From this moment new tokenisations write `key_version_id = v2`. Old tokens with `v1` remain
detokenisable — v1 is still in the ring (ROTATING, not removed).

**Step 2 — Batch re-encryption (cron: every 15 min, batch size: 500):**
```
SELECT * FROM token_vault WHERE key_version_id = v1 AND is_active = TRUE LIMIT 500

For each token:
  old_kek       = ring.getByVersion(v1).copyKek()
  new_kek       = ring.getByVersion(v2).copyKek()
  dek           = AesGcmCipher.unwrapDek(encrypted_dek, old_kek)    ← no KMS
  new_enc_dek   = AesGcmCipher.wrapDek(dek, new_kek)               ← no KMS, new IV
  zero(old_kek, new_kek, dek)

  UPDATE token_vault SET encrypted_dek = new_enc_dek, key_version_id = v2 WHERE token_id = X
  Audit: TOKEN_REENCRYPTED
```

If the app restarts mid-batch: both v1 (ROTATING) and v2 (ACTIVE) are reloaded into the ring
on startup. The job resumes from whatever rows still have `key_version_id = v1`.

**Step 3 — Completion (auto-detected):**
```
countActiveByKeyVersionId(v1) == 0

DB:   UPDATE key_versions SET status = 'RETIRED' WHERE id = v1
Ring: v1 removed from ring
Audit: KEY_ROTATION_COMPLETED
```

---

## HMAC rotation — step by step

Like KEK rotation, HMAC rotation **generates genuinely new cryptographic material**.

**Why HMAC needs rotation:** The HMAC secret is used to compute `pan_hash` for deduplication.
Rotating it requires re-hashing every PAN in the vault — the one batch that decrypts PAN
plaintext outside of a live detokenisation request.

**Trigger:** `POST /api/v1/admin/keys/hmac-keys/rotate`

**Step 1 — Initiate:**
```
DB:   UPDATE key_versions SET status = 'ROTATING' WHERE id = h1

App:  new_hmac_bytes = SecureRandom.nextBytes(32)           ← genuinely new material
      kek_bytes      = ring.getActive().copyKek()
      enc_secret     = AesGcmCipher.encryptBytes(new_hmac_bytes, kek_bytes)
      zero(kek_bytes)

DB:   INSERT key_versions (key_type = 'HMAC', encrypted_secret = enc_secret,
                           encrypting_kek_id = active_kek_id, ...) → h2, status = 'ACTIVE'
Ring: hmacRing.load(h2, new_hmac_bytes); hmacRing.promoteActive(h2)
      zero(new_hmac_bytes)

Audit: HMAC_ROTATION_STARTED
```

From this moment new tokenisations hash with h2. Old vault rows still carry the h1 hash.

**Dual-lookup deduplication during the rotation window:**

Without this, the same PAN tokenised before and after initiation would produce two different
`pan_hash` values and get two different tokens — breaking deduplication.

```
// TokenisationService
new_hash = HMAC(pan, active_hmac=h2)
existing = vault.findByPanHash(new_hash)

if not found:
    rotating_id = hmacRing.findRotatingVersionId()   // returns h1
    if present:
        old_hash = HMAC(pan, h1_secret)
        existing = vault.findByPanHash(old_hash)     // finds the old record
        // returns same token — no duplicate issued
```

**Step 2 — Batch re-hash (cron: daily 02:00 UTC, batch size: 100):**
```
SELECT * FROM token_vault WHERE hmac_key_version_id = h1 AND is_active = TRUE LIMIT 100

For each token:
  kek_bytes    = ring.getByVersion(token.key_version_id).copyKek()
  dek_bytes    = AesGcmCipher.unwrapDek(encrypted_dek, kek_bytes)   ← KEK unwraps DEK
  pan_bytes    = AesGcmCipher.decryptWithDek(encrypted_pan, iv, auth_tag, dek_bytes)
  new_hash     = HMAC-SHA256(pan_bytes, hmacRing.getActiveSecret())
  zero(kek_bytes, dek_bytes, pan_bytes)

  UPDATE token_vault SET pan_hash = new_hash, hmac_key_version_id = h2 WHERE token_id = X
  Audit: PAN_HASH_RECOMPUTED
```

This decrypts PAN plaintext in memory — no KMS call, but the most sensitive batch in the
system. Parallelism is limited to 4 threads (vs 8 for KEK) to reduce exposure window.

**Step 3 — Completion (auto-detected):**
```
countActiveByHmacVersionId(h1) == 0

DB:     UPDATE key_versions SET status = 'RETIRED' WHERE id = h1
Ring:   hmacRing.retire(h1)   ← zeros bytes, removes from ring
Audit:  HMAC_ROTATION_COMPLETED
```

---

## Resumability

Both jobs are fully resumable across restarts.

`KeyRingInitialiser` always loads **ACTIVE and ROTATING** versions at startup. If the app
restarts mid-rotation, both the old (ROTATING) and new (ACTIVE) versions reload into their
respective rings. The batch job resumes from wherever `WHERE status = 'ROTATING'` still has
records — it never needs to know how far it got before the restart.

---

## KMS call budget

| Operation | KMS calls |
|-----------|-----------|
| App startup (normal) | 1 — decrypt the ACTIVE KEK blob |
| App startup (mid-rotation) | 2 — decrypt ACTIVE + ROTATING blobs |
| Per-token tokenise | 0 |
| Per-token detokenise | 0 |
| KEK rotation initiate | 2 — encrypt new KEK bytes (wrapNewKek) + decrypt to load into ring (unwrapKek) |
| KEK rotation batch (per record) | 0 — in-memory AES-GCM only |
| HMAC rotation initiate | 0 — new secret encrypted in memory under existing KEK |
| HMAC rotation batch (per record) | 0 — in-memory AES-GCM + HMAC only |

KMS is a **startup-only dependency** for a running application. If KMS becomes unavailable
after the app has started, all tokenise/detokenise/rotation operations continue unaffected.
KMS is only required again on the next restart or when a new KEK version row is persisted.

---

## Operational sequencing for concurrent rotation

**Never run KEK and HMAC rotation simultaneously.** If a HMAC batch record's KEK becomes
`COMPROMISED` during a concurrent emergency KEK rotation, the HMAC batch emits
`RE_HASH_SKIPPED_COMPROMISED_KEY` and skips that record. Those records are picked up again
after the KEK batch completes and re-wraps their DEKs.

Recommended sequence for a full scheduled rotation:
1. Trigger HMAC rotation → wait for batch to complete (all `hmac_key_version_id` updated)
2. Trigger KEK rotation → runs every 15 min until all `key_version_id` updated
3. Confirm both old versions are `RETIRED` in audit log / health endpoint
