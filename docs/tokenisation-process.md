# Card Tokenisation System — Process Reference

This document is a self-contained reference for anyone who needs to understand how the
tokenisation system works end-to-end. It covers the mental model (key concepts and acronyms),
all operational flows, and the KMS call cost of each operation.

---

## Table of Contents

1. [Mental Model and Glossary](#1-mental-model-and-glossary)
2. [Tokenisation Flow](#2-tokenisation-flow)
3. [Detokenisation Flow](#3-detokenisation-flow)
4. [Detokenisation During DEK Rotation](#4-detokenisation-during-dek-rotation)
5. [Detokenisation During HMAC Rotation](#5-detokenisation-during-hmac-rotation)
6. [Detokenisation During Emergency Rotation (COMPROMISED DEK)](#6-detokenisation-during-emergency-rotation)
7. [DEK Rotation Flow](#7-dek-rotation-flow)
8. [HMAC Rotation Flow](#8-hmac-rotation-flow)
9. [AWS CMK Auto-Rotation (Transparent)](#9-aws-cmk-auto-rotation)
10. [KMS Call Cost Summary](#10-kms-call-cost-summary)

---

## 1. Mental Model and Glossary

### PAN (Primary Account Number)

The 16-digit card number — the thing we are protecting. It must never appear in logs, error
messages, or audit records. Example: `5500 0055 5555 5559`.

### Token

An opaque, meaningless identifier that replaces the PAN in all systems outside the vault.
Looks like a UUID: `3a4f9d2e-1b5c-4f8a-a3e7-c6d9f0b2a1e4`. Safe to store in merchant databases
— even if breached, the attacker gets nothing useful without access to the vault.

### DEK (Data Encryption Key)

A 32-byte AES-256 key used to encrypt PANs. One DEK is active per rotation cycle — all PANs
created during that cycle share the same DEK. KMS generates the DEK via `GenerateDataKey`,
which returns both the plaintext (for immediate in-memory use) and an encrypted blob (for
storage in `key_versions.encrypted_dek_blob`). The plaintext DEK is held in `InMemoryDekKeyRing`
and is zeroed from memory immediately after each encrypt/decrypt call.

*Analogy: the DEK is the combination to the vault for a rotation period. All valuables (PANs)
from that period are locked with it. The combination itself is sealed in an envelope (the
encrypted DEK blob) that only KMS can open.*

### KMS (Key Management Service)

A secure external service (e.g. AWS KMS, or the local-dev in-process adapter) that stores and
manages the CMK. The application asks KMS to generate a new DEK (`GenerateDataKey`) or decrypt
an existing DEK blob (`Decrypt`) — the raw CMK bytes never leave the HSM.

### CMK (Customer Master Key)

The master key inside KMS. This is the root of the key hierarchy. The application has one CMK
(symmetric, encrypt/decrypt). It is used directly to protect both the DEK blob and the HMAC
blob using distinct encryption contexts.

### Encryption Context

A `Map<String, String>` passed in `kms.generateDataKey()` and `kms.decrypt()` API calls. AWS
binds it cryptographically to the ciphertext — a blob produced with one context cannot be
decrypted with a different context. Values appear in CloudTrail as audit metadata (not secret).

This system uses:
- `purpose=data-key` — for DEK blobs (`key_versions.encrypted_dek_blob`)
- `purpose=hmac-key` — for HMAC secret blobs (`key_versions.encrypted_secret`)

### Envelope Encryption (2-layer)

The technique used in this system:

1. KMS generates a DEK and returns both plaintext bytes and an encrypted blob (`GenerateDataKey`)
2. The plaintext DEK is loaded into the key ring; the encrypted blob is persisted
3. Each PAN is encrypted directly with the DEK (AES-256-GCM) — no intermediate wrapping
4. Zero the DEK copy from memory immediately after use

To decrypt a PAN at runtime:
1. Look up `key_version_id` on the vault row → find the DEK in `InMemoryDekKeyRing` (no KMS call)
2. AES-GCM decrypt `(encrypted_pan, dek, iv, auth_tag)` → plaintext PAN
3. Zero the DEK copy from memory

The key and the data travel separately: the encrypted PAN is in `token_vault`, the DEK blob is
in `key_versions`, and the plaintext DEK lives only in RAM.

### IV (Initialization Vector)

A 12-byte random value generated fresh for every AES-GCM encrypt call. With a shared DEK used
across many PANs, IV uniqueness is critical: AES-GCM produces `ciphertext = plaintext XOR
keystream(DEK, IV)`. Reusing an IV means reusing the keystream — an attacker could XOR two
ciphertexts to recover `PAN1 XOR PAN2`. Fresh IVs guarantee each `(DEK, IV)` pair is unique.

### Auth Tag (Authentication Tag)

A 16-byte value produced by AES-GCM that proves the ciphertext has not been tampered with. On
decryption, if even one bit of the ciphertext was changed, the authentication check fails — the
decryption itself detects tampering. An auth tag mismatch triggers a `TAMPER_ALERT` audit event
and an `HTTP 500` to the caller.

### HMAC (Hash-based Message Authentication Code)

A keyed one-way hash function. Used in this system to compute a **PAN fingerprint**
(`pan_hash`) for deduplication. When the same PAN is submitted for tokenisation again, the
system hashes it with the current HMAC secret and looks up `pan_hash` to find the existing
token — avoiding duplicate vault rows.

The HMAC secret is never used to recover a PAN — it is a one-way operation. If the secret
were leaked, an attacker could enumerate known PANs and check which ones match stored hashes,
but they could **not** reverse the hash to extract PANs. The risk is **cardholder linkability**,
not PAN exposure.

### Key Ring (`InMemoryDekKeyRing`)

The in-memory store of decrypted DEK material. At startup, the application asks KMS to decrypt
the active DEK blob(s) and holds the plaintext bytes in RAM. This means KMS is only called at
startup and at rotation initiation — not on every tokenisation or detokenisation request.

The ring also holds ROTATING DEKs (during a rotation batch) so that tokens encrypted under the
old DEK remain readable while the batch re-encrypts them under the new one.

---

## 2. Tokenisation Flow

**Trigger:** `POST /api/v1/tokens { pan, merchantId, tokenType }`  
**KMS calls:** 0 (DEK and HMAC secret already in ring from startup)

```
Client                    Application                           PostgreSQL
  │                            │                                    │
  │── POST /api/v1/tokens ────▶│                                    │
  │                            │                                    │
  │                            │  1. dek = dekRing.getActive().copyDek()   (in-process)
  │                            │  2. iv  = SecureRandom(12 bytes)          (in-process)
  │                            │  3. Encrypt PAN:  AES-GCM(PAN, dek, iv)  (in-process)
  │                            │                   → encrypted_pan, authTag
  │                            │  4. Zero dek bytes from memory
  │                            │  5. Hash PAN:     HMAC-SHA256(PAN, inMemoryHmacSecret)
  │                            │                   → pan_hash
  │                            │  6. Dedup check:  SELECT WHERE pan_hash = ?  ──────────▶│
  │                            │◀─────────────────────── existing row or empty ───────────│
  │                            │                                    │
  │                            │  7a. If existing: return existing token (no INSERT)
  │                            │  7b. If new:      generate token UUID
  │                            │                   INSERT token_vault ──────────────────▶│
  │                            │                   (token, encrypted_pan, iv, authTag,    │
  │                            │                    keyVersionId, pan_hash,               │
  │                            │                    hmac_key_version_id)                  │
  │                            │                   INSERT token_audit_log ───────────────▶│
  │                            │                                    │
  │◀── { token, lastFour } ────│                                    │
```

**Key points:**
- No KMS call — the DEK is already in the ring from startup
- The DEK copy exists in RAM for milliseconds — zeroed immediately after step 4
- `pan_hash` is used **only** for deduplication; it is never used to recover the PAN
- The PAN never touches the database in plaintext, not even temporarily
- One-time tokens always create a new vault row regardless of `pan_hash`
- Recurring tokens check `pan_hash` first and return the existing token if found

---

## 3. Detokenisation Flow

**Trigger:** `GET /api/v1/tokens/{token}` with `X-Merchant-ID` header  
**KMS calls:** 0 (DEK already in ring from startup)

```
Client                    Application                           PostgreSQL
  │                            │                                    │
  │── GET /api/v1/tokens/T ───▶│                                    │
  │   X-Merchant-ID: M         │                                    │
  │                            │  1. SELECT token_vault WHERE token = T ──────▶│
  │                            │◀────── encrypted_pan, iv, authTag,             │
  │                            │        keyVersionId, merchantId ────────────────│
  │                            │                                    │
  │                            │  2. Verify merchantId == M (scope check)
  │                            │  3. dek = dekRing.getByVersion(keyVersionId).copyDek()
  │                            │     (in-memory — no KMS call)
  │                            │  4. Check dek.status ≠ COMPROMISED
  │                            │  5. pan = AES-GCM.decrypt(encrypted_pan, dek, iv, authTag)
  │                            │     (auth tag verified here — detects any tampering)
  │                            │  6. Zero dek bytes from memory
  │                            │  7. INSERT token_audit_log ─────────────────────▶│
  │                            │                                    │
  │◀── { pan, lastFour } ──────│                                    │
```

**Key points:**
- No per-record DEK to unwrap — the ring holds the shared DEK directly, indexed by `keyVersionId`
- HMAC key is **never consulted** during detokenisation — it is only used for tokenisation dedup
- Zero KMS calls — the DEK was decrypted once at startup and held in `InMemoryDekKeyRing`
- AES-GCM auth tag check (step 5) implicitly detects any database-level tampering with
  `encrypted_pan`, `iv`, or `auth_tag`
- Step 4 (COMPROMISED check) only matters during an emergency rotation — see §6

---

## 4. Detokenisation During DEK Rotation

When a scheduled DEK rotation is initiated, the old DEK moves from `ACTIVE` → `ROTATING`
synchronously, before the batch starts. `InMemoryDekKeyRing` keeps both the ROTATING and ACTIVE
DEKs loaded simultaneously.

```
                           │ rotation initiated │ completeRotation() │
                           ▼                   ▼
DEK status:   ACTIVE ──── ROTATING ──────────── RETIRED

Tokens on old DEK:  encrypted with oldDek, key_version_id = v1   ← being re-encrypted by batch
Tokens on new DEK:  encrypted with newDek, key_version_id = v2   ← available immediately

Detokenisation of old-DEK token:
  vault.keyVersionId = v1 → dekRing.getByVersion(v1) → ROTATING, still in ring ✓ → works

Detokenisation of new-DEK token:
  vault.keyVersionId = v2 → dekRing.getByVersion(v2) → ACTIVE, in ring ✓ → works

After completeRotation() (batch complete, old DEK → RETIRED):
  old DEK evicted from ring; all vault rows now point to v2
  Detokenisation: works normally for all tokens
```

**There is no window where detokenisation fails during a scheduled DEK rotation.**

---

## 5. Detokenisation During HMAC Rotation

HMAC rotation runs a batch that updates `token_vault.pan_hash` from the old fingerprint to the
new one. Detokenisation reads `encrypted_pan`, `iv`, and `auth_tag` — it **never reads
`pan_hash`**.

```
HMAC rotation batch:    updating pan_hash values for existing vault rows
Detokenisation:         reading encrypted_pan, iv, auth_tag → unaffected

Any token at any point during the HMAC batch:
  vault.keyVersionId → DEK version (unchanged) → in ring → decryption works ✓
  HMAC ring not consulted at any step
```

**Detokenisation is completely unaffected by HMAC rotation.**

The only thing affected during the HMAC rotation batch window is **new tokenisation dedup**:
`TokenisationService` uses dual-lookup (new hash first, old hash fallback) to prevent duplicate
tokens while the batch is in progress.

---

## 6. Detokenisation During Emergency Rotation

When an emergency rotation is triggered (DEK suspected compromised), the old DEK moves to
`COMPROMISED` immediately and synchronously in `InMemoryDekKeyRing`. This is the most sensitive
scenario.

```
                           │ emergency rotation triggered │ batch complete │
                           ▼                              ▼
DEK status:   ACTIVE ──── COMPROMISED ────────────────── RETIRED

Detokenisation of token on COMPROMISED DEK:
  vault.keyVersionId → old DEK (COMPROMISED) → in ring, but status = COMPROMISED
  → BLOCKED: application throws; HTTP 500 returned to caller
  → TAMPER_ALERT written to audit log

Reason: if the DEK was compromised, associated PANs may have been exposed.
        Silently returning decrypted PANs is not acceptable.

After batch completes (all tokens re-encrypted under new DEK):
  vault.keyVersionId now points to new ACTIVE DEK
  Detokenisation resumes normally for all tokens
```

The block window (from `COMPROMISED` until batch completion) is an **explicit security design
decision**, not a bug. The length of this window depends on vault size and batch throughput.

---

## 7. DEK Rotation Flow

**Trigger:** `POST /api/v1/admin/keys/rotate { reason, newKeyAlias }`  
**KMS calls:** 1 at initiation (`GenerateDataKey`), 0 during batch

```
── SYNCHRONOUS (completes before 202 Accepted returns) ──────────────────────────────────

  1. dataKey = kmsProvider.generateDataKey()        ← 1 KMS call (GenerateDataKey)
     → dataKey.plaintextDek   (32 bytes, use immediately)
     → dataKey.encryptedDekBlob (raw BYTEA, store in DB)
  2. UPDATE old key_versions row → status=ROTATING
  3. INSERT key_versions row (encrypted_dek_blob, key_type=DEK, status=ACTIVE) → v2
  4. dekRing.load(v2, plaintextDek, rotateBy)
     dekRing.promoteActive(v2)
     zero(plaintextDek)
  → New tokenisations immediately encrypt PANs with new DEK
  → HMAC rows: UNTOUCHED

── ASYNC BATCH (RotationJob cron, every 15 minutes) ────────────────────────────────────

  For each token_vault record still referencing old DEK version (v1):
    old_dek   = dekRing.getByVersion(v1).copyDek()        in-memory, 0 KMS calls
    new_dek   = dekRing.getByVersion(v2).copyDek()        in-memory, 0 KMS calls
    pan_bytes = AES-GCM.decrypt(encrypted_pan, old_dek, iv, auth_tag)
    result    = AES-GCM.encrypt(pan_bytes, new_dek)       ← fresh IV generated
    zero(old_dek, new_dek, pan_bytes)
    UPDATE token_vault SET
        encrypted_pan  = result.ciphertext(),
        iv             = result.iv(),
        auth_tag       = result.authTag(),
        key_version_id = v2
    Audit: TOKEN_REENCRYPTED

── CUTOVER (RotationJob, when all tokens migrated) ─────────────────────────────────────

  UPDATE key_versions SET status=RETIRED for old DEK row (v1)
  dekRing.retire(v1)
  Log KEY_ROTATION_COMPLETED audit event
```

**Key properties:**
- Only 1 KMS call total (at initiation — `GenerateDataKey`)
- Zero KMS calls during the batch — all re-encryption is pure in-memory AES-GCM
- Each token gets a fresh random IV on re-encryption
- HMAC secret completely unaffected — it is protected directly by the CMK
- No downtime — detokenisation works throughout (see §4)

---

## 8. HMAC Rotation Flow

**Trigger:** `POST /api/v1/admin/hmac-keys/rotate { newKeyAlias }`  
**KMS calls:** 1 at initiation, 0 during batch

```
── SYNCHRONOUS (completes before 202 Accepted returns) ──────────────────────────────────

  1. SecureRandom(32) → newHmacBytes                  in-process
  2. kms.encrypt(newHmacBytes, ctx=hmac-key)          ← 1 KMS call
     → encryptedHmacBlob stored in key_versions.encrypted_secret
  3. UPDATE old key_versions HMAC row → status=ROTATING
  4. INSERT key_versions row (key_type=HMAC, status=ACTIVE)
  5. hmacRing.load(newVersionId, newHmacBytes); hmacRing.promoteActive(...)
     zero(newHmacBytes)
  → New tokenisations immediately hash with new HMAC secret
  → DEK rows: UNTOUCHED

── ASYNC BATCH (HmacRotationJob cron, nightly) ─────────────────────────────────────────

  Dual-lookup active during this window:
    TokenisationService tries newPanHash first, falls back to oldPanHash
    (prevents duplicate tokens while batch is in progress)

  For each token_vault record still referencing old HMAC version:
    dek       = dekRing.getByVersion(token.keyVersionId).copyDek()   in-memory, 0 KMS calls
    pan_bytes = AES-GCM.decrypt(encrypted_pan, dek, iv, auth_tag)   in-memory → PAN briefly in RAM
    newPanHash = HMAC-SHA256(pan_bytes, newHmacSecret)               in-memory
    zero(dek, pan_bytes)
    UPDATE token_vault SET pan_hash = newPanHash, hmac_key_version_id = newHmacVersionId
    Audit: PAN_HASH_RECOMPUTED

── CUTOVER (HmacRotationJob, when all tokens migrated) ─────────────────────────────────

  UPDATE key_versions SET status=RETIRED for old HMAC row
  hmacRing.retire(oldVersionId)
  Log HMAC_ROTATION_COMPLETED audit event
```

**Key properties:**
- Only 1 KMS call total (at initiation)
- The re-hash batch must briefly decrypt each PAN (most sensitive batch in the system) — runs
  nightly off-peak with limited parallelism
- DEK rotation completely independent — HMAC and DEK rotate on separate schedules
- Detokenisation completely unaffected (never reads `pan_hash`) — see §5

---

## 9. AWS CMK Auto-Rotation

AWS KMS can be configured to rotate the CMK's backing key material annually.

```
What AWS does:
  1. Creates new backing key material inside AWS HSM
  2. Leaves existing ciphertexts (our key_versions rows) completely unchanged
  3. Keeps old backing key permanently — existing blobs remain decryptable forever
  4. Future kms.encrypt() / kms.generateDataKey() calls use the new backing material

Effect on our running application:   NONE
Effect on our next startup:           NONE (kms.decrypt still works on existing blobs)
Effect on seeding a new environment:  New environment's DEK/HMAC blobs use newer CMK material
                                      (transparent — code is identical)
```

**Our application is completely unaware of CMK auto-rotation.** No code runs, no restarts are
needed, no `key_versions` rows change. The blobs we store remain decryptable because AWS keeps
all historical backing keys.

This is sometimes called "key rotation at the envelope level" — it re-protects the wrapper
(encrypted DEK blob and HMAC blob) without touching the vault rows at all.

---

## 10. KMS Call Cost Summary

| Operation | KMS calls | Notes |
|---|---|---|
| Application startup (normal) | **2** | 1 to decrypt ACTIVE DEK blob, 1 to decrypt ACTIVE HMAC blob |
| Application startup (mid-rotation) | **3** | +1 for ROTATING DEK blob |
| Tokenise | **0** | DEK from ring; all crypto in-process |
| Detokenise | **0** | DEK from ring; HMAC ring not consulted |
| DEK rotation (initiation) | **1** | `GenerateDataKey` — returns plaintext + encrypted blob in one call |
| DEK rotation (batch, per token) | **0** | PAN re-encryption with in-memory DEK |
| HMAC rotation (initiation) | **1** | `KMS.Encrypt(newHmacBytes, ctx=hmac-key)` |
| HMAC rotation (batch, per token) | **0** | PAN decrypt + re-hash in-process |
| AWS CMK auto-rotation | **0** | Entirely inside AWS — application unaware |
| Emergency rotation (initiation) | **1** | `GenerateDataKey` — same as scheduled |
| Emergency rotation (batch, per token) | **0** | PAN re-encryption with in-memory DEK |

**The design goal is to make KMS calls proportional to the number of *key events*, not the
number of *token operations*.** Regardless of vault size (millions of tokens), startup costs 2
KMS calls and each rotation initiation costs 1. All per-token operations are pure in-process
AES-GCM with zero KMS involvement.
