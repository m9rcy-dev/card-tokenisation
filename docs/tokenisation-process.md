# Card Tokenisation System — Process Reference

This document is a self-contained reference for anyone who needs to understand how the
tokenisation system works end-to-end. It covers the mental model (key concepts and acronyms),
all operational flows, and the KMS call cost of each operation.

---

## Table of Contents

1. [Mental Model and Glossary](#1-mental-model-and-glossary)
2. [Tokenisation Flow](#2-tokenisation-flow)
3. [Detokenisation Flow](#3-detokenisation-flow)
4. [Detokenisation During KEK Rotation](#4-detokenisation-during-kek-rotation)
5. [Detokenisation During HMAC Rotation](#5-detokenisation-during-hmac-rotation)
6. [Detokenisation During Emergency Rotation (COMPROMISED KEK)](#6-detokenisation-during-emergency-rotation)
7. [KEK Rotation Flow](#7-kek-rotation-flow)
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

A unique 32-byte AES key used to encrypt one PAN. Every token has its own DEK — if one DEK
is compromised, only that one PAN is exposed.

DEKs are **never stored in plaintext**. They are always wrapped (encrypted) by a KEK.

*Analogy: a DEK is a house key. It unlocks one house (one PAN). You don't keep house keys lying
around — you store them locked in a safe (encrypted by the KEK).*

### KEK (Key Encryption Key)

A 32-byte AES key that encrypts all the DEKs. There is one active KEK per rotation cycle.
At startup, the application asks KMS to decrypt the KEK blob and holds the result in RAM (the
Key Ring). The KEK itself is never stored in plaintext in the database.

*Analogy: the combination to the safe that holds all the house keys. We ask KMS to use this
combination to lock/unlock a house key, but the combination never leaves KMS.*

### KMS (Key Management Service)

A secure external service (e.g. AWS KMS, or the local-dev in-process adapter) that stores and
manages the CMK. The application asks KMS to encrypt or decrypt using a key reference (an ARN) —
the raw CMK bytes never leave the HSM.

### CMK (Customer Master Key)

The master key inside KMS. This is the root of the key hierarchy. The application has one CMK
(symmetric, encrypt/decrypt). It is used directly to protect both the KEK blob and the HMAC
blob using distinct encryption contexts.

### Encryption Context

A `Map<String, String>` passed in `kms.encrypt()` and `kms.decrypt()` API calls. AWS binds it
cryptographically to the ciphertext — a blob encrypted with one context cannot be decrypted with
a different context. Values appear in CloudTrail as audit metadata (not secret).

This system uses:
- `purpose=kek-unwrap` — for KEK ciphertext blobs
- `purpose=hmac-key` — for HMAC secret ciphertext blobs

### Envelope Encryption

The technique of encrypting data with a DEK, then encrypting the DEK with a KEK. To decrypt:

1. Use KMS to decrypt the encrypted KEK blob → plaintext KEK (one KMS call, done at startup)
2. Use the in-memory KEK to decrypt the encrypted DEK → plaintext DEK (AES-GCM, in-process)
3. Use the plaintext DEK to decrypt the encrypted PAN → plaintext PAN (AES-GCM, in-process)
4. Zero out the DEK bytes from memory immediately

The data and its DEK travel together in the vault; the KEK that locks the DEK lives in KMS.

### IV (Initialization Vector)

A 12-byte random value prepended to each AES-GCM ciphertext. It makes each encryption unique
even when the same key and plaintext are encrypted twice. Generated fresh for every encrypt call.

### Auth Tag (Authentication Tag)

A 16-byte value appended by AES-GCM encryption that proves the ciphertext has not been tampered
with. On decryption, if even one bit of the ciphertext was changed, the authentication check
fails — the decryption itself detects tampering. This is the "GCM" in AES-256-GCM.

### HMAC (Hash-based Message Authentication Code)

A keyed one-way hash function. Used in this system to compute a **PAN fingerprint**
(`pan_hash`) for deduplication. When the same PAN is submitted for tokenisation again, the
system hashes it with the current HMAC secret and looks up `pan_hash` to find the existing
token — avoiding duplicate vault rows.

The HMAC secret is never used to recover a PAN — it is a one-way operation. If the secret
were leaked, an attacker could enumerate known PANs and check which ones match stored hashes,
but they could **not** reverse the hash to extract PANs. The risk is **cardholder linkability**,
not PAN exposure.

### Key Ring

The in-memory store of decrypted key material. At startup, the application asks KMS to decrypt
the active KEK blob and the active HMAC blob, and holds the raw bytes in RAM. This means KMS
is only called at startup — not on every tokenisation or detokenisation request.

The ring also holds ROTATING keys (during a rotation batch) so that tokens encrypted under the
old key remain readable while the batch migrates them to the new key.

---

## 2. Tokenisation Flow

**Trigger:** `POST /api/v1/tokens { pan, merchantId, tokenType }`  
**KMS calls:** 0 (KEK and HMAC secret already in ring from startup)

```
Client                    Application                           PostgreSQL
  │                            │                                    │
  │── POST /api/v1/tokens ────▶│                                    │
  │                            │                                    │
  │                            │  1. Generate DEK: SecureRandom(32) bytes   (in-process)
  │                            │  2. Encrypt PAN:  AES-GCM(PAN, DEK, IV)   (in-process)
  │                            │                   → encrypted_pan, authTag
  │                            │  3. Wrap DEK:     AES-GCM(DEK, inMemoryKEK) (in-process)
  │                            │                   → encrypted_dek
  │                            │  4. Zero DEK bytes from memory
  │                            │  5. Hash PAN:     HMAC-SHA256(PAN, inMemoryHmacSecret)
  │                            │                   → pan_hash
  │                            │  6. Dedup check:  SELECT WHERE pan_hash = ?  ──────────▶│
  │                            │◀─────────────────────── existing row or empty ───────────│
  │                            │                                    │
  │                            │  7a. If existing: return existing token (no INSERT)
  │                            │  7b. If new:      generate token UUID
  │                            │                   INSERT token_vault ──────────────────▶│
  │                            │                   (token, encrypted_pan, authTag,        │
  │                            │                    encrypted_dek, keyVersionId,          │
  │                            │                    pan_hash, hmac_key_version_id)        │
  │                            │                   INSERT token_audit_log ───────────────▶│
  │                            │                                    │
  │◀── { token, lastFour } ────│                                    │
```

**Key points:**
- The plaintext DEK exists in RAM for milliseconds — zeroed immediately after step 4
- `pan_hash` is used **only** for deduplication; it is never used to recover the PAN
- The PAN never touches the database in plaintext, not even temporarily
- One-time tokens always create a new vault row regardless of `pan_hash`
- Recurring tokens check `pan_hash` first and return the existing token if found

---

## 3. Detokenisation Flow

**Trigger:** `GET /api/v1/tokens/{token}` with `X-Merchant-ID` header  
**KMS calls:** 0 (KEK already in ring from startup)

```
Client                    Application                           PostgreSQL
  │                            │                                    │
  │── GET /api/v1/tokens/T ───▶│                                    │
  │   X-Merchant-ID: M         │                                    │
  │                            │  1. SELECT token_vault WHERE token = T ──────▶│
  │                            │◀────── encrypted_pan, encrypted_dek,           │
  │                            │        authTag, keyVersionId, merchantId ───────│
  │                            │                                    │
  │                            │  2. Verify merchantId == M (scope check)
  │                            │  3. kek = keyRing.getByVersion(keyVersionId)
  │                            │     (in-memory — no KMS call)
  │                            │  4. Check kek.status ≠ COMPROMISED
  │                            │  5. dek = AES-GCM.decrypt(encrypted_dek, kek)
  │                            │  6. pan = AES-GCM.decrypt(encrypted_pan, dek, authTag)
  │                            │     (auth tag checked here — detects tampering)
  │                            │  7. Zero dek bytes from memory
  │                            │  8. INSERT token_audit_log ─────────────────────▶│
  │                            │                                    │
  │◀── { pan, lastFour } ──────│                                    │
```

**Key points:**
- HMAC key is **never consulted** during detokenisation — it is only used for tokenisation dedup
- Zero KMS calls — the KEK was decrypted once at startup and held in the Key Ring
- AES-GCM auth tag check (step 6) implicitly detects any database-level tampering with
  `encrypted_pan` or `encrypted_dek`
- Step 4 (COMPROMISED check) only matters during an emergency rotation — see §6

---

## 4. Detokenisation During KEK Rotation

When a scheduled KEK rotation is initiated, the old KEK moves from `ACTIVE` → `ROTATING`
synchronously, before the batch starts. The Key Ring keeps both the ROTATING and ACTIVE keys
loaded simultaneously.

```
                           │ rotation initiated │ completeRotation() │
                           ▼                   ▼
KEK status:   ACTIVE ──── ROTATING ──────────── RETIRED

Tokens on old KEK:  ENCRYP_DEK uses oldKek         ← being migrated by batch
Tokens on new KEK:  ENCRYP_DEK uses newKek         ← available immediately

Detokenisation of old-KEK token:
  vault.keyVersionId → old KEK (ROTATING) → still in ring ✓ → works normally

Detokenisation of new-KEK token:
  vault.keyVersionId → new KEK (ACTIVE)   → in ring        ✓ → works normally

After completeRotation() (batch complete, old KEK → RETIRED):
  old KEK evicted from ring; all vault rows now point to new KEK
  Detokenisation: works normally for all tokens
```

**There is no window where detokenisation fails during a scheduled KEK rotation.**

---

## 5. Detokenisation During HMAC Rotation

HMAC rotation runs a batch that updates `token_vault.pan_hash` from the old fingerprint to the
new one. Detokenisation reads `encrypted_dek` and `encrypted_pan` — it **never reads `pan_hash`**.

```
HMAC rotation batch:    updating pan_hash values for existing vault rows
Detokenisation:         reading encrypted_dek and encrypted_pan → unaffected

Any token at any point during the HMAC batch:
  vault.keyVersionId → KEK version (unchanged) → in ring → decryption works ✓
  HMAC ring not consulted at any step
```

**Detokenisation is completely unaffected by HMAC rotation.**

The only thing affected during the HMAC rotation batch window is **new tokenisation dedup**:
`TokenisationService` uses dual-lookup (new hash first, old hash fallback) to prevent duplicate
tokens while the batch is in progress.

---

## 6. Detokenisation During Emergency Rotation

When an emergency rotation is triggered (KEK suspected compromised), the old KEK moves to
`COMPROMISED` immediately and synchronously. This is the most sensitive scenario.

```
                           │ emergency rotation triggered │ batch complete │
                           ▼                              ▼
KEK status:   ACTIVE ──── COMPROMISED ────────────────── RETIRED

Detokenisation of token on COMPROMISED KEK:
  vault.keyVersionId → old KEK (COMPROMISED) → in ring, but status = COMPROMISED
  → BLOCKED: application throws; HTTP 500 returned to caller
  → TAMPER_ALERT written to audit log

Reason: if the KEK was compromised, associated PANs may have been exposed.
        Silently returning decrypted PANs is not acceptable.

After batch completes (all tokens migrated to new KEK):
  vault.keyVersionId now points to new ACTIVE KEK
  Detokenisation resumes normally for all tokens
```

The block window (from `COMPROMISED` until batch completion) is an **explicit security design
decision**, not a bug. The length of this window depends on vault size and batch throughput.

---

## 7. KEK Rotation Flow

**Trigger:** `POST /api/v1/admin/keys/rotate { reason, newKeyAlias }`  
**KMS calls:** 1 at initiation, 0 during batch

```
── SYNCHRONOUS (completes before 202 Accepted returns) ──────────────────────────────────

  1. SecureRandom(32) → newKekBytes                   in-process
  2. kms.encrypt(newKekBytes, ctx=kek-unwrap)         ← 1 KMS call
     → encryptedKekBlob stored in key_versions
  3. INSERT key_versions row (key_type=KEK, status=ACTIVE)
  4. UPDATE old key_versions row → status=ROTATING
  5. Load newKek into InMemoryKekKeyRing, promote as active
  → New tokenisations immediately use new KEK for DEK wrapping
  → HMAC rows: UNTOUCHED

── ASYNC BATCH (RotationJob cron, every 15 minutes) ────────────────────────────────────

  For each token_vault record still referencing old KEK version:
    dek  = AES-GCM.decrypt(encrypted_dek, oldKek)     in-memory, 0 KMS calls
    dek2 = AES-GCM.encrypt(dek, newKek)               in-memory, 0 KMS calls
    UPDATE token_vault SET encrypted_dek = dek2, key_version_id = newKekVersionId
    Zero dek bytes

── CUTOVER (RotationJob, when all tokens migrated) ─────────────────────────────────────

  UPDATE key_versions SET status=RETIRED for old KEK row
  Evict old KEK from InMemoryKekKeyRing
  Log KEY_ROTATION_COMPLETED audit event
```

**Key properties:**
- Only 1 KMS call total (at initiation)
- Zero KMS calls during the batch — all DEK re-wraps are pure in-memory AES-GCM
- HMAC secret completely unaffected — it is protected directly by the CMK, not by the KEK
- No downtime — detokenisation works throughout (see §4)

---

## 8. HMAC Rotation Flow

**Trigger:** `POST /api/v1/admin/hmac-keys/rotate { newKeyAlias }`  
**KMS calls:** 1 at initiation, 0 during batch

```
── SYNCHRONOUS (completes before 202 Accepted returns) ──────────────────────────────────

  1. SecureRandom(32) → newHmacBytes                  in-process
  2. kms.encrypt(newHmacBytes, ctx=hmac-key)          ← 1 KMS call
     → encryptedHmacBlob stored in key_versions
  3. INSERT key_versions row (key_type=HMAC, status=ACTIVE)
  4. UPDATE old key_versions row → status=ROTATING
  5. Load newHmac into InMemoryHmacKeyRing, promote as active
  → New tokenisations immediately hash with new HMAC secret
  → KEK rows: UNTOUCHED

── ASYNC BATCH (HmacRotationJob cron, nightly) ─────────────────────────────────────────

  Dual-lookup active during this window:
    TokenisationService tries newPanHash first, falls back to oldPanHash
    (prevents duplicate tokens while batch is in progress)

  For each token_vault record still referencing old HMAC version:
    kek = keyRing.getActive()                         in-memory
    dek = AES-GCM.decrypt(encrypted_dek, kek)        in-memory, 0 KMS calls
    pan = AES-GCM.decrypt(encrypted_pan, dek)        in-memory → PAN briefly in RAM
    newPanHash = HMAC-SHA256(pan, newHmacSecret)     in-memory
    Zero dek and pan bytes
    UPDATE token_vault SET pan_hash = newPanHash, hmac_key_version_id = newHmacVersionId

── CUTOVER (HmacRotationJob, when all tokens migrated) ─────────────────────────────────

  UPDATE key_versions SET status=RETIRED for old HMAC row
  Evict old HMAC secret from InMemoryHmacKeyRing
  Log HMAC_ROTATION_COMPLETED audit event
```

**Key properties:**
- Only 1 KMS call total (at initiation)
- The re-hash batch must briefly decrypt each PAN (most sensitive batch in the system) — runs
  nightly off-peak
- KEK completely unaffected — HMAC and KEK rotate independently
- Detokenisation completely unaffected (never reads `pan_hash`) — see §5

---

## 9. AWS CMK Auto-Rotation

AWS KMS can be configured to rotate the CMK's backing key material annually.

```
What AWS does:
  1. Creates new backing key material inside AWS HSM
  2. Leaves existing ciphertexts (our key_versions rows) completely unchanged
  3. Keeps old backing key permanently — existing blobs remain decryptable forever
  4. Future kms.encrypt() calls use the new backing material

Effect on our running application:  NONE
Effect on our next startup:          NONE (kms.decrypt still works on existing blobs)
Effect on seeding a new environment: New environment's KEK/HMAC blobs use newer CMK material
                                     (transparent — code is identical)
```

**Our application is completely unaware of CMK auto-rotation.** No code runs, no restarts are
needed, no key_versions rows change. The blobs we store remain decryptable because AWS keeps all
historical backing keys.

This is sometimes called "key rotation at the envelope level" — it re-protects the wrapper of
the wrapper, not the key material (DEK, KEK, HMAC secret) we generate ourselves.

---

## 10. KMS Call Cost Summary

| Operation | KMS calls | Notes |
|---|---|---|
| Application startup | **2** | 1 to decrypt KEK blob, 1 to decrypt HMAC blob |
| Tokenise (recurring) | **0** | All crypto in-process using ring |
| Tokenise (one-time) | **0** | All crypto in-process using ring |
| Detokenise | **0** | KEK from ring; HMAC ring not consulted |
| KEK rotation (initiation) | **1** | Encrypt new KEK bytes |
| KEK rotation (batch, per token) | **0** | AES-GCM DEK re-wrap in-process |
| HMAC rotation (initiation) | **1** | Encrypt new HMAC bytes |
| HMAC rotation (batch, per token) | **0** | PAN decrypt + re-hash in-process |
| AWS CMK auto-rotation | **0** | Entirely inside AWS — application unaware |
| Emergency rotation (initiation) | **1** | Encrypt new KEK bytes |
| Emergency rotation (batch, per token) | **0** | AES-GCM DEK re-wrap in-process |

**The design goal is to make KMS calls proportional to the number of *key events*, not the number
of *token operations*.** Regardless of vault size (millions of tokens), startup costs 2 KMS calls
and each rotation costs 1. All per-token operations are pure in-process AES-GCM.
