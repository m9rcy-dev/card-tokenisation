# Design Document — Card Tokenisation System

This document explains how the card tokenisation system works, why it was built this way, and what all the technical terms mean in plain language.

---

## Table of Contents

1. [What is card tokenisation and why do we need it?](#1-what-is-card-tokenisation-and-why-do-we-need-it)
2. [The two big problems: confidentiality and key management](#2-the-two-big-problems-confidentiality-and-key-management)
3. [Plain-language glossary (DEK, KMS, HMAC, and more)](#3-plain-language-glossary)
4. [How tokenisation works step by step](#4-how-tokenisation-works-step-by-step)
5. [How detokenisation works step by step](#5-how-detokenisation-works-step-by-step)
6. [Key rotation: why and how](#6-key-rotation-why-and-how)
7. [Tamper detection: how we know the keys haven't been touched](#7-tamper-detection)
8. [Architecture overview](#8-architecture-overview)
9. [Database design decisions](#9-database-design-decisions)
10. [Security decisions and trade-offs](#10-security-decisions-and-trade-offs)
11. [Why certain technologies were chosen](#11-why-certain-technologies-were-chosen)

---

## 1. What is card tokenisation and why do we need it?

A **Primary Account Number (PAN)** is the 16-digit number embossed on a credit card, like `4111 1111 1111 1111`. Merchants need to remember which card belongs to which customer (e.g. for recurring billing), but storing the raw PAN creates enormous risk — if the merchant's database is breached, all card numbers are exposed.

**Tokenisation** solves this by replacing the PAN with a meaningless substitute (a **token**) that looks like `3a4f9d2e-1b5c-4f8a-a3e7-c6d9f0b2a1e4`. The token can be stored safely — even if a breach occurs, the attacker gets nothing useful. The real PAN is stored encrypted in a separate, hardened vault. Only authorised services with the right encryption key can reverse the process.

**This system is specifically a vault tokenisation system**, not a payment network tokenisation system (like Visa Token Service or Mastercard MDES). It protects PANs between a merchant's systems, not at the point-of-sale.

---

## 2. The two big problems: confidentiality and key management

### Problem 1: Confidentiality

If we just encrypted every PAN with one shared key and stored the key in a config file, a database breach plus config access would expose everything. We need:
- PANs encrypted with a key that is itself managed by the KMS — a database breach alone reveals nothing, because the encrypted DEK blob is useless without a KMS call to unwrap it.
- The DEK never stored in plaintext — it lives only in the in-memory ring, zeroed immediately after each encrypt/decrypt.
- The master key to live somewhere separate from the data — in a Hardware Security Module (HSM) via a Key Management Service.

### Problem 2: Key management

Keys have lifetimes. PCI-DSS requires that cryptographic keys be rotated regularly. When a key is rotated:
- New tokens must use the new key.
- Old tokens must still be readable (they were encrypted with the old key's DEK).
- The old key must eventually be retired once all tokens have been migrated.

This rotation process must happen **without downtime** — customers can't stop making purchases while we rotate keys.

---

## 3. Plain-language glossary

### PAN (Primary Account Number)
The 16-digit card number. The thing we are protecting. It must never appear in logs, error messages, or audit records.

### Token
An opaque, meaningless identifier that replaces the PAN in all systems outside the vault. Looks like a UUID: `3a4f9d2e-1b5c-4f8a-a3e7-c6d9f0b2a1e4`. Safe to store in merchant databases.

### DEK (Data Encryption Key)
A 32-byte AES-256 key used to encrypt PANs. One DEK is active per key rotation cycle — all PANs created during that cycle are encrypted with the same shared DEK. The encrypted DEK blob is stored in `key_versions.encrypted_dek_blob` (protected by KMS); the plaintext DEK lives only in the in-memory `InMemoryDekKeyRing`.

Think of the DEK as the combination to a vault. All the valuables (PANs) from one rotation period are locked with that combination. The combination itself is sealed in an envelope (the encrypted DEK blob) that only KMS can open.

### KMS (Key Management Service)
A secure external service (e.g. AWS KMS) that stores and operates the top-level master key. The application never sees the raw master key bytes — it asks KMS to either **generate a new DEK** (`GenerateDataKey`) or **decrypt an existing DEK blob** (`Decrypt`). AWS KMS uses a Hardware Security Module (HSM) to ensure the master key never leaves secure hardware.

**The contract:** "Generate a fresh DEK and give me both the plaintext and encrypted forms" (`generateDataKey`) or "Decrypt this DEK blob and return the plaintext bytes" (`decryptDataKey`).

### Envelope Encryption (2-layer)
The technique used in this system: KMS generates a DEK and returns both the raw bytes and an encrypted blob. The raw DEK is loaded into the key ring (zeroed from memory after use); the encrypted blob is stored in `key_versions`. To decrypt a PAN:
1. Look up `key_version_id` on the vault row → fetch the encrypted DEK blob from the key ring.
2. The DEK is already in RAM (loaded at startup). Use it to AES-GCM-decrypt the PAN.
3. Zero out the DEK copy immediately after use.

No KMS call is needed on the hot path — the ring holds the plaintext DEK in memory.

### IV (Initialization Vector)
A random value that makes each encryption unique even when the same key and plaintext are used twice. Without an IV, encrypting the same PAN twice with the same DEK would produce the same ciphertext — an attacker could detect duplicates. With AES-GCM, the IV is 12 bytes, generated fresh for every encryption.

### Auth Tag (Authentication Tag)
A 16-byte value produced by AES-GCM encryption that proves the ciphertext hasn't been tampered with. When decrypting, if even one bit of the ciphertext was changed, AES-GCM's authentication check fails — the decryption operation itself detects tampering. This is the "GCM" part (Galois/Counter Mode).

### HMAC (Hash-based Message Authentication Code)
A way to verify that a piece of data hasn't been changed, using a secret key. Used in this system to detect tampering with rows in the `key_versions` table. If someone changes a key version's status directly in the database (bypassing the application), the HMAC checksum won't match and a `TAMPER_ALERT` is written to the audit log.

### Key Ring (`InMemoryDekKeyRing`)
The in-memory store of active DEK material. At startup, the application asks KMS to decrypt the encrypted DEK blob(s) from `key_versions` and holds the plaintext DEK bytes in RAM. This means KMS is only called once at startup (plus periodic refresh), not on every tokenise/detokenise request. This dramatically reduces KMS latency costs and removes a per-request KMS dependency.

---

## 4. How tokenisation works step by step

```
Client                    Application               KMS (via key ring)    PostgreSQL
  |                           |                            |                |
  |-- POST /api/v1/tokens --> |                            |                |
  |                           | dek = dekRing.getActive().copyDek()         |
  |                           | iv  = SecureRandom(12 bytes)                |
  |                           | AES-256-GCM encrypt(PAN, dek, iv)           |
  |                           | zero out dek copy                           |
  |                           |                            |                |
  |                           |-- INSERT token_vault ---------------------->|
  |                           |   (token, encryptedPan, IV, authTag,        |
  |                           |    keyVersionId, panHash)                   |
  |                           |                            |                |
  |                           |-- INSERT token_audit_log ----------------->|
  |                           |                            |                |
  |<-- {token, lastFour} ---- |                            |                |
```

**Key points:**
- No KMS call at tokenise time. The DEK is already in the in-memory ring (loaded at startup).
- A fresh random 12-byte IV is generated per encryption. With a shared DEK, IV uniqueness is critical — reusing an IV with the same key would allow keystream recovery (see §10).
- The DEK copy exists in RAM only for the duration of the AES-GCM encrypt call. It is zeroed immediately after.
- The `panHash` is an HMAC-SHA256 of the PAN stored alongside the token. Used for **deduplication** of RECURRING tokens: "does a token already exist for this PAN + merchant?" Without the hash, we'd have to decrypt every vault row to check.
- The PAN never touches the database in plaintext, even temporarily.
- One-time tokens always create a new vault row. Recurring tokens check the `panHash` first and return the existing token if found.

---

## 5. How detokenisation works step by step

```
Client                    Application              KMS (via key ring)    PostgreSQL
  |                           |                           |                  |
  |-- GET /api/v1/tokens/T    |                           |                  |
  |   X-Merchant-ID: M  ----> |                           |                  |
  |                           |-- SELECT token_vault  ---------------------->|
  |                           |<-- {encryptedPan, IV,      |                  |
  |                           |    authTag, keyVersionId,  |                  |
  |                           |    merchantId}             |                  |
  |                           |                           |                  |
  |                           | verify merchantId == M (scope check)         |
  |                           |                           |                  |
  |                           | dek = dekRing.getByVersion(keyVersionId).copyDek()
  |                           | pan = AES-256-GCM decrypt(encryptedPan, dek, IV, authTag)
  |                           | zero out dek copy         |                  |
  |                           |-- INSERT token_audit_log ----------------->  |
  |                           |                           |                  |
  |<-- {pan, lastFour, ...} --|                           |                  |
```

**Key points:**
- The DEK is already in the key ring (loaded at startup). No KMS call is needed on the hot path.
- There is no per-record DEK to unwrap — the ring holds the shared DEK directly, keyed by `keyVersionId`.
- The merchant scope check (`merchantId == M`) prevents merchant A from seeing merchant B's tokens.
- If the key version is marked `COMPROMISED` in the ring, the detokenise operation fails immediately with HTTP 500. No decryption is attempted.
- The AES-GCM authentication tag check happens inside `decrypt()`. If the ciphertext was modified in the database, this check fails and a `TAMPER_ALERT` is written.

---

## 6. Key rotation: why and how

### Why rotate?

1. **Compliance:** PCI-DSS requires cryptographic keys to be rotated on a schedule (typically annually). The `rotate_by` column in `key_versions` tracks the compliance deadline.

2. **Compromise:** If a DEK is leaked, all PANs encrypted under that key version are potentially exposed. Rotation produces a new DEK and re-encrypts all PANs under it — limiting the exposure window to the current rotation period.

### How it works

Rotation **re-encrypts PANs under the new DEK**. Unlike the old 3-layer design (which only re-wrapped a per-record DEK blob), rotation now briefly decrypts each PAN into memory, re-encrypts it with the new DEK and a fresh IV, then zeros the plaintext immediately.

```
Before rotation:
  token_vault: (encryptedPan, iv, authTag) = AES-GCM(PAN, oldDek, oldIv)

After rotation:
  token_vault: (encryptedPan, iv, authTag) = AES-GCM(PAN, newDek, freshIv)
  (PAN is re-encrypted — ciphertext, IV, and auth tag all change)
```

KMS is called only at rotation initiation — once to generate the new DEK (`GenerateDataKey`) and once to decrypt it into the ring (`Decrypt`). The per-token re-encryption is pure in-process AES-GCM with no KMS calls.

### The batch process

Rotating 50,000 tokens takes time. The system uses a **non-blocking batch approach**:
- New tokens immediately use the new DEK.
- Old tokens are re-encrypted in batches (default 500 per run, every 15 minutes).
- Old tokens remain readable during migration (the old DEK stays in the ring as `ROTATING`).
- When the batch count reaches zero, the old key is automatically retired.

### Zero-downtime guarantee

At any point during rotation, a token is either:
- On the old DEK: decryptable using the `ROTATING` key entry in the ring.
- On the new DEK: decryptable using the `ACTIVE` key entry in the ring.

Both are in the ring simultaneously. No downtime, no request failures.

---

## 7. Tamper Detection

The `key_versions` table stores the operational state of all DEKs and HMAC keys. If an attacker directly modified a row (e.g. marked an old key as `ACTIVE` again to decrypt traffic), the system needs to detect this.

### How it works

When a key version is created or transitioned, an **HMAC-SHA256 checksum** is computed over its immutable fields:
```
checksum = HMAC-SHA256(id + kmsKeyId + status + activatedAt, signingSecret)
```

The checksum is stored in `key_versions.checksum`. Before performing sensitive operations (rotation initiation, key cutover), the application recomputes the checksum and compares it with the stored value using **constant-time comparison** (to prevent timing attacks).

A mismatch means:
1. A `TAMPER_ALERT` audit event is written immediately.
2. A `KeyIntegrityException` is thrown, blocking the operation.
3. The key version should be treated as compromised.

The `signingSecret` is separate from the DEK and the PAN hash secret — three different secrets for three different purposes.

---

## 8. Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────────┐
│                              REST Layer                                   │
│  POST /api/v1/tokens        GET /api/v1/tokens/{token}                   │
│  POST /api/v1/admin/keys/rotate                                           │
│  GET  /api/v1/health        GET /api/v1/metrics                          │
└───────────────────────────────┬──────────────────────────────────────────┘
                                 │
┌───────────────────────────────▼──────────────────────────────────────────┐
│                           Service Layer                                   │
│  TokenisationService         DetokenisationService                        │
│  KeyRotationService          RotationBatchProcessor                       │
└───────────────────────────────┬──────────────────────────────────────────┘
                                 │
         ┌──────────────────────┼───────────────────────────┐
         ▼                      ▼                           ▼
┌─────────────────┐   ┌──────────────────┐   ┌─────────────────────────────┐
│   Crypto Layer  │   │   KMS Layer      │   │   Monitoring Layer          │
│  AesGcmCipher   │   │  KmsProvider     │   │  HealthService              │
│  PanHasher      │   │  AwsKmsAdapter   │   │  MetricsCollector           │
│  InMemoryDekKeyRing│   │  LocalDevAdapter │   │  MetricsInterceptor         │
│  TamperDetector │   │                  │   │                             │
└────────┬────────┘   └────────┬─────────┘   └─────────────────────────────┘
         │                     │
         ▼                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      PostgreSQL (via JPA + Flyway)                       │
│  key_versions   token_vault   token_audit_log                            │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 9. Database Design Decisions

### Why three tables?

- **`key_versions`** — Tracks DEK lifecycle. Rows are never deleted (the ring needs the ROTATING entry to decrypt old tokens until they are all re-encrypted). The `checksum` column enables tamper detection.
- **`token_vault`** — One row per token. Stores the encrypted PAN, IV, auth tag, and a `key_version_id` reference — no per-record DEK blob. The shared DEK is resolved at runtime from `InMemoryDekKeyRing` keyed by `key_version_id`. The `is_active` column allows soft-delete (token deactivation without data loss).
- **`token_audit_log`** — Append-only audit trail. The DB role is restricted to INSERT + SELECT — no UPDATE or DELETE. This provides an independent integrity guarantee: even if the application is compromised, a written audit event cannot be erased.

### Why a partial unique index for the active key?

```sql
CREATE UNIQUE INDEX idx_key_versions_single_active
  ON key_versions(status)
  WHERE status = 'ACTIVE';
```

This ensures that at most one key version can have `status = 'ACTIVE'` at any time — enforced at the database level, not just the application level. This prevents accidental dual-activation that would break the "which key do I use to tokenise?" question.

### Why `panHash` and not a plain equality check?

To deduplicate RECURRING tokens ("does this PAN already have a token?"), we need to search by PAN. But the PAN is encrypted — we can't do `WHERE pan = ?`. The `panHash = HMAC-SHA256(pan, panHashSecret)` is a deterministic, irreversible fingerprint. It cannot be reversed to recover the PAN, but it allows fast equality lookups.

A separate `panHashSecret` is used (different from the DEK and tamper detection secret) so that even if the panHash column is leaked, it reveals nothing about the PAN.

### Why `record_version` for optimistic locking?

During batch re-encryption, multiple instances of the application (in a multi-node deployment) might try to process the same token concurrently. The `@Version` column (`record_version`) causes a `ObjectOptimisticLockingFailureException` if two transactions try to update the same row simultaneously. The batch processor catches this and skips the row — it will appear again in the next batch.

---

## 10. Security Decisions and Trade-offs

### Why not store the DEK in the application config?

A config-file key is the most common mistake in cryptographic systems. It combines the key and the data in the same security boundary — a single breach gives both. KMS separates them: the encrypted DEK blob is in the database, the decrypt operation happens in the HSM. An attacker who breaches the database gets only an encrypted blob they cannot open without KMS access.

### Why AES-256-GCM instead of AES-256-CBC?

GCM (Galois/Counter Mode) provides both **encryption** and **authentication** in a single operation. If any byte of the ciphertext is modified, the authentication tag check fails and decryption is rejected. CBC (Cipher Block Chaining) provides encryption only — an attacker can modify ciphertext without detection (CBC bit-flipping attacks). GCM is the current industry standard for authenticated encryption.

### Why a shared DEK per key version instead of per-token DEK?

The previous design used a unique DEK per token (stored as `encrypted_dek` per vault row). This minimised blast radius (one compromised DEK = one PAN exposed) but required KMS to be called on every tokenise operation (to generate a fresh DEK) and stored 60 extra bytes per row.

The current 2-layer design uses a **shared DEK per key version** — all PANs within a rotation period are encrypted with the same DEK. Trade-offs:

| | Per-token DEK (old) | Shared DEK per version (new) |
|--|--|--|
| Blast radius if DEK leaked | 1 PAN | All PANs in that rotation window |
| KMS calls per tokenise | 1 (`GenerateDataKey`) | 0 |
| Storage per token | +60 bytes | None |
| Rotation: what moves | Re-wrap the DEK blob | Re-encrypt the PAN |

The blast radius increase is mitigated by: (a) the DEK never leaving the application process in plaintext, (b) regular rotation limiting the window of exposure, and (c) the auth tag catching any attempt to tamper with stored ciphertexts. The operational and performance gains are significant — KMS is now only involved at startup and rotation initiation.

### Why must each encryption use a fresh IV?

With a shared DEK, reusing an IV is catastrophic. AES-GCM is a stream cipher: `ciphertext = plaintext XOR keystream(key, IV)`. If two PANs are encrypted with the same `(DEK, IV)`, an attacker can XOR the two ciphertexts to recover the XOR of the two PANs. Fresh random 12-byte IVs ensure each `(DEK, IV)` pair is unique across the lifetime of the key.

### Why keep retired keys in the ring?

A token may be detokenised long after it was created. If the key ring evicted retired keys after rotation, those old tokens would become permanently unreadable. Retired keys stay in the ring (but are not available for new wrapping operations) until all tokens that reference them have been re-encrypted.

---

## 11. Why Certain Technologies Were Chosen

| Technology | Why |
|------------|-----|
| **Spring Boot** | Convention over configuration, production-ready ecosystem (security, JPA, scheduling, testing). |
| **PostgreSQL** | ACID transactions, partial unique indexes (for single-ACTIVE enforcement), native UUID support. |
| **Flyway** | Schema migration with version history. Ensures the DB schema is always in sync with the application. |
| **AES-256-GCM** | Authenticated encryption. Both confidentiality and integrity in one operation. NIST-recommended. |
| **Testcontainers** | Tests run against a real PostgreSQL instance (not H2 mock). Catches schema validation errors, constraint violations, and Flyway migration issues that in-memory DBs would miss. |
| **Caffeine** | Fast in-memory rate-limit counters. Lock-free, O(1) reads. Appropriate for single-node deployment. Replace with Redis for multi-node. |
| **Virtual threads (Java 21)** | Load tests use virtual threads for high-concurrency HTTP generation without proportional OS thread cost. |
| **Lombok** | Reduces boilerplate (builders, getters). All Lombok annotations are applied at compile time — no runtime dependency. |
| **SpringDoc/Swagger UI** | Interactive API documentation. OpenAPI 3.0 descriptor at `/v3/api-docs`, Swagger UI at `/swagger-ui.html`. |
