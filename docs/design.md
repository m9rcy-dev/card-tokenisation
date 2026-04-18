# Design Document — Card Tokenisation System

This document explains how the card tokenisation system works, why it was built this way, and what all the technical terms mean in plain language.

---

## Table of Contents

1. [What is card tokenisation and why do we need it?](#1-what-is-card-tokenisation-and-why-do-we-need-it)
2. [The two big problems: confidentiality and key management](#2-the-two-big-problems-confidentiality-and-key-management)
3. [Plain-language glossary (DEK, KEK, KMS, and more)](#3-plain-language-glossary)
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
- Each PAN encrypted with a unique key (so compromising one key doesn't expose all PANs).
- The keys themselves stored encrypted (so a DB breach doesn't expose the keys).
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
The unique encryption key used to encrypt one PAN. Every token has its own DEK — if one DEK is compromised, only that one PAN is exposed. DEKs are **never stored in plaintext**; they are always wrapped (encrypted) by a KEK.

Think of a DEK as a house key. It unlocks one house (one PAN). You don't keep house keys lying around — you keep them in a safe (wrapped by the KEK).

### KEK (Key Encryption Key)
The master key that encrypts all the DEKs. There is one active KEK per key rotation cycle. The KEK lives in the KMS (not in the application's memory or the database).

Think of a KEK as the combination to the safe that holds all the house keys. It is managed by the KMS — we ask the KMS to "use this combination to lock/unlock a house key" but the combination itself never leaves the HSM.

### KMS (Key Management Service)
A secure external service (e.g. AWS KMS) that stores and manages KEKs. The application never sees the raw KEK bytes — it asks KMS to perform operations using a key reference (an ARN). AWS KMS uses a Hardware Security Module (HSM) to ensure the raw key bytes never leave secure hardware.

**The contract:** "Give me a new DEK encrypted with key X" (`generateDataKey`) or "Decrypt this DEK using key X" (`decrypt`).

### Envelope Encryption
The technique of encrypting data with a DEK, then encrypting the DEK with a KEK. The encrypted DEK is stored alongside the encrypted data. To decrypt the data:
1. Ask KMS to decrypt the encrypted DEK (yielding the plaintext DEK).
2. Use the plaintext DEK to decrypt the data.
3. Zero out the plaintext DEK from memory immediately after use.

The data and its key travel together, but the key to the key stays in the KMS.

### IV (Initialization Vector)
A random value that makes each encryption unique even when the same key and plaintext are used twice. Without an IV, encrypting the same PAN twice with the same DEK would produce the same ciphertext — an attacker could detect duplicates. With AES-GCM, the IV is 12 bytes, generated fresh for every encryption.

### Auth Tag (Authentication Tag)
A 16-byte value produced by AES-GCM encryption that proves the ciphertext hasn't been tampered with. When decrypting, if even one bit of the ciphertext was changed, AES-GCM's authentication check fails — the decryption operation itself detects tampering. This is the "GCM" part (Galois/Counter Mode).

### HMAC (Hash-based Message Authentication Code)
A way to verify that a piece of data hasn't been changed, using a secret key. Used in this system to detect tampering with rows in the `key_versions` table. If someone changes a key version's status directly in the database (bypassing the application), the HMAC checksum won't match and a `TAMPER_ALERT` is written to the audit log.

### Key Ring
The in-memory store of active KEK material. At startup, the application asks KMS to decrypt the active KEK(s) and holds the result in RAM. This means KMS is only called once at startup (plus periodic refresh), not on every tokenise/detokenise request. This dramatically reduces KMS latency costs and removes a per-request KMS dependency.

---

## 4. How tokenisation works step by step

```
Client                    Application                    KMS            PostgreSQL
  |                           |                            |                |
  |-- POST /api/v1/tokens --> |                            |                |
  |                           |-- generateDataKey(KEK) --> |                |
  |                           |<-- {plaintext DEK,          |                |
  |                           |     encrypted DEK} -------- |                |
  |                           |                            |                |
  |                           | AES-256-GCM encrypt(PAN, IV, plaintext DEK)  |
  |                           | zero out plaintext DEK                       |
  |                           |                            |                |
  |                           |-- INSERT token_vault ---------------------->|
  |                           |   (token, encryptedPan, IV, authTag,        |
  |                           |    encryptedDek, keyVersionId, panHash)      |
  |                           |                            |                |
  |                           |-- INSERT token_audit_log ----------------->|
  |                           |                            |                |
  |<-- {token, lastFour} ---- |                            |                |
```

**Key points:**
- The plaintext DEK exists in RAM only for the duration of the AES-GCM encryption. It is zeroed immediately after.
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
  |                           |    authTag, encryptedDek,  |                  |
  |                           |    keyVersionId, merchantId}                  |
  |                           |                           |                  |
  |                           | verify merchantId == M (scope check)         |
  |                           |                           |                  |
  |                           | kek = keyRing.getByVersion(keyVersionId)     |
  |                           | plainDek = AES-256-GCM unwrap(encryptedDek, kek)
  |                           |                           |                  |
  |                           | pan = AES-256-GCM decrypt(encryptedPan, plainDek, IV, authTag)
  |                           | zero out plainDek         |                  |
  |                           |-- INSERT token_audit_log ----------------->  |
  |                           |                           |                  |
  |<-- {pan, lastFour, ...} --|                           |                  |
```

**Key points:**
- The KEK is already in the key ring (loaded at startup). No KMS call is needed on the hot path.
- The merchant scope check (`merchantId == M`) prevents merchant A from seeing merchant B's tokens.
- If the key version is marked `COMPROMISED` in the ring, the detokenise operation fails immediately with HTTP 500. No decryption is attempted.
- The AES-GCM authentication tag check happens inside `decrypt()`. If the ciphertext was modified in the database, this check fails and a `TAMPER_ALERT` is written.

---

## 6. Key rotation: why and how

### Why rotate?

1. **Compliance:** PCI-DSS requires cryptographic keys to be rotated on a schedule (typically annually). The `rotate_by` column in `key_versions` tracks the compliance deadline.

2. **Compromise:** If a KEK is leaked or the KMS CMK is compromised, any encrypted DEK in the database can be decrypted. Rotation produces a new KEK and re-wraps all DEKs — limiting the exposure window.

### How it works

Rotation only changes the **wrapping of DEKs**, not the encryption of PANs themselves:

```
Before rotation:
  token_vault.encryptedDek = AES-256-GCM(plainDek, oldKEK)

After rotation:
  token_vault.encryptedDek = AES-256-GCM(plainDek, newKEK)
  (same plainDek — the PAN ciphertext is unchanged)
```

This is the `rewrapDek` operation in `KmsProvider`. AWS KMS performs this as a single atomic operation — the plaintext DEK never leaves the HSM.

### The batch process

Rotating 50,000 tokens takes time. The system uses a **non-blocking batch approach**:
- New tokens immediately use the new KEK.
- Old tokens are migrated in batches (default 500 per run, every 15 minutes).
- Old tokens remain readable during migration (the old KEK stays in the key ring as `ROTATING`).
- When the batch count reaches zero, the old key is automatically retired.

### Zero-downtime guarantee

At any point during rotation, a token is either:
- On the old key: decryptable using the `ROTATING` key entry in the ring.
- On the new key: decryptable using the `ACTIVE` key entry in the ring.

Both are in the ring simultaneously. No downtime, no request failures.

---

## 7. Tamper Detection

The `key_versions` table stores the operational state of all KEKs. If an attacker directly modified a row (e.g. marked an old key as `ACTIVE` again to decrypt traffic), the system needs to detect this.

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

The `signingSecret` is separate from the KEK and the PAN hash secret — three different secrets for three different purposes.

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
│  InMemoryKeyRing│   │  LocalDevAdapter │   │  MetricsInterceptor         │
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

- **`key_versions`** — Tracks KEK lifecycle. Rows are never deleted (needed for historical DEK unwrapping of pre-rotation tokens). The `checksum` column enables tamper detection.
- **`token_vault`** — One row per token. Stores the encrypted PAN, DEK, IV, auth tag, and metadata. The `is_active` column allows soft-delete (token deactivation without data loss).
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

A separate `panHashSecret` is used (different from the KEK and tamper detection secret) so that even if the panHash column is leaked, it reveals nothing about the PAN.

### Why `record_version` for optimistic locking?

During batch re-encryption, multiple instances of the application (in a multi-node deployment) might try to process the same token concurrently. The `@Version` column (`record_version`) causes a `ObjectOptimisticLockingFailureException` if two transactions try to update the same row simultaneously. The batch processor catches this and skips the row — it will appear again in the next batch.

---

## 10. Security Decisions and Trade-offs

### Why not store the KEK in the application config?

A config-file KEK is the most common mistake in cryptographic systems. It combines the key and the data in the same security boundary — a single breach gives both. KMS separates them: the encrypted DEKs are in the database, the KEK operations happen in the HSM. An attacker who breaches the database cannot decrypt anything without also breaking KMS.

### Why AES-256-GCM instead of AES-256-CBC?

GCM (Galois/Counter Mode) provides both **encryption** and **authentication** in a single operation. If any byte of the ciphertext is modified, the authentication tag check fails and decryption is rejected. CBC (Cipher Block Chaining) provides encryption only — an attacker can modify ciphertext without detection (CBC bit-flipping attacks). GCM is the current industry standard for authenticated encryption.

### Why unique DEKs per token instead of one DEK per merchant?

With per-merchant DEKs, a breach of one merchant's DEK exposes all that merchant's tokens. With per-token DEKs, a DEK compromise exposes exactly one PAN. The cost: more KMS calls and more storage. The benefit: dramatically reduced breach blast radius.

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
