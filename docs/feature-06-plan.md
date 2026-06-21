# Feature 06 — HMAC Key: Direct KMS Protection (Remove KEK Coupling)

## Status: DRAFT — under review, no implementation started

---

## 1. Background and Problem Statement

### What the HMAC key does

Every time a PAN is tokenised, we compute:

```
pan_hash = HMAC-SHA256(PAN, hmacSecret)
```

This hash is stored in `token_vault.pan_hash`. Its sole purpose is **deduplication**: when the same
PAN arrives again, we look up `pan_hash` to find the existing token instead of creating a duplicate.
The HMAC secret is never used to recover a PAN — it is a one-way fingerprint.

Consequence: if the HMAC secret were leaked, an attacker could enumerate known PAN ranges and check
which ones match stored hashes. They could not reverse the hash to extract PANs. The risk is
**cardholder linkability**, not PAN exposure. This is lower severity than a KEK compromise.

### Current key chain

```
AWS KMS CMK
    │
    │  kms.decrypt(encryptedKekBlob)          ← 1 KMS call at startup
    ▼
KEK (32 bytes, in InMemoryKekKeyRing)
    │
    ├──  AES-GCM(DEK, KEK)                    ← wraps each token's DEK (in-process)
    │
    └──  AES-GCM(hmacSecret, KEK)             ← wraps the HMAC secret  ← COUPLING
              │
              ▼
         HMAC secret (32 bytes, in InMemoryHmacKeyRing)
```

The HMAC secret is encrypted **by the KEK, not directly by AWS KMS**. This creates a hidden
dependency:

- When the KEK rotates and the old KEK is retired, the HMAC secret blob (which was encrypted
  under the old KEK) can no longer be loaded at the next restart — the retired KEK is not
  in the ring.
- We had to add `RotationJob.rewrapHmacSecrets()` to re-encrypt HMAC blobs under the new KEK
  before retiring the old one. This is fragile bookkeeping.
- `KeyRingInitialiser` Phase 2 must first load the KEK ring, then look up which KEK version
  encrypted each HMAC row, then decrypt. Two-step dependency just to load the HMAC secret.
- `HmacRotationService.initiateRotation()` touches the KEK ring to encrypt the new HMAC secret.

### Proposed key chain

```
AWS KMS CMK
    │
    ├──  kms.decrypt(encryptedKekBlob)         ← 1 KMS call at startup
    │         │
    │         ▼
    │    KEK (32 bytes, in InMemoryKekKeyRing)
    │         │
    │         └──  AES-GCM(DEK, KEK)          ← wraps each token's DEK (in-process)
    │
    └──  kms.decrypt(encryptedHmacBlob)        ← 1 KMS call at startup (NEW)
              │
              ▼
         HMAC secret (32 bytes, in InMemoryHmacKeyRing)
```

The HMAC secret is encrypted **directly by the CMK** — parallel to how the KEK is protected.
They are independent. Neither depends on the other.

---

## 2. One CMK or Two CMKs?

### Encryption Context — what it is and why the CMK does not change

The flow diagrams below reference `ctx=purpose`. This is **not a property of the KMS key** —
your existing CMK (symmetric, encrypt/decrypt) is exactly correct and requires no changes in the
AWS console.

The encryption context is a **map of key-value pairs you pass in the API call** to `kms.encrypt()`
or `kms.decrypt()`. AWS KMS binds it cryptographically to the ciphertext. Example:

```java
// Wrapping the HMAC secret at seeding / rotation time:
EncryptRequest.builder()
    .keyId(masterKeyArn)                                    // your existing CMK ARN — unchanged
    .plaintext(SdkBytes.fromByteArray(hmacBytes))
    .encryptionContext(Map.of("purpose", "hmac-key"))       // ← this is "ctx=hmac-key"
    .build();

// Loading the HMAC secret at startup:
DecryptRequest.builder()
    .ciphertextBlob(SdkBytes.fromByteArray(storedBlob))
    .keyId(masterKeyArn)
    .encryptionContext(Map.of("purpose", "hmac-key"))       // ← must match exactly
    .build();
```

AWS enforces: a blob encrypted with `purpose=hmac-key` **cannot** be decrypted with
`purpose=kek-unwrap`. This prevents accidental cross-use of blobs sharing the same CMK.
The context values appear in CloudTrail logs as audit metadata — they are not secret.

### Option A — One CMK (chosen)

```
CMK  (one key, two encryption contexts)
  ├── context: purpose=kek-unwrap   →  wraps the KEK
  └── context: purpose=hmac-key    →  wraps the HMAC secret
```

**Pros:** Simpler config (one ARN), cheaper (one CMK = $1/month in AWS), same physical security.
**Cons:** Same IAM policy grants access to both operations; single CMK rotation schedule.

**Current plan assumes Option A (one CMK).** The code change is identical for both options — only
the configuration (`application.yml` and env vars) differs. If two CMKs are preferred later, a
second property `kms.aws.hmac-master-key-arn` can be added to `AwsKmsAdapter` without
restructuring anything else.

---

## 3. What "Rotation" Means at Each Layer

This is the most important conceptual piece to get right before implementation.

### Layer 1 — AWS CMK auto-rotation (annual, automatic)

AWS can be configured to rotate the CMK's own backing key material annually. What this does:

- Creates a new backing key inside AWS's HSM.
- **Does NOT re-encrypt existing ciphertexts.** Our stored KEK blob and HMAC blob remain as-is.
- Old backing key is **kept permanently** so existing blobs remain decryptable forever.
- Future `kms.encrypt()` calls use the newer backing material.

**Effect on our system: zero.** No code runs, no restarts needed.

### Layer 2 — Application KEK rotation (explicit, our API)

Triggered by `POST /api/v1/admin/keys/rotate`.

- Generates new 32-byte KEK locally (`SecureRandom`).
- Calls `kms.encrypt(newKekBytes, context=kek-unwrap)` → stores new blob in `key_versions`. ← 1 KMS call
- Old KEK → `ROTATING`, new KEK → `ACTIVE`, all new tokenisations use new KEK immediately.
- Batch job re-wraps all `token_vault.encrypted_dek` records from old KEK to new KEK (pure
  in-memory AES-GCM, zero KMS calls during the batch).
- **With proposed change:** HMAC blobs are NOT touched during KEK rotation (they are independent).

### Layer 3 — Application HMAC rotation (explicit, our API)

Triggered by `POST /api/v1/admin/hmac-keys/rotate`.

- Generates new 32-byte HMAC secret locally (`SecureRandom`).
- Calls `kms.encrypt(newHmacBytes, context=hmac-key)` → stores new blob in `key_versions`. ← 1 KMS call
- Old HMAC → `ROTATING`, new HMAC → `ACTIVE`, new tokenisations immediately hash with new secret.
- Batch job re-hashes all `token_vault.pan_hash` records (must briefly decrypt each PAN to
  compute the new hash — most sensitive batch in the system).
- **KEK is NOT touched during HMAC rotation** (they are independent).

### Summary table

| Rotation type | Trigger | Re-hashes `pan_hash`? | Re-wraps DEKs? | KMS calls |
|---|---|---|---|---|
| AWS CMK auto (annual) | AWS automatically | No | No | 0 — transparent |
| KEK rotation | Admin API | No | Yes (batch, in-memory) | 1 at initiation |
| HMAC rotation | Admin API | **Yes (batch, needs PAN decrypt)** | No | 1 at initiation |

**Is using AWS KMS for HMAC "real rotation"?**

- CMK auto-rotation (Layer 1) is automatic and free — but it only re-protects the wrapper, not
  the key material inside. The 32-byte HMAC secret itself does not change.
- A genuine HMAC key material rotation (Layer 3) still requires re-hashing all `pan_hash` values.
  There is no way to avoid this — the fingerprints are computed from the secret.
- What we gain from the proposed change: the HMAC key is decoupled from the KEK. Each rotates
  independently. AWS CMK auto-rotation protects both at the same cloud layer.

---

## 4. Flows Across All Environments

### 4.1 Startup — first boot (empty database)

```
Environment:    AWS (real)                LocalStack              Local-dev
                ─────────────────         ─────────────────       ─────────────────

@Order(1)       AwsKeySeeder              AwsKeySeeder            LocalDevKeySeeder
KEK seed:       SecureRandom(32)          SecureRandom(32)        (fixed hex from config)
                kms.encrypt(kekBytes,     kms.encrypt(kekBytes,   AES-GCM(kekBytes, localKey)
                  ctx=kek-unwrap)           ctx=kek-unwrap)
                → encryptedKekBlob        → encryptedKekBlob      → encryptedKekBlob
                INSERT key_versions KEK   INSERT key_versions KEK INSERT key_versions KEK

@Order(1)       AwsKeySeeder              AwsKeySeeder
HMAC seed:      SecureRandom(32)          SecureRandom(32)
                kms.encrypt(hmacBytes,    kms.encrypt(hmacBytes,
                  ctx=hmac-key)             ctx=hmac-key)
                → encryptedHmacBlob       → encryptedHmacBlob
                INSERT key_versions HMAC  INSERT key_versions HMAC
                (encrypting_kek_id=NULL)  (encrypting_kek_id=NULL)

@Order(2)                                                         LocalDevHmacKeySeeder
HMAC seed:                                                        (fixed known secret)
(local-dev)                                                       kms.encrypt(hmacBytes,
                                                                    ctx=hmac-key)  [local AES-GCM]
                                                                  INSERT key_versions HMAC
                                                                  (encrypting_kek_id=NULL)

@Order(10)      KeyRingInitialiser        KeyRingInitialiser      KeyRingInitialiser
Phase 1 — KEK:  kms.decrypt(kekBlob,     kms.decrypt(kekBlob,    localKey.decrypt(kekBlob)
                  ctx=kek-unwrap)           ctx=kek-unwrap)
                → kekBytes in ring        → kekBytes in ring      → kekBytes in ring
                promoteActive(kekId)      promoteActive(kekId)    promoteActive(kekId)

Phase 2 — HMAC: kms.decrypt(hmacBlob,    kms.decrypt(hmacBlob,   localKey.decrypt(hmacBlob)
                  ctx=hmac-key)             ctx=hmac-key)
                → hmacBytes in ring       → hmacBytes in ring     → hmacBytes in ring
                promoteActive(hmacId)     promoteActive(hmacId)   promoteActive(hmacId)
                ← NO KEK lookup           ← NO KEK lookup         ← NO KEK lookup

KMS calls:      2 total                   2 total (LocalStack)    0 (all in-process)
```

### 4.2 Startup — subsequent boots (rows already in database)

Identical to first boot Phase 1 and Phase 2 — seeders skip (idempotent), ring initialiser
loads from DB rows via KMS decrypt. Same KMS call count: 2.

### 4.3 Normal tokenisation (all environments — zero KMS calls)

```
POST /api/v1/tokens  { pan: "5500005555555559" }

Step 1  Generate DEK       SecureRandom(32)                      in-process
Step 2  Encrypt PAN        AES-GCM(PAN, DEK)                     in-process → encrypted_pan
Step 3  Wrap DEK           AES-GCM(DEK, inMemoryKEK)             in-process → encrypted_dek
Step 4  Hash PAN           HMAC-SHA256(PAN, inMemoryHmacSecret)  in-process → pan_hash
Step 5  Dedup check        SELECT WHERE pan_hash = ?             database
Step 6  Store or return    INSERT / SELECT token_vault           database

KMS calls: 0
```

### 4.4 KEK rotation (AWS real-world)

```
Admin: POST /api/v1/admin/keys/rotate { reason: "SCHEDULED", newKeyAlias: "kek-2027-q1" }

── SYNCHRONOUS (completes before 202 Accepted returns) ──────────────────────────────────
  SecureRandom(32) → newKekBytes
  kms.encrypt(newKekBytes, ctx=kek-unwrap)   ← 1 KMS call
  INSERT key_versions (key_type=KEK, status=ACTIVE)
  UPDATE old key_versions row → status=ROTATING
  Load newKek into InMemoryKekKeyRing, promote as active
  New tokenisations immediately use new KEK for DEK wrapping

  HMAC rows in key_versions: UNTOUCHED  ← this is the whole benefit of the change

── ASYNC BATCH (RotationJob cron, every 15 minutes) ────────────────────────────────────
  For each token_vault record still on old KEK:
    AES-GCM.decrypt(encrypted_dek, oldKek)    in-memory, no KMS
    AES-GCM.encrypt(dekBytes, newKek)          in-memory, no KMS
    UPDATE token_vault SET encrypted_dek = ?, key_version_id = ?
    KMS calls per token: 0

── CUTOVER (RotationJob, when countActiveByKeyVersionId = 0) ───────────────────────────
  old key_versions KEK row → status=RETIRED
  old KEK evicted from InMemoryKekKeyRing
  No rewrapHmacSecrets() call  ← removed in this feature
```

### 4.5 HMAC rotation (AWS real-world)

```
Admin: POST /api/v1/admin/hmac-keys/rotate { newKeyAlias: "hmac-2027-q1" }

── SYNCHRONOUS ──────────────────────────────────────────────────────────────────────────
  SecureRandom(32) → newHmacBytes
  kms.encrypt(newHmacBytes, ctx=hmac-key)    ← 1 KMS call
  INSERT key_versions (key_type=HMAC, status=ACTIVE, encrypting_kek_id=NULL)
  UPDATE old HMAC row → status=ROTATING
  Load newHmac into InMemoryHmacKeyRing, promote as active
  New tokenisations immediately use new HMAC for pan_hash

  KEK rows in key_versions: UNTOUCHED

── ASYNC BATCH (HmacRotationJob cron, nightly) ─────────────────────────────────────────
  For each active token_vault record still on old HMAC version:
    AES-GCM.decrypt(encrypted_dek, inMemoryKEK)    in-memory → dekBytes
    AES-GCM.decrypt(encrypted_pan, dekBytes)        in-memory → PAN (briefly in memory)
    HMAC-SHA256(PAN, newHmacSecret)                 in-memory → newPanHash
    UPDATE token_vault SET pan_hash = ?, hmac_key_version_id = ?
    KMS calls per token: 0

  During batch window: TokenisationService dual-lookup
    → try newPanHash first for dedup
    → fall back to oldPanHash if no match found

── CUTOVER (HmacRotationJob, when count on old HMAC version = 0) ───────────────────────
  old key_versions HMAC row → status=RETIRED
  old HMAC secret evicted from InMemoryHmacKeyRing
```

### 4.6 AWS CMK auto-rotation (transparent, no application involvement)

```
AWS fires annual CMK key rotation:

  1. Creates new backing key material inside AWS HSM.
  2. Does NOT re-encrypt our stored blobs (key_versions rows unchanged).
  3. Old backing key kept permanently — existing blobs still decrypt.
  4. Future kms.encrypt() calls use new backing material.

Effect on our running application:  NONE
Effect on next startup:             NONE (kms.decrypt still works on old blobs)
Effect on next seeding (new env):   New blobs protected by newer CMK material
```

### 4.7 Detokenisation — normal path (all environments, zero KMS calls)

```
GET /api/v1/tokens/{token}

Step 1  Look up vault     SELECT token_vault WHERE token = ? AND is_active = true
Step 2  Get KEK version   vault.keyVersion.id  →  which KEK encrypted this token's DEK
Step 3  Get KEK from ring keyRing.getByVersion(keyVersionId)   in-memory, no KMS call
Step 4  Check status      if keyMaterial.status == COMPROMISED → block (see §4.10)
Step 5  Copy KEK bytes    kekMaterial.copyKek()                defensive copy
Step 6  Decrypt DEK       AES-GCM.decrypt(encrypted_dek, kek) dekBytes (in-memory)
Step 7  Decrypt PAN       AES-GCM.decrypt(encrypted_pan, dek) panBytes (briefly in memory)
Step 8  Zero key bytes    Arrays.fill(kek, 0); Arrays.fill(dek, 0)
Step 9  Return PAN        DetokeniseResponse { pan, lastFour, cardScheme }

KMS calls: 0
HMAC key:  NOT USED — detokenisation never consults the HMAC ring
```

The HMAC secret is only used during **tokenisation** (to compute `pan_hash` for dedup lookups).
Detokenisation reads `encrypted_dek` and `encrypted_pan` directly — the HMAC ring is never touched.

### 4.8 Detokenisation during KEK rotation (ROTATING status — no downtime window)

When rotation is initiated, the old KEK moves from `ACTIVE` → `ROTATING` synchronously, before
the batch starts. The ring keeps both keys loaded simultaneously.

```
Token encrypted under OLD KEK (still being migrated in the batch):
  vault.keyVersion.id → old KEK (ROTATING) → still in ring ✓
  Detokenisation: works normally

Token already migrated to NEW KEK:
  vault.keyVersion.id → new KEK (ACTIVE) → in ring ✓
  Detokenisation: works normally

After completeRotation() fires (all tokens migrated, old KEK → RETIRED):
  Old KEK evicted from ring; all vault rows now point to new KEK
  Detokenisation: works normally
```

There is **no window** during scheduled KEK rotation where detokenisation fails.

### 4.9 Detokenisation during HMAC rotation (re-hash batch — zero impact)

HMAC rotation updates `token_vault.pan_hash` only. Detokenisation reads `encrypted_dek` and
`encrypted_pan` — it **never reads `pan_hash`**.

```
Any token at any point during the HMAC re-hash batch:
  Detokenisation: works normally (HMAC ring not consulted)

Only NEW tokenisation dedup is affected during the batch window:
  TokenisationService uses dual-lookup (new hash first, old hash fallback)
  to prevent duplicate tokens while the batch is in progress.
```

### 4.10 Detokenisation during emergency rotation (COMPROMISED KEK — intentional block)

The old KEK moves to `COMPROMISED` immediately (synchronous). This is the most sensitive scenario.

```
Token encrypted under COMPROMISED KEK:
  vault.keyVersion.id → old KEK (COMPROMISED) → in ring, status check fails
  → BLOCKED: throws exception
  → Audit: TAMPER_ALERT written
  → HTTP 500 returned to caller

  Intentional: if the KEK was compromised, the PAN may have been exposed.
  We should not silently continue returning decrypted PANs.

After re-encryption batch completes (all tokens migrated to new KEK):
  vault.keyVersion.id now points to new ACTIVE KEK
  Detokenisation resumes normally
```

The window where detokenisation fails (from `COMPROMISED` until batch completion) is an explicit
security design decision, not a bug.

---

## 5. Proposed Code Changes

### 5.1 New methods on `KmsProvider` interface

```java
// src/main/java/com/yourorg/tokenisation/kms/KmsProvider.java

/**
 * Encrypts an HMAC secret under the KMS master key for storage.
 * Uses encryption context purpose=hmac-key, distinct from purpose=kek-unwrap,
 * so blobs cannot be cross-decrypted between the two operations.
 * Caller must zero plaintextHmacKey after this method returns.
 */
byte[] wrapNewHmacKey(byte[] plaintextHmacKey);

/**
 * Decrypts a stored HMAC key blob and returns the raw secret bytes.
 * Called once per HMAC key version at startup by KeyRingInitialiser.
 * Caller must zero the returned array after loading into the HMAC ring.
 */
byte[] unwrapHmacKey(byte[] encryptedHmacBlob);
```

### 5.2 `AwsKmsAdapter` — implement both

```
wrapNewHmacKey: kms.encrypt(plaintext, keyId=masterKeyArn, context={purpose=hmac-key})
                → ciphertextBlob().asByteArray()   (raw bytes, stored as BYTEA)

unwrapHmacKey:  kms.decrypt(ciphertext, keyId=masterKeyArn, context={purpose=hmac-key})
                → plaintext().asByteArray()
```

No 32-byte enforcement at the interface level (callers always pass 32 bytes, but the interface
stays flexible in case bootstrap migration needs variable-length secrets).

### 5.3 `LocalDevKmsAdapter` — implement both

Local AES-GCM with `localKek` using the existing IV-prefix format (same as `wrapDek`/`unwrapDek`
private helpers, without the 32-byte assertion). No network calls.

### 5.4 Callers that change (HMAC write path)

All four places that create HMAC `key_versions` rows change from
`cipher.encryptBytes(secret, kek)` to `kmsProvider.wrapNewHmacKey(secret)`:

| File | Method | Notes |
|------|--------|-------|
| `AwsKeySeeder.java` | `seedHmac()` | Remove KEK loading and `cipher` injection |
| `LocalDevHmacKeySeeder.java` | `run()` | Remove `AesGcmCipher` constructor param |
| `HmacRotationService.java` | `initiateRotation()` | Remove `InMemoryKekKeyRing`, `AesGcmCipher`; inject `KmsProvider` |
| ~~`HmacKeyBootstrapService.java`~~ | ~~`run()`~~ | **Delete this file** — see §5.9 |

`forHmac()` no longer takes `encryptingKekId` (removed from entity — see §8). All callers
drop that parameter.

### 5.5 `KeyRingInitialiser` — HMAC load path (simplified)

With the drop-and-reseed decision, there are no legacy rows. `loadHmacVersion()` becomes:

```java
// Direct KMS-protected format — no KEK lookup, no AesGcmCipher
secret = kmsProvider.unwrapHmacKey(hv.getEncryptedSecret());
```

Remove `AesGcmCipher` from `KeyRingInitialiser`'s constructor — it is no longer needed anywhere
in the class.

### 5.6 `RotationJob` — revert changes from current session

The `rewrapHmacSecrets()` method added in the previous session becomes unnecessary.

- Revert `completeRotation(KeyVersion, KeyVersion)` back to `completeRotation(KeyVersion)`
- Remove `rewrapHmacSecrets()` method
- Remove `AesGcmCipher` constructor injection
- Fix `processRotationBatch()` call back to `completeRotation(rotatingKey)`

### 5.7 Cleanup from current session (also revert)

- `KeyVersionRepository.findHmacByEncryptingKekId()` — remove
- `KeyVersion.rewrapSecret()` — remove

### 5.8 Schema — V12 migration drops `encrypting_kek_id`

With drop-and-reseed, the column is removed entirely:

```sql
-- src/main/resources/db/migration/V12__drop_encrypting_kek_id.sql
ALTER TABLE key_versions DROP COLUMN IF EXISTS encrypting_kek_id;
```

`encrypted_secret` BYTEA column stays — it now holds the KMS ciphertext blob directly
(instead of a KEK-wrapped AES-GCM blob). Column Javadoc on `KeyVersion.encryptedSecret`
updated accordingly.

### 5.9 Delete `HmacKeyBootstrapService.java`

This class migrated legacy `PAN_HASH_SECRET` env var secrets into the database. Since the system
is not in production, it is deleted as part of this feature. Remove any `@Bean` registration
in configuration classes.

---

## 6. What Does NOT Change

- `encrypted_secret` BYTEA column — stays in `key_versions`; now holds KMS ciphertext blob
  directly (protected by CMK `purpose=hmac-key` context) rather than a KEK-wrapped AES-GCM blob
- `InMemoryHmacKeyRing` and `PanHasher` — unchanged
- HMAC rotation cadence / re-hashing batch (`PanHashBatchProcessor`, `HmacRotationJob`) — unchanged
- `encryptedKekBlob` / KEK path — unchanged
- `token_vault` schema — unchanged
- KMS call count at startup — still 2 (one KEK decrypt, one HMAC decrypt)
- KMS call count during tokenisation / detokenisation — still 0

---

## 7. Decisions (resolved)

1. **One CMK or two CMKs?**
   → **One CMK** (`kms.aws.master-key-arn`) with distinct encryption contexts
   (`purpose=kek-unwrap` for KEK, `purpose=hmac-key` for HMAC). A second CMK can be added
   later if IAM separation becomes a requirement — the code change is identical.

2. **Legacy row migration strategy?**
   → **Drop and re-seed.** The system is not yet deployed to production, so there is no need
   for backward compatibility. All existing HMAC rows are dropped and the seeders re-run with
   the new KMS-direct format. This removes the need for a legacy load path in `KeyRingInitialiser`.

3. **`HmacKeyBootstrapService` timeline?**
   → **Delete as part of this feature.** Since the system is not in production, the legacy
   `PAN_HASH_SECRET` env var migration path can be removed immediately.

---

## 8. DB Changes

### New migration

**`src/main/resources/db/migration/V12__drop_encrypting_kek_id.sql`**

```sql
-- encrypting_kek_id is no longer needed: HMAC secrets are now protected
-- directly by AWS KMS CMK (purpose=hmac-key), not wrapped under a KEK.
-- All existing HMAC rows have been dropped and re-seeded via the new KMS-direct path.
ALTER TABLE key_versions DROP COLUMN IF EXISTS encrypting_kek_id;
```

### `KeyVersion.java` entity changes

Remove:
- `@Column(name = "encrypting_kek_id") private UUID encryptingKekId` field
- `encryptingKekId` parameter from the `@Builder` constructor
- `rewrapSecret(byte[] newEncryptedSecret, UUID newEncryptingKekId)` mutation method

Update `encrypted_secret` Javadoc from:
> "IV-prefixed AES-GCM blob of the HMAC secret, wrapped under `encrypting_kek_id`."

To:
> "KMS ciphertext of the HMAC secret, protected directly by the CMK with `purpose=hmac-key`
> encryption context. Null for KEK rows."

`forHmac()` factory method — remove `UUID encryptingKekId` parameter:

```java
// BEFORE
public static KeyVersion forHmac(byte[] encryptedSecret, UUID encryptingKekId,
                                  String keyAlias, Instant rotateBy, String createdBy)

// AFTER
public static KeyVersion forHmac(byte[] encryptedSecret,
                                  String keyAlias, Instant rotateBy, String createdBy)
```

### `KeyVersionRepository.java`

Remove `findHmacByEncryptingKekId(UUID kekVersionId)` — no longer needed.

---

## 9. Unit Test Changes

### `HmacRotationServiceTest.java`
`src/test/java/com/yourorg/tokenisation/rotation/HmacRotationServiceTest.java`

**Remove:**
- `@Mock private InMemoryKekKeyRing keyRing` (line 53)
- `@Mock private AesGcmCipher cipher` (line 55)
- `when(keyRing.getActive()).thenReturn(kekMaterial)` stubs (lines 76, 120)
- `when(cipher.encryptBytes(any(), any())).thenReturn(FAKE_BLOB)` stubs (lines 77, 121)
- `kekMaterial` variable setup that was only used for the stubs above

**Add:**
- `@Mock private KmsProvider kmsProvider`
- `when(kmsProvider.wrapNewHmacKey(any())).thenReturn(FAKE_BLOB)` stub in each `@Test`

**Update service construction** (line 63):
```java
// BEFORE
service = new HmacRotationService(keyVersionRepository, keyRing, hmacKeyRing, cipher, auditLogger);

// AFTER
service = new HmacRotationService(keyVersionRepository, kmsProvider, hmacKeyRing, auditLogger);
```

**Update assertions:** `verify(kmsProvider).wrapNewHmacKey(any())` instead of
`verify(cipher).encryptBytes(any(), any())`.

### `HmacRotationIntegrationTest.java`
`src/test/java/com/yourorg/tokenisation/HmacRotationIntegrationTest.java`

- Remove `@Autowired private AesGcmCipher cipher` (line 62)
- Line 116: change from `cipher.decryptBytes(seedHmac.getEncryptedSecret(), kek)` to
  `kmsProvider.unwrapHmacKey(seedHmac.getEncryptedSecret())`
- Remove the KEK loading that preceded line 116 (finding active KEK, calling `unwrapKek`, etc.)
  if it was only used for the cipher call

### `KeyRingInitialiserIntegrationTest.java`
`src/test/java/com/yourorg/tokenisation/crypto/KeyRingInitialiserIntegrationTest.java`

- Remove `@Autowired private AesGcmCipher cipher` (line 60)
- Update factory method at line 171:
  ```java
  // BEFORE
  new KeyRingInitialiser(kmsProvider, keyVersionRepository, keyRing, hmacKeyRing, cipher)
  // AFTER
  new KeyRingInitialiser(kmsProvider, keyVersionRepository, keyRing, hmacKeyRing)
  ```

---

## 10. Load Test Changes

The load tests live at `src/test/java/com/yourorg/tokenisation/loadtest/` (Java-based — no
Gatling or Scala in this project).

None of the load test files directly reference `encryptingKekId`, `AesGcmCipher` for HMAC,
or the seeder internals:

| File | Impact |
|------|--------|
| `KeyRotationUnderLoadTest.java` | Tests KEK rotation only; injects `InMemoryKekKeyRing` for KEK status assertions. No HMAC-specific code. **No changes needed.** |
| `TokenisationLoadTest.java` | Exercises HTTP tokenisation API. **No changes needed.** |
| `DetokenisationLoadTest.java` | Exercises HTTP detokenisation API. **No changes needed.** |
| `MixedWorkloadLoadTest.java` | Mixed HTTP load. **No changes needed.** |
| `BulkTokenSeeder.java` | Seeds tokens via HTTP API, not via DB direct. **Verify no `encryptingKekId` references; no changes expected.** |
| `AbstractLoadTest.java`, `RandomWorkloadDispatcher.java`, `PanGenerator.java`, `LoadTestResult.java` | Infrastructure classes. **No changes needed.** |

---

## 11. Documentation Impact

### `docs/key-rotation-runbook.md` — Section 4, Step 2

Current text (line ~203):
> "A new 32-byte `SecureRandom` HMAC key is generated, **encrypted under the active KEK**, and
> persisted as a new `ACTIVE` HMAC row."

Update to:
> "A new 32-byte `SecureRandom` HMAC key is generated, **encrypted directly by AWS KMS CMK**
> (encryption context `purpose=hmac-key`), and persisted as a new `ACTIVE` HMAC row. The KEK
> is not involved in HMAC key protection."

### `docs/design.md` — Section 3 HMAC definition (line 90–91)

Current text is incorrect — it conflates HMAC with tamper detection:
> "Used in this system to **detect tampering with rows in the `key_versions` table**."

Update to:
> "**HMAC (Hash-based Message Authentication Code)** — Used in this system to compute a
> **one-way fingerprint of each PAN** (`pan_hash` in `token_vault`), enabling deduplication:
> when the same PAN arrives again, we hash it and look up `pan_hash` to find the existing token
> instead of creating a duplicate. Compromising the HMAC secret allows an attacker to enumerate
> known PANs and check for matches — they cannot reverse the hash to extract PANs. The risk is
> **cardholder linkability**, not PAN exposure."

Note: Section 7 of `design.md` ("Tamper Detection") describes AES-GCM auth tag integrity checking,
which is a **different** mechanism unrelated to the HMAC key. That section is correct as-is.

### `docs/design.md` — Section 4 tokenisation flow (pre-existing inaccuracy, flag only)

The flow diagram shows `generateDataKey(KEK)`. Our code does NOT call AWS GenerateDataKey — it
uses `SecureRandom(32)` locally and wraps the DEK with the in-memory KEK. This is a pre-existing
inaccuracy; flag it for a separate documentation fix — do not block Feature 06 on it.

### `docs/aws-kek-hmac-simplified.md`

Review for any language that states HMAC is encrypted under the KEK. Update to reflect that
HMAC is now protected directly by the CMK.

### New file: `docs/tokenisation-process.md`

A self-contained reference document for all audiences, covering the full system mental model
(glossary with corrected HMAC definition), all tokenisation and detokenisation flows, and all
rotation scenarios with KMS call counts.

---

## 12. Startup Ordering After Change

| Order | Bean | Action |
|-------|------|--------|
| `@Order(1)` | `AwsKeySeeder` / `LocalDevKeySeeder` | Seed KEK row |
| `@Order(2)` | `LocalDevHmacKeySeeder` (local-dev only) | Seed HMAC row via `wrapNewHmacKey`; `encrypting_kek_id` column gone |
| ~~`@Order(5)`~~ | ~~`HmacKeyBootstrapService`~~ | **DELETED** |
| `@Order(10)` | `KeyRingInitialiser` Phase 1 | Load KEK ring: `kms.decrypt(kekBlob, ctx=kek-unwrap)` |
| `@Order(10)` | `KeyRingInitialiser` Phase 2 | Load HMAC ring: `kms.decrypt(hmacBlob, ctx=hmac-key)` — direct, no KEK lookup, no `AesGcmCipher` |

---

## 13. Verification Checklist

1. `make localstack-test` — all integration tests pass
2. `make start-localstack` + IDE startup:
   - Startup logs show `seeded ACTIVE HMAC [<uuid>] (KMS-protected)`
   - Startup logs show `Loaded HMAC version <uuid> (status: ACTIVE) into ring`
   - No `No ACTIVE KEK version found` errors
3. `POST /api/v1/tokens` → `201 Created`
4. Same PAN → same token (dedup works, HMAC ring loaded correctly)
5. `GET /api/v1/tokens/<token>` → PAN returned
6. Trigger HMAC rotation via admin endpoint → `HmacRotationService` does not reference
   `InMemoryKekKeyRing`
7. Trigger KEK rotation → `RotationJob.completeRotation` does not call `rewrapHmacSecrets`
8. After V12 migration: `\d key_versions` shows no `encrypting_kek_id` column
9. `./gradlew test` — all unit tests pass
