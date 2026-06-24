# KMS Provider Migration Runbook

This runbook covers how to migrate the card tokenisation system from one KMS vendor to another
(e.g. AWS KMS → GCP Cloud KMS, AWS KMS → Azure Key Vault). Read the entire document before
acting — the ordering of steps is important.

---

## Table of Contents

1. [Background — What Is and Is Not Vendor-Coupled](#1-background--what-is-and-is-not-vendor-coupled)
2. [The 3-Layer Advantage](#2-the-3-layer-advantage)
3. [Code Changes Required](#3-code-changes-required)
4. [Vendor-Specific Implementation Notes](#4-vendor-specific-implementation-notes)
5. [Data Migration Strategy](#5-data-migration-strategy)
6. [Step-by-Step Migration Runbook](#6-step-by-step-migration-runbook)
7. [Verifying Completion](#7-verifying-completion)
8. [Rollback Considerations](#8-rollback-considerations)
9. [Decommissioning the Old KMS Key](#9-decommissioning-the-old-kms-key)

---

## 1. Background — What Is and Is Not Vendor-Coupled

The system is layered so that only the KMS adapter package has any vendor dependency.
Everything above the adapter is already vendor-agnostic.

### Vendor-agnostic (no changes needed on migration)

| Component | Why it is safe |
|-----------|----------------|
| `KeyRingInitialiser` | Injects `KmsProvider` interface only |
| `KeyRotationService` | Injects `KmsProvider` interface only |
| `HmacRotationService` | Injects `KmsProvider` interface only |
| `TokenisationService` | Uses in-memory KEK via `AesGcmCipher` — no KMS calls |
| `DetokenisationService` | Uses in-memory KEK via `AesGcmCipher` — no KMS calls |
| `RotationBatchProcessor` | In-memory AES-GCM re-wrap — no KMS calls |
| `token_vault` schema | `encrypted_dek` is AES-GCM wrapped by the in-memory KEK, not by KMS |
| `key_versions` schema | `kms_provider` is plain `VARCHAR(50)` with no CHECK constraint |

### Vendor-coupled (requires migration)

| Location | Column / field | Why it is coupled |
|----------|---------------|-------------------|
| `key_versions` | `encrypted_kek_blob` | KMS ciphertext — only the encrypting KMS can decrypt it |
| `key_versions` | `encrypted_secret` | KMS ciphertext — only the encrypting KMS can decrypt it |
| `key_versions` | `kms_key_id` | Stores the vendor key reference (e.g. AWS ARN, GCP resource name) |
| `key_versions` | `kms_provider` | Convention string (`AWS_KMS`, `GCP_KMS`, etc.) — informational only |
| `AwsKmsAdapter` | Entire class | AWS SDK v2 client calls |
| `KmsConfig` | Entire class | AWS SDK v2 `KmsClient` bean construction |
| `AwsKeySeeder` | `kmsProvider` / `kmsKeyId` strings | Hardcodes `"AWS_KMS"` and `"aws-kms"` |

---

## 2. The 3-Layer Advantage

Understanding the key hierarchy explains why migrating vendors is inexpensive compared to
a 2-layer (CMK → DEK → data) design.

```
3-layer design (this system):

  KMS CMK  ──(wraps)──►  KEK (in-memory, 1 row in key_versions)
                              └──(wraps)──►  DEK (per record, stored in token_vault)
                                                 └──(encrypts)──►  PAN ciphertext

2-layer design (e.g. Google's DEK-caching pattern):

  KMS CMK  ──(wraps)──►  DEK (per record or per N records, stored alongside data)
                              └──(encrypts)──►  data
```

In the 2-layer design, switching vendors requires re-encrypting every `encrypted_dek` in
`token_vault` — one KMS call per vault record (potentially millions).

In our 3-layer design, the DEKs in `token_vault` are wrapped by the **in-memory KEK using
local AES-GCM** — not by KMS directly. Switching vendors only requires re-wrapping the handful
of `key_versions` rows (typically 2–5 rows), regardless of how many tokens are in the vault.

**Token vault rows are never touched during a vendor migration.**

---

## 3. Code Changes Required

### 3.1 New KMS adapter

Create `src/main/java/com/yourorg/tokenisation/kms/<Vendor>KmsAdapter.java` implementing
`KmsProvider`. Guard it with `@ConditionalOnProperty`:

```java
@Component
@ConditionalOnProperty(name = "kms.provider", havingValue = "gcp")  // or "azure", etc.
public class GcpKmsAdapter implements KmsProvider {

    @Override
    public byte[] unwrapKek(String encryptedKekBlob) { /* GCP decrypt call */ }

    @Override
    public String wrapNewKek(byte[] plaintextKek) { /* GCP encrypt call */ }

    @Override
    public byte[] wrapDek(byte[] plaintextDek, String keyVersionId) { /* GCP encrypt */ }

    @Override
    public byte[] rewrapDek(byte[] encryptedDek, String old, String newId) {
        byte[] plain = unwrapDekForVersion(encryptedDek, old);
        try { return wrapDek(plain, newId); }
        finally { Arrays.fill(plain, (byte) 0); }
    }

    @Override
    public byte[] wrapNewHmacKey(byte[] plaintextHmacKey) { /* GCP encrypt, purpose=hmac-key */ }

    @Override
    public byte[] unwrapHmacKey(byte[] encryptedHmacBlob) { /* GCP decrypt, purpose=hmac-key */ }

    @Override
    public KeyMetadata describeKey(String kmsKeyId) { /* GCP describe key */ }
}
```

The encryption context pattern (`purpose=kek-unwrap`, `purpose=hmac-key`) must be replicated
using the new vendor's equivalent mechanism. See §4 for vendor-specific notes.

### 3.2 New KMS client configuration

Create `src/main/java/com/yourorg/tokenisation/config/<Vendor>KmsConfig.java`:

```java
@Configuration
@ConditionalOnProperty(name = "kms.provider", havingValue = "gcp")
public class GcpKmsConfig {

    @Bean
    public KeyManagementServiceClient gcpKmsClient(...) { ... }
}
```

### 3.3 New seeder

Create `src/main/java/com/yourorg/tokenisation/kms/<Vendor>KeySeeder.java` following the
same pattern as `AwsKeySeeder`:

```java
@Component
@ConditionalOnExpression("'${kms.provider:}' == 'gcp' && '${kms.gcp.seed-on-startup:false}' == 'true'")
@Order(1)
public class GcpKeySeeder implements ApplicationRunner {
    // Seed initial KEK row with kmsProvider="GCP_KMS", kmsKeyId=<GCP key resource name>
    // Seed initial HMAC row using kmsProvider.wrapNewHmacKey()
}
```

The dual-guard (`kms.provider=gcp` AND `seed-on-startup=true`) is required for the same
reason as `AwsKeySeeder` — `kms.provider=gcp` may be used in both staging and production;
the seed flag prevents silent auto-seeding in production.

### 3.4 Configuration properties

Add to `application.yml` under a new namespace:

```yaml
kms:
  gcp:
    project-id:   ${GCP_PROJECT_ID}
    location:     ${GCP_KMS_LOCATION}
    key-ring:     ${GCP_KMS_KEY_RING}
    key-name:     ${GCP_KMS_KEY_NAME}
    seed-on-startup: ${KMS_GCP_SEED_ON_STARTUP:false}
```

The existing `kms.aws.*` block remains untouched until decommission.

### 3.5 Files that do not change

```
KmsProvider.java               — interface is already vendor-agnostic
KeyRingInitialiser.java        — no changes
KeyRotationService.java        — no changes
HmacRotationService.java       — no changes
TokenisationService.java       — no changes
DetokenisationService.java     — no changes
RotationBatchProcessor.java    — no changes
All Flyway migrations          — no new migration needed (kms_provider is unconstrained VARCHAR)
token_vault schema             — no changes
```

---

## 4. Vendor-Specific Implementation Notes

### 4.1 Encryption context

Our `AwsKmsAdapter` passes an encryption context (`purpose=kek-unwrap`, `purpose=hmac-key`)
on every encrypt and decrypt call. AWS KMS binds this context cryptographically to the
ciphertext — a blob encrypted with one context cannot be decrypted with a different context.

| Vendor | Equivalent mechanism |
|--------|---------------------|
| **GCP Cloud KMS** | `additionalAuthenticatedData` (AAD) field on encrypt/decrypt requests. Pass the purpose string as AAD bytes. Behaviour is identical to AWS. |
| **Azure Key Vault** | No native encryption context equivalent. Approximate by embedding the purpose in a wrapper: encrypt `[purpose_prefix + plaintext]`, validate the prefix on decrypt before returning the payload. |
| **HashiCorp Vault** | Transit secrets engine supports `context` parameter on encrypt/decrypt. Pass the purpose string as a base64-encoded context. |

### 4.2 Key ID format

`key_versions.kms_key_id` currently stores AWS ARN strings
(`arn:aws:kms:ap-southeast-2:123456789012:key/...`). The column is plain `VARCHAR(255)` —
any format is accepted. For a new vendor, store whichever reference format that vendor's SDK
requires:

| Vendor | Key ID format stored in `kms_key_id` |
|--------|--------------------------------------|
| AWS KMS | `arn:aws:kms:<region>:<account>:key/<key-id>` |
| GCP Cloud KMS | `projects/<project>/locations/<loc>/keyRings/<ring>/cryptoKeys/<key>` |
| Azure Key Vault | `https://<vault>.vault.azure.net/keys/<key-name>/<version>` |
| HashiCorp Vault | `transit/<mount>/keys/<key-name>` |

`describeKey()` in the new adapter receives this stored string and must pass it to the
vendor's describe/get-key API in whatever format that API expects.

### 4.3 Blob format

`AwsKmsAdapter` stores raw KMS ciphertext bytes in `encrypted_secret` (HMAC) and
Base64-encodes them in `encrypted_kek_blob` (KEK). The new adapter must be internally
consistent — whatever format `wrapNewKek` produces must be reversible by `unwrapKek` in the
same adapter. No other code makes assumptions about blob format.

---

## 5. Data Migration Strategy

### 5.1 What needs to move

Only the `key_versions` table is affected. For each ACTIVE and ROTATING row:

```sql
SELECT id, key_type, key_alias, status, kms_key_id, kms_provider,
       encrypted_kek_blob, encrypted_secret
FROM key_versions
WHERE status IN ('ACTIVE', 'ROTATING');
```

Typical result: 1–2 KEK rows, 1–2 HMAC rows. The migration is O(key_versions rows),
not O(token_vault rows).

RETIRED rows do not need migration — they are never loaded at startup, and the tokens
they once protected have already been re-encrypted under a newer key.

### 5.2 Re-wrapping approach — use the existing rotation machinery

Rather than a bespoke migration script, reuse the rotation flows already in the system.
This avoids plaintext key material ever appearing outside the application boundary.

**KEK migration via standard scheduled rotation:**

1. At migration time, the new KMS adapter is active (`kms.provider=gcp`).
2. Call `POST /api/v1/admin/keys/rotate` with `reason=SCHEDULED`.
3. `KeyRotationService` generates a fresh 32-byte KEK, wraps it via the new adapter
   (`GcpKmsAdapter.wrapNewKek`), and inserts a new ACTIVE row with `kms_provider='GCP_KMS'`.
4. The old KEK row (AWS-wrapped) moves to ROTATING.
5. `RotationJob` re-wraps all `token_vault.encrypted_dek` values under the new KEK using
   local in-memory AES-GCM — zero KMS calls per token.
6. Once all tokens are migrated, the old KEK row is RETIRED. Its `encrypted_kek_blob` is an
   AWS ciphertext that no code will ever call `unwrapKek` on again.

**HMAC migration via standard HMAC rotation:**

1. Call `POST /api/v1/admin/hmac-keys/rotate`.
2. `HmacRotationService` generates a fresh 32-byte HMAC secret, wraps it via
   `GcpKmsAdapter.wrapNewHmacKey`, and inserts a new ACTIVE row with `kms_provider='GCP_KMS'`.
3. The old HMAC row (AWS-wrapped) moves to ROTATING.
4. `HmacRotationJob` re-hashes all `pan_hash` values in `token_vault` under the new secret.
5. Once all records are re-hashed, the old HMAC row is RETIRED.

This means the old AWS-wrapped `key_versions` rows are never explicitly decrypted during
the migration — AWS KMS is only needed at startup to load the old KEK into the in-memory
ring. Once the ring holds the old KEK in memory, the rotation re-wrap batch runs entirely
in-process.

### 5.3 Dual-KMS startup window

During the migration window (between adapter switchover and old keys being fully RETIRED),
`KeyRingInitialiser` loads both ACTIVE (new, GCP-wrapped) and ROTATING (old, AWS-wrapped)
key versions. The ROTATING row's `encrypted_kek_blob` is an AWS ciphertext — so AWS KMS
must still be reachable at startup until the rotation batch completes.

```
Migration window startup sequence:

  KeyRingInitialiser Phase 1:
    ACTIVE KEK row  → GcpKmsAdapter.unwrapKek()   ✓ (new vendor)
    ROTATING KEK row → AwsKmsAdapter.unwrapKek()  ✓ (old vendor, still needed)

  KeyRingInitialiser Phase 2:
    ACTIVE HMAC row  → GcpKmsAdapter.unwrapHmacKey()  ✓
    ROTATING HMAC row → AwsKmsAdapter.unwrapHmacKey() ✓
```

For this to work, both adapters must be wired simultaneously during the migration window.
Implement this by registering both as named beans rather than relying on
`@ConditionalOnProperty` during the migration:

```java
// Temporary migration configuration — remove after old keys are RETIRED
@Bean("awsKmsProvider")
public KmsProvider awsKmsProvider(...) { return new AwsKmsAdapter(...); }

@Bean("gcpKmsProvider")  
public KmsProvider gcpKmsProvider(...) { return new GcpKmsAdapter(...); }
```

Then implement a `RoutingKmsProvider` that selects the correct adapter based on the
`kms_provider` column value on the row being loaded:

```java
public class RoutingKmsProvider implements KmsProvider {
    // unwrapKek: inspect kms_provider on the KeyVersion row, delegate to correct adapter
    // wrapNewKek / wrapNewHmacKey: always delegates to the new (active) adapter
}
```

Remove the `RoutingKmsProvider` and the old adapter once all ROTATING rows are RETIRED.

---

## 6. Step-by-Step Migration Runbook

### Step 1 — Provision the new KMS key

Create the key in the new vendor's KMS. Record the key reference (ARN, resource name, etc.).
Ensure the application's IAM identity has `encrypt` and `decrypt` permissions on the new key.

Verify connectivity from the application environment:

```bash
# Example for GCP — adjust for your vendor
gcloud kms encrypt \
  --location=<location> --keyring=<ring> --key=<key> \
  --plaintext-file=/dev/urandom --ciphertext-file=/dev/null \
  --plaintext-file-size=32
```

### Step 2 — Implement and test the new adapter

Write `<Vendor>KmsAdapter`, `<Vendor>KmsConfig`, and `<Vendor>KeySeeder`. Test against the
new vendor using the LocalStack-equivalent test profile for that vendor, or write integration
tests using Testcontainers (e.g. the GCP Cloud KMS emulator).

Ensure `wrapNewKek` → `unwrapKek` round-trip and `wrapNewHmacKey` → `unwrapHmacKey`
round-trip are covered by unit tests before deploying.

### Step 3 — Deploy the dual-adapter build

Deploy the application with both the old and new adapters wired (using `RoutingKmsProvider`
or an equivalent mechanism). At this point the primary adapter is still the old vendor —
new tokenisations continue to use the old keys.

Confirm startup is healthy:

```bash
curl https://<host>/api/v1/health
# Expected: {"database":"UP","keyRing":"UP"}
```

### Step 4 — Switch the primary adapter to the new vendor

Update configuration to point the active operations at the new vendor:

```yaml
kms:
  provider: gcp
  gcp:
    project-id: <project>
    location:   <location>
    key-ring:   <ring>
    key-name:   <key>
```

Rolling-restart the application. On startup, `KeyRingInitialiser` loads:
- The ACTIVE KEK (still AWS-wrapped at this point) via the old adapter
- The ACTIVE HMAC (still AWS-wrapped at this point) via the old adapter

New tokenisations still succeed because the in-memory KEK is unchanged.

### Step 5 — Trigger KEK rotation to the new vendor

```bash
curl -X POST https://<host>/api/v1/admin/keys/rotate \
  -H 'Content-Type: application/json' \
  -d '{"reason": "SCHEDULED", "newKeyAlias": "gcp-kek-2026-q3"}'
# Expected: HTTP 202 Accepted
```

This creates a new ACTIVE KEK row with `kms_provider='GCP_KMS'`. The old row moves to ROTATING.
Monitor the `RotationJob` batch until all tokens are migrated:

```sql
SELECT kv.key_alias, kv.kms_provider, kv.status, COUNT(tv.token_id) AS remaining
FROM key_versions kv
LEFT JOIN token_vault tv ON tv.key_version_id = kv.id AND tv.is_active = TRUE
WHERE kv.key_type = 'KEK'
GROUP BY kv.key_alias, kv.kms_provider, kv.status
ORDER BY kv.activated_at DESC;
```

### Step 6 — Trigger HMAC rotation to the new vendor

```bash
curl -X POST https://<host>/api/v1/admin/hmac-keys/rotate \
  -H 'Content-Type: application/json' \
  -d '{"newKeyAlias": "gcp-hmac-2026-q3"}'
# Expected: HTTP 202 Accepted
```

Monitor the `HmacRotationJob` batch:

```sql
SELECT kv.key_alias, kv.kms_provider, kv.status,
       COUNT(tv.token_id) AS remaining
FROM key_versions kv
LEFT JOIN token_vault tv ON tv.hmac_key_version_id = kv.id AND tv.is_active = TRUE
WHERE kv.key_type = 'HMAC'
GROUP BY kv.key_alias, kv.kms_provider, kv.status
ORDER BY kv.activated_at DESC;
```

### Step 7 — Confirm all old rows are RETIRED

```sql
SELECT id, key_type, key_alias, kms_provider, status, retired_at
FROM key_versions
ORDER BY key_type, activated_at DESC;
```

Expected state:

| key_type | kms_provider | status |
|----------|-------------|--------|
| KEK | GCP_KMS | ACTIVE |
| KEK | AWS_KMS | RETIRED |
| HMAC | GCP_KMS | ACTIVE |
| HMAC | AWS_KMS | RETIRED |

### Step 8 — Remove the dual-adapter wiring

Deploy the final build with only the new adapter registered. The `RoutingKmsProvider` and
`AwsKmsAdapter` bean can be removed. AWS SDK dependency can be dropped from `pom.xml`.

Restart and confirm startup health.

---

## 7. Verifying Completion

Run the full verification checklist after Step 8:

| Check | Query / command | Expected |
|-------|-----------------|----------|
| No AWS-wrapped active keys | `SELECT * FROM key_versions WHERE kms_provider='AWS_KMS' AND status != 'RETIRED'` | 0 rows |
| New vendor keys active | `SELECT status FROM key_versions WHERE kms_provider='GCP_KMS'` | ACTIVE for each type |
| Token vault untouched | `SELECT COUNT(*) FROM token_vault WHERE is_active=TRUE` | Unchanged row count |
| Rotation audit | `SELECT event_type, outcome FROM token_audit_log WHERE event_type IN ('KEY_ROTATION_COMPLETED','HMAC_ROTATION_COMPLETED') ORDER BY created_at DESC LIMIT 4` | SUCCESS for both |
| Tokenise round-trip | `POST /api/v1/tokens` then `GET /api/v1/tokens/<token>` | PAN returned correctly |
| Health endpoint | `GET /api/v1/health` | `{"keyRing":"UP"}` |

---

## 8. Rollback Considerations

### During Step 3–4 (before rotation triggered)

Rollback is straightforward — redeploy the previous build. The old vendor's ACTIVE keys are
unchanged. No data has moved.

### During Step 5–6 (rotation in progress)

The old ROTATING key is still in the in-memory ring. Rollback to the old adapter:

1. Redeploy the previous build (old adapter only)
2. On restart, `KeyRingInitialiser` loads the ROTATING key (still AWS-wrapped) from AWS KMS
3. Detokenisation of already-migrated tokens works — the new KEK row is ACTIVE but still
   has its plaintext KEK in the ring (loaded from the new vendor at startup)
4. However, the new vendor's `encrypted_kek_blob` on the ACTIVE row cannot be read by the
   old adapter — you may need to manually demote the ACTIVE row back to RETIRED and promote
   the ROTATING row back to ACTIVE via SQL if the rollback build cannot load the new row

To avoid this, **do not** decommission the old adapter until the rotations are fully complete
and verified (Step 7).

### After Step 7 (all rows RETIRED)

Rollback is not possible without re-migrating in reverse. The AWS-wrapped rows are RETIRED
and the in-memory KEK from them is no longer loaded at startup. If rollback is needed at
this stage, treat it as a new forward migration back to AWS.

---

## 9. Decommissioning the Old KMS Key

Only schedule the old KMS key for deletion after **all** of the following are true:

1. All `key_versions` rows with the old `kms_provider` are `status='RETIRED'`
2. The old adapter bean has been removed from the application
3. At least one full application restart cycle has completed successfully without the old adapter
4. Audit logs show no `KMS unavailable` or `InvalidCiphertextException` errors since the restart
5. Backup / point-in-time recovery policy has been reviewed — restoring an old DB snapshot
   would require the old KMS key to still be available to re-decrypt RETIRED rows during recovery

AWS KMS allows scheduling a key for deletion with a waiting period (minimum 7 days).
Use the maximum waiting period that your compliance policy allows to preserve rollback
options. Do not delete the key — schedule for deletion and monitor for unexpected decrypt
calls in CloudTrail during the waiting period before the deletion executes.
