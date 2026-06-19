# Feature 05: Versioned HMAC Key + LocalStack AWS KMS

## Overview

Three workstreams, in implementation order:

1. **Remove TamperDetector** — delete the checksum-based tamper detection on `key_versions` rows. DB access controls (role restrictions tested in `DbRoleRestrictionTest`) and KMS envelope encryption already prevent meaningful tampering. Removing it simplifies the key model significantly.
2. **HMAC key versioning** — store the PAN-hash secret as a versioned row in the existing `key_versions` table (new `key_type` column: `KEK` or `HMAC`), enabling rotation, startup loading, and historical re-verification with no new table.
3. **LocalStack AWS KMS** — add real KMS behavior testing via LocalStack (separate Docker Compose + Testcontainers profile, no impact on existing tests), plus an operator runbook for managing the system with real KMS.

---

## Part 1 — Remove TamperDetector

### What to delete

| File | Action |
|------|--------|
| `crypto/TamperDetector.java` | Delete |
| `config/TamperDetectionProperties.java` | Delete |
| `test/crypto/TamperDetectorTest.java` | Delete |

### What to update

**`domain/KeyVersion.java`**
- Remove `checksum` field and column mapping
- Remove `initializeChecksum(String checksum)` method
- Remove `getChecksum()` method

**`rotation/KeyRotationService.java`**
- Remove `tamperDetector` dependency injection
- Remove `assertIntegrity(activeKey)` call in `initiateScheduledRotation()`
- Remove `assertIntegrity(compromisedKey)` call in `initiateEmergencyRotation()`
- Remove `persistWithChecksum()` helper — replace with plain `save()`

**`audit/AuditEventType.java`**
- Remove `TAMPER_ALERT`
- Remove `KEY_INTEGRITY_VIOLATION`

**`test/ScheduledRotationIntegrationTest.java`**
- Remove all checksum assertions (e.g. `assertThat(newKey.getChecksum()).matches("[0-9a-f]{64}")`)
- Remove `recomputeRealChecksum()` setup step in `@BeforeEach`

**`test/EmergencyRotationIntegrationTest.java`**
- Remove tamper-detection-specific test cases
- Remove `assertIntegrity` assertions

**`test/KeyRotationServiceTest.java`**
- Remove `TamperDetector` mock and all stub/verify calls against it

**`application.yml`**
- Remove `tokenisation.tamper-detection.signing-secret` property

**`application-test.yml`**
- Remove `tokenisation.tamper-detection.signing-secret` property

**DB migration V8** (see Part 2A) — drop `checksum` column from `key_versions` in the same migration that adds `key_type`.

**Docs to update** — covered in Part 4 (Documentation).

---

## Part 2 — HMAC Key Versioning

### Design decisions

**Unified `key_versions` table.** A new `key_type` column (`KEK` | `HMAC`) turns the existing table into the single source of truth for all key material. HMAC rows use two new nullable columns (`encrypted_secret`, `encrypting_kek_id`); KEK rows leave them null. One table, one entity, one repository.

**HMAC secrets encrypted under active KEK.** The 32-byte HMAC secret is wrapped with `AesGcmCipher.encryptBytes()` using the active KEK before storage. This reuses the existing envelope pattern without adding another KMS dependency. `encryptBytes`/`decryptBytes` are two new methods on `AesGcmCipher` with no 32-byte length restriction (unlike `wrapDek` which enforces AES-256 DEK size).

**Bootstrap preserves existing `pan_hash` values.** On first boot the bootstrap service reads the legacy `PAN_HASH_SECRET` env var, UTF-8 encodes it exactly as `PanHasher` did, encrypts, and stores it. Existing `pan_hash` values in `token_vault` are valid immediately — no re-hashing needed at deploy time.

**`KeyRingInitialiser` loads both KEK and HMAC in one pass.** No second `ApplicationRunner` class. After loading KEK rows it loads HMAC rows, decrypting each with the already-loaded KEK ring.

**One HMAC key active at a time.** With TamperDetector gone there is only one HMAC purpose (PAN_HASH). `InMemoryHmacKeyRing` has a single `volatile String activeHmacVersionId` pointer, no per-purpose complexity.

**Concurrent KEK + HMAC rotation: recommended against but tolerated.** Both batch processors update `token_vault` rows and will occasionally collide on `record_version`. Both are designed to skip-and-retry on `OptimisticLockException`. The `HmacRotationService` logs a WARNING if a KEK rotation is in progress but does not block — operators should schedule HMAC rotation during quiet windows.

---

### Part 2A — Database Migrations

#### V8 — `db/migration/V8__add_hmac_key_type.sql`

```sql
-- Add type discriminator; existing rows are KEK
ALTER TABLE key_versions
    ADD COLUMN key_type VARCHAR(10) NOT NULL DEFAULT 'KEK'
        CHECK (key_type IN ('KEK', 'HMAC'));

-- Encrypted HMAC secret blob (IV-prefix AES-GCM); NULL for KEK rows
ALTER TABLE key_versions
    ADD COLUMN encrypted_secret BYTEA;

-- Self-referential FK: which KEK encrypted this HMAC secret; NULL for KEK rows
ALTER TABLE key_versions
    ADD COLUMN encrypting_kek_id UUID REFERENCES key_versions(id);

-- Drop TamperDetector checksum column
ALTER TABLE key_versions
    DROP COLUMN IF EXISTS checksum;

-- Replace old single-ACTIVE partial index with per-type uniqueness
-- (existing index name from V1 migration — drop and recreate)
DROP INDEX IF EXISTS uq_key_versions_single_active;
CREATE UNIQUE INDEX uq_key_versions_single_active_per_type
    ON key_versions(key_type) WHERE status = 'ACTIVE';

-- Index for HMAC-type lookup at startup
CREATE INDEX idx_key_versions_hmac_status
    ON key_versions(key_type, status) WHERE key_type = 'HMAC';
```

#### V9 — `db/migration/V9__add_hmac_version_to_vault.sql`

```sql
-- Records which HMAC version produced each pan_hash (needed by re-hash batch)
ALTER TABLE token_vault
    ADD COLUMN hmac_key_version_id UUID REFERENCES key_versions(id);

-- Index for batch query: find vault rows still on the rotating HMAC version
CREATE INDEX idx_token_vault_hmac_version_active
    ON token_vault(hmac_key_version_id) WHERE is_active = TRUE;
```

`hmac_key_version_id` nullable initially — bootstrap backfills all existing rows. After bootstrap a follow-up migration can enforce `NOT NULL`.

No new role grants needed — `tokenisation_app` already has `SELECT, INSERT, UPDATE` on `key_versions` from V6.

---

### Part 2B — Modified Existing Classes

#### `crypto/AesGcmCipher.java`

Add two public methods (same IV-prefix GCM format as `wrapDek`/`unwrapDek`, no length restriction):

```java
public byte[] encryptBytes(byte[] plaintext, byte[] kek)   // any-length plaintext
public byte[] decryptBytes(byte[] ivPrefixedBlob, byte[] kek)
```

#### `domain/KeyType.java` (new enum)

```java
public enum KeyType { KEK, HMAC }
```

#### `domain/KeyVersion.java`

Add fields:
- `keyType KeyType` (`@Enumerated(STRING)`, NOT NULL, default `KEK`)
- `encryptedSecret byte[]` (nullable, defensive-clone getter)
- `encryptingKekId UUID` (nullable — self-ref, not a JPA association to avoid circular loading issues; query the ring by UUID directly)

Remove fields (from TamperDetector removal in Part 1):
- `checksum`, `initializeChecksum()`, `getChecksum()`

Add factory method:
```java
public static KeyVersion forHmac(byte[] encryptedSecret, UUID encryptingKekId,
                                  String alias, Instant rotateBy, String createdBy)
```

#### `repository/KeyVersionRepository.java`

Add:
```java
Optional<KeyVersion> findActiveHmac();
// @Query: WHERE key_type='HMAC' AND status='ACTIVE'

List<KeyVersion> findByKeyTypeAndStatusIn(KeyType keyType, List<KeyStatus> statuses);

Optional<KeyVersion> findActiveOrThrow(KeyType keyType);
// default method; throws IllegalStateException if absent
```

Update existing `findActiveOrThrow()` → `findActiveOrThrow(KeyType.KEK)` in all callers (`KeyRingInitialiser`, `HmacKeyBootstrapService`, `KeyRotationService`).

`TokenVaultRepository` additions:
```java
Page<TokenVault> findActiveByHmacKeyVersionId(UUID hmacVersionId, Pageable p);
long countActiveByHmacKeyVersionId(UUID hmacVersionId);

@Modifying
@Query("UPDATE TokenVault t SET t.hmacKeyVersionId = :id WHERE t.isActive = true")
void bulkSetHmacVersionId(@Param("id") UUID id);
```

#### `crypto/KeyRingInitialiser.java`

Extend the single `run()` method to load HMAC rows after KEK rows. No new class needed.

```
run():
  // Phase 1 — KEK (existing)
  kevVersions = repo.findByKeyTypeAndStatusIn(KEK, [ACTIVE, ROTATING])
  for each: kek = kmsProvider.unwrapKek(kv.encryptedKekBlob) → kekRing.load(...)
  kekRing.promoteActive(activeKekId)

  // Phase 2 — HMAC (new)
  hmacVersions = repo.findByKeyTypeAndStatusIn(HMAC, [ACTIVE, ROTATING])
  for each hv:
    kekMaterial = kekRing.getByVersion(hv.encryptingKekId.toString())
    kek = kekMaterial.copyKek()
    secret = cipher.decryptBytes(hv.encryptedSecret, kek)   // zero kek + secret in finally
    hmacRing.load(hv.id.toString(), secret, hv.rotateBy)
  hmacRing.promoteActive(activeHmacId)
  fail fast if no ACTIVE HMAC found
```

#### `crypto/PanHasher.java`

Replace `@Value`-injected `hashingSecretBytes` with `InMemoryHmacKeyRing` injection.

New `HashResult` record: `String hash`, `String hmacVersionId`.

Updated signatures:
- `hash(String pan)` → `HashResult` — uses `hmacRing.getActive()`
- `hashWithVersion(String pan, String hmacVersionId)` → `String` — uses `hmacRing.getByVersion(id)`

#### `service/TokenisationService.java`

1. Store `HashResult.hmacVersionId()` in `vault.hmacKeyVersionId` on every tokenisation.
2. Add dedup dual-lookup during rotation window:
```java
HashResult hr = panHasher.hash(pan);
Optional<TokenVault> existing = tokenVaultRepository.findActiveByPanHash(hr.hash());
if (existing.isEmpty()) {
    hmacRing.findRotatingVersionId().ifPresent(oldId -> {
        String oldHash = panHasher.hashWithVersion(pan, oldId);
        existing = tokenVaultRepository.findActiveByPanHash(oldHash);
    });
}
```

#### `domain/TokenVault.java`

Add `hmacKeyVersionId UUID` field. Add `updatePanHash(String newHash, UUID newHmacVersionId)` method.

#### `application.yml`

Remove `tokenisation.tamper-detection.signing-secret`.

Keep `tokenisation.pan-hash-secret` as `#{null}`-defaulting optional (bootstrap reads it; removed after first rotation):
```yaml
tokenisation:
  pan-hash-secret: ${PAN_HASH_SECRET:#{null}}
```

Add HMAC rotation batch config:
```yaml
rotation:
  hmac-batch:
    cron: "0 0 2 * * *"      # off-peak default
    size: 100
    parallelism: 4
```

#### `audit/AuditEventType.java`

Add: `HMAC_ROTATION_STARTED`, `HMAC_ROTATION_COMPLETED`, `PAN_HASH_RECOMPUTED`, `RE_HASH_SKIPPED_COMPROMISED_KEY`

Remove (from Part 1): `TAMPER_ALERT`, `KEY_INTEGRITY_VIOLATION`

---

### Part 2C — New Classes

#### `crypto/HmacKeyMaterial.java`

In-memory wrapper (mirrors `KeyMaterial` but no fixed-length restriction on secret):
- Fields: `hmacVersionId String`, `secret byte[]` (defensive copy in constructor), `expiresAt Instant`, `volatile KeyStatus status`
- Methods: `copySecret()` (defensive clone), `zero()` (`Arrays.fill`), `asRetired()`

#### `crypto/InMemoryHmacKeyRing.java` (`@Component`)

Single active pointer (no per-purpose complexity):
- `ConcurrentHashMap<String, HmacKeyMaterial> materials`
- `volatile String activeHmacVersionId`
- `load(versionId, secret, expiresAt)`
- `promoteActive(versionId)`
- `getActive()` — throws if null
- `getByVersion(String versionId)` — throws `KeyVersionNotFoundException` if absent
- `retire(versionId)`
- `findRotatingVersionId()` → `Optional<String>`

#### `kms/HmacKeyBootstrapService.java` (`@Component @Order(5) implements ApplicationRunner`)

Runs before `KeyRingInitialiser` (`@Order(10)` — add this to `KeyRingInitialiser`). Uses `kmsProvider.unwrapKek()` directly (ring not loaded yet).

```
run():
  if key_versions has HMAC row with status=ACTIVE → return  // idempotent
  if PAN_HASH_SECRET env var is null → throw IllegalStateException

  activeKek = keyVersionRepository.findActiveOrThrow(KEK)
  kek = kmsProvider.unwrapKek(activeKek.encryptedKekBlob)    // direct call, not from ring
  secretBytes = panHashSecret.getBytes(UTF_8)                // exact bytes PanHasher used
  encryptedSecret = cipher.encryptBytes(secretBytes, kek)
  persist KeyVersion.forHmac(encryptedSecret, activeKek.id, "bootstrap-hmac", ...)
  tokenVaultRepository.bulkSetHmacVersionId(hmacVersion.id)  // backfill existing rows
  zero kek and secretBytes in finally
```

#### `kms/LocalDevHmacKeySeeder.java` (`@Component @Order(1)`, conditional on `kms.provider=local-dev`)

Seeds one HMAC row with a fixed 32-byte secret if absent. Uses `cipher.encryptBytes(fixedSecret, localDevKek)`. Mirrors `LocalDevKeySeeder`.

#### `rotation/HmacRotationService.java` (`@Service @Transactional`)

```
initiateHmacRotation(String newAlias):
  activeHmac = keyVersionRepository.findActiveOrThrow(HMAC)
  rotatingKekCount = keyVersionRepository.findByKeyTypeAndStatusIn(KEK, [ROTATING]).size()
  if rotatingKekCount > 0 → log WARNING "KEK rotation in progress; HMAC rotation may have retries"

  Generate 32 random bytes
  activeKek = keyVersionRepository.findActiveOrThrow(KEK)
  kek = kekRing.getActive().copyKek()
  encryptedSecret = cipher.encryptBytes(newSecret, kek)
  zero kek, newSecret in finally

  activeHmac.markRotating() → save
  persist KeyVersion.forHmac(encryptedSecret, activeKek.id, newAlias, ...)
  cipher.decryptBytes(encryptedSecret, kek copy) → hmacRing.load(...) → hmacRing.promoteActive(...)
  audit HMAC_ROTATION_STARTED
  // PanHashBatchProcessor picks up on next HmacRotationJob tick
```

#### `rotation/PanHashBatchProcessor.java` (mirrors `RotationBatchProcessor`)

Per-record `REQUIRES_NEW` transaction:
1. If `kekMaterial.status() == COMPROMISED` → skip, emit `RE_HASH_SKIPPED_COMPROMISED_KEY` audit
2. `kek = kekRing.getByVersion(vault.keyVersionId).copyKek()`
3. `panBytes = cipher.decrypt(vault.encryptedPan, vault.iv, vault.authTag, vault.encryptedDek, kek)`
4. `newHash = panHasher.hashWithVersion(pan, newHmacVersionId)`
5. `vault.updatePanHash(newHash, newHmacVersionId)` → save
6. Emit `PAN_HASH_RECOMPUTED` audit
7. Zero `kek`, `panBytes` in `finally`

Parallelism: 4 threads (`rotation.hmac-batch.parallelism`), batch size 100 (`rotation.hmac-batch.size`).

#### `rotation/HmacRotationJob.java` (mirrors `RotationJob`)

Scheduled via `rotation.hmac-batch.cron`. On each tick:
- Find any `HMAC` + `ROTATING` version
- Drive `PanHashBatchProcessor` pages
- When `countActiveByHmacKeyVersionId(rotatingId) == 0` → `hmacRing.retire(rotatingId)` + DB `markRetired()` + emit `HMAC_ROTATION_COMPLETED`

#### `exception/RotationConflictException.java`

Thrown (as HTTP 409) if HMAC rotation is requested while an incompatible state exists. Currently: not a hard block but a WARNING log. Add endpoint-level check returning 409 if desired by operator preference.

#### New admin endpoint

`POST /api/v1/admin/hmac-keys/rotate` — body: `{"newKeyAlias": "pan-hash-key-2026-q2"}`
Added to `AdminKeyController` alongside the existing KEK rotate endpoint.

---

### Part 2D — Startup Order

| @Order | Bean | Action |
|--------|------|--------|
| 1 | `LocalDevKeySeeder` (existing) | Seed KEK row in local dev |
| 1 | `LocalDevHmacKeySeeder` (new) | Seed HMAC row in local dev |
| 5 | `HmacKeyBootstrapService` (new) | Migrate `PAN_HASH_SECRET` env var → HMAC row (idempotent) |
| 10 | `KeyRingInitialiser` (add `@Order(10)`) | Phase 1: load KEK versions; Phase 2: load HMAC versions |

---

## Part 3 — Tests

### 3A — Tests that break and must be fixed first

| File | What breaks | Fix |
|------|-------------|-----|
| `AbstractIntegrationTest.TestDataSeederConfig` | No HMAC row → `KeyRingInitialiser` Phase 2 fails at startup | Seed one HMAC row (`SEED_HMAC_VERSION_ID = "00000000-0000-0000-0000-000000000002"`) encrypted under local-dev KEK; bulk-set `token_vault.hmac_key_version_id` |
| `PanHasherTest` | Constructor changed from `@Value` to ring injection | Mock `InMemoryHmacKeyRing`; stub `getActive()` to return a `HmacKeyMaterial` with the test secret bytes |
| `TamperDetectorTest` | Class deleted | Delete test file |
| `KeyRotationServiceTest` | `TamperDetector` mock removed; `persistWithChecksum()` gone | Remove `TamperDetector` setup; update assertions |
| `ScheduledRotationIntegrationTest` | `recomputeRealChecksum()` setup fails (column gone); checksum assertions fail | Remove checksum setup and assertions; add `hmac_key_version_id` assertion on newly created tokens |
| `EmergencyRotationIntegrationTest` | Tamper detection scenarios removed | Remove TAMPER_ALERT test cases; verify HMAC ring unaffected by emergency KEK rotation |
| `TokenisationIntegrationTest` | `panHasher.hash()` returns `HashResult`, not `String` | Update assertions; verify `hmac_key_version_id` populated in vault |
| `application-test.yml` | `tamper-detection.signing-secret` no longer resolved | Remove property |

### 3B — New unit tests

**`crypto/AesGcmCipherTest.java`** (additions):
- `encryptBytes_roundTrip` — encrypt then decrypt, assert equal for 1/16/32/64/100-byte inputs
- `encryptBytes_differentIvEachCall` — same plaintext → different blob each call
- `decryptBytes_tampered_throwsEncryptionException`

**`crypto/HmacKeyMaterialTest.java`** (new):
- Constructor defensive copy; `copySecret` returns copy; `zero` fills with zeros; `asRetired` status transition

**`crypto/InMemoryHmacKeyRingTest.java`** (new):
- `load_andGetByVersion`; `promoteActive_thenGetActive`; `getActive_whenNonePromoted_throws`; `getByVersion_absent_throws`; `retire_updatesStatus`; `findRotatingVersionId_whenRotating_returnsId`

**`kms/HmacKeyBootstrapServiceTest.java`** (new):
- Idempotent (skips if HMAC row exists); seeds from env var; bulk-updates vault rows; throws on null env var

**`rotation/HmacRotationServiceTest.java`** (new):
- Transitions old to ROTATING, creates new ACTIVE; loads new secret into ring; logs WARNING when KEK is ROTATING

**`rotation/PanHashBatchProcessorTest.java`** (new):
- Happy path re-hash; empty batch; COMPROMISED KEK → skip with audit; failure → continue batch; optimistic lock → log and continue

### 3C — New integration tests

**`HmacRotationIntegrationTest.java`** (new, extends `AbstractIntegrationTest`):
- `rotation_createsNewActiveVersion_oldBecomesRotating`
- `dualLookupDedup_duringBatchWindow` — tokenise PAN, rotate, tokenise same PAN before batch → same token returned
- `batch_rehashesPanHash_andRetiresOldVersion`
- `existingTokensRemainDetokenisable_duringAndAfterBatch`
- `newTokenisationsUseNewHmacVersion`
- `rotationWhileKekRotating_logsWarning_doesNotBlock`

**`HmacRotationUnderLoadTest.java`** (new, `@Tag("load")`):
1. Pre-seed 5,000 tokens
2. 20 concurrent tokenise + 10 detokenise threads
3. Trigger HMAC rotation
4. Verify no duplicate tokens (dual-lookup); all 5,000 detokenisable; p99 < 3000ms during batch

### 3D — Existing integration tests: additions

**`ScheduledRotationIntegrationTest.java`** — add: after KEK rotation, `token_vault.hmac_key_version_id` still equals `SEED_HMAC_VERSION_ID` (HMAC ring unaffected by KEK rotation).

**`TokenisationIntegrationTest.java`** — add: `hmac_key_version_id` equals `SEED_HMAC_VERSION_ID` in vault after tokenisation.

### 3E — Gatling updates

**`RotationSimulation.java`** — add `hmacRotationScenario`:
- `POST /api/v1/admin/hmac-keys/rotate` after initial ramp-up
- 70% tokenise / 30% detokenise concurrently
- Assertions: p99 < 5000ms, success ≥ 99%

**`DbSetupHelper.java`** additions:
- `countVaultRowsByHmacVersion(UUID)` — monitor batch progress during simulation
- `resetHmacKeyVersions()` — retire all but seed HMAC version for simulation teardown

### 3F — Test execution commands (no change to existing commands)

| Command | Runs |
|---------|------|
| `mvn test` | All unit + integration (no load, no localstack) |
| `mvn test -P load-tests` | Only `@Tag("load")` |
| `mvn test -P localstack-tests` | Only `@Tag("localstack")` — requires Docker |
| `mvn gatling:test -P gatling-tests` | Gatling — requires running app |

---

## Part 4 — Documentation Updates

### 4A — `docs/key-rotation-runbook.md` (full rewrite of affected sections)

**Remove:**
- All references to `checksum`, `TAMPER_DETECTION_SECRET`, `TAMPER_ALERT`
- "Integrity check failure during cutover" troubleshooting entry
- Any mention of `TamperDetector`

**Add — new section "HMAC Key Rotation"** covering:

*Background:* The `PAN_HASH` HMAC secret is versioned alongside KEK versions in `key_versions` (`key_type='HMAC'`). Rotation generates a new 32-byte secret, encrypts it under the active KEK, loads it into the in-memory ring, and starts a background batch that decrypts each active token's PAN and re-hashes it with the new secret. Tokenisation dedup continues to work during the batch via a dual-lookup (checks both the new-version hash and the old-version hash).

*Step 1 — Check current HMAC key state:*
```bash
psql $DATABASE_URL -c "
  SELECT id, key_alias, status, activated_at, rotate_by
  FROM key_versions WHERE key_type = 'HMAC' ORDER BY activated_at DESC;"
```
Expected: one `ACTIVE` row; any number of `RETIRED` rows.

*Step 2 — Confirm no KEK rotation in progress (recommended, not enforced):*
```bash
psql $DATABASE_URL -c "SELECT COUNT(*) FROM key_versions WHERE key_type='KEK' AND status='ROTATING';"
```
Expected: `0`. If non-zero, wait for KEK batch to complete first.

*Step 3 — Trigger rotation:*
```bash
curl -X POST https://<host>/api/v1/admin/hmac-keys/rotate \
  -H 'Content-Type: application/json' \
  -d '{"newKeyAlias": "pan-hash-key-2026-q2"}'
```
Expected: `HTTP 202 Accepted`. New tokenisations immediately use the new key. Dedup dual-lookup is active.

*Step 4 — Monitor batch:*
```bash
psql $DATABASE_URL -c "
  SELECT kv.key_alias, COUNT(tv.token_id) AS remaining
  FROM key_versions kv
  JOIN token_vault tv ON tv.hmac_key_version_id = kv.id
  WHERE kv.key_type = 'HMAC' AND kv.status = 'ROTATING' AND tv.is_active = TRUE
  GROUP BY kv.key_alias;"
```
Batch runs on `rotation.hmac-batch.cron` schedule. Each tick processes `rotation.hmac-batch.size` tokens with `rotation.hmac-batch.parallelism` threads.

*Step 5 — Verify completion:*
```bash
# Old HMAC version should be RETIRED
psql $DATABASE_URL -c "SELECT status, retired_at FROM key_versions WHERE key_type='HMAC' ORDER BY activated_at DESC;"

# No active tokens remain on old version
psql $DATABASE_URL -c "
  SELECT COUNT(*) FROM token_vault tv
  JOIN key_versions kv ON kv.id = tv.hmac_key_version_id
  WHERE kv.status='RETIRED' AND tv.is_active=TRUE;"

# Audit log
psql $DATABASE_URL -c "
  SELECT event_type, outcome, created_at FROM token_audit_log
  WHERE event_type IN ('HMAC_ROTATION_STARTED','HMAC_ROTATION_COMPLETED')
  ORDER BY created_at DESC LIMIT 5;"
```

*Troubleshooting — HMAC batch stuck:*
- Check `HmacRotationJob` cron is not `"-"` in production config
- Check for `RE_HASH_SKIPPED_COMPROMISED_KEY` audit events — if present, a concurrent emergency KEK rotation occurred; wait for KEK batch to complete, then HMAC batch auto-resumes (it is idempotent)
- Restart application to reload in-memory rings from DB state

*Post-rotation — retire env var:*
After the first successful HMAC rotation (which generates a fresh `SecureRandom` key), the original `PAN_HASH_SECRET` env var is no longer used. Remove it from the secrets manager.

**Update — monitoring table:** add row:
```
HMAC rotation lag | tokens on ROTATING HMAC > 0 for > 2 hours | WARN | Batch stalled
```

**Update — concurrent rotation rules:**
| Combination | Recommendation |
|-------------|---------------|
| KEK + HMAC simultaneously | Avoid — both write `token_vault` rows; retries occur but throughput degrades |
| Emergency KEK + HMAC batch in progress | Tolerated — HMAC batch skips COMPROMISED-KEK tokens and resumes after |

### 4B — `docs/ops-runbook.md` (targeted updates)

**§1.4 Secrets Management table:** Remove `TAMPER_DETECTION_SECRET` row.

**§7.4 Tamper Alert in Audit Log:** Remove entire subsection (no longer applicable).

**§8 Production Environment Variables:** Remove `TAMPER_DETECTION_SECRET` row. Update `PAN_HASH_SECRET` description: "Required on first boot to bootstrap HMAC key into DB. Can be removed from secrets manager after first successful HMAC rotation."

**§8 Startup Validation:** Remove `TAMPER_DETECTION_SECRET` fail-fast entry. Update `PAN_HASH_SECRET` note: "Required on first boot only; optional after initial HMAC key is seeded."

**Add metric/alert row** to §4.1 Key Metrics:
```
HMAC rotation lag | tokens on ROTATING HMAC > 0 for > 2 hours | WARN | Batch stalled
```

### 4C — `docs/localstack-kms-runbook.md` (new file)

Content:

```markdown
# LocalStack AWS KMS Runbook

This runbook covers running the tokenisation service against LocalStack (a local AWS KMS
emulator) for development, pre-production testing, and verifying KMS integration before
promoting to real AWS.

## 1. Prerequisites
- Docker and Docker Compose installed
- `awslocal` CLI installed: `pip install awscli-local`
- App built: `mvn package -DskipTests`

## 2. Start LocalStack + Postgres

docker-compose -f docker-compose-localstack.yml up -d

Wait for LocalStack to be healthy:
  docker-compose -f docker-compose-localstack.yml ps

## 3. Provision a KMS Master Key

The init script (`localstack/init-kms.sh`) runs automatically on container start.
Retrieve the created key ID:

  KEY_ID=$(awslocal kms list-keys --region us-east-1 \
    --query 'Keys[0].KeyId' --output text)
  echo "Master key: $KEY_ID"

## 4. Seed the First Key Version

Insert an initial key_versions row (KEK) encrypted under the LocalStack key:

  # Generate a random 32-byte KEK
  KEK_HEX=$(openssl rand -hex 32)

  # Encrypt it via LocalStack KMS
  ENCRYPTED_BLOB=$(awslocal kms encrypt \
    --key-id $KEY_ID \
    --plaintext fileb://<(echo -n $KEK_HEX | xxd -r -p) \
    --encryption-context purpose=kek-unwrap \
    --region us-east-1 \
    --query 'CiphertextBlob' --output text)

  # Insert into DB
  psql postgresql://local:local@localhost:5432/tokenisation -c "
    INSERT INTO key_versions
      (id, kms_key_id, kms_provider, key_alias, encrypted_kek_blob, status,
       activated_at, rotate_by, created_by, key_type)
    VALUES
      (gen_random_uuid(), '$KEY_ID', 'AWS_KMS', 'localstack-initial-key',
       '$ENCRYPTED_BLOB', 'ACTIVE',
       now(), now() + interval '365 days', 'operator', 'KEK');"

## 5. Start the Application

  KMS_PROVIDER=aws \
  AWS_REGION=us-east-1 \
  AWS_KMS_ENDPOINT_OVERRIDE=http://localhost:4566 \
  AWS_KMS_KEY_ARN=$KEY_ID \
  PAN_HASH_SECRET=my-32-byte-local-hmac-secret!!!! \
  DATASOURCE_URL=jdbc:postgresql://localhost:5432/tokenisation \
  DATASOURCE_USER=local \
  DATASOURCE_PASSWORD=local \
  mvn spring-boot:run

Startup logs to confirm:
  "Loaded key version ... (status: ACTIVE) into ring"
  "HMAC ring initialised. Active: ..."

## 6. Verify Tokenisation and Detokenisation

  # Tokenise
  curl -s -X POST http://localhost:8080/api/v1/tokens \
    -H 'Content-Type: application/json' \
    -H 'X-Merchant-ID: MERCHANT_001' \
    -d '{"pan":"4111111111111111","expiryMonth":12,"expiryYear":2030,"cardScheme":"VISA"}' \
    | tee /tmp/token.json

  TOKEN=$(jq -r '.token' /tmp/token.json)

  # Detokenise
  curl -s http://localhost:8080/api/v1/tokens/$TOKEN \
    -H 'X-Merchant-ID: MERCHANT_001'
  # Expected: {"pan":"4111111111111111",...}

## 7. Initiate KEK Rotation via LocalStack

  curl -X POST http://localhost:8080/api/v1/admin/keys/rotate \
    -H 'Content-Type: application/json' \
    -d '{"reason":"SCHEDULED","newKeyAlias":"localstack-key-v2"}'
  # Expected: HTTP 202

Monitor batch (cron disabled by default; trigger manually):
  # Check tokens still on old key
  psql postgresql://local:local@localhost:5432/tokenisation -c "
    SELECT kv.key_alias, COUNT(*) FROM key_versions kv
    JOIN token_vault tv ON tv.key_version_id = kv.id
    WHERE kv.status='ROTATING' AND tv.is_active=TRUE GROUP BY kv.key_alias;"

  # Trigger batch via actuator or wait for cron — see rotation.batch.cron config

After batch:
  curl -s http://localhost:8080/api/v1/tokens/$TOKEN \
    -H 'X-Merchant-ID: MERCHANT_001'
  # Still returns PAN (migrated to new key)

## 8. Initiate HMAC Key Rotation via LocalStack

  curl -X POST http://localhost:8080/api/v1/admin/hmac-keys/rotate \
    -H 'Content-Type: application/json' \
    -d '{"newKeyAlias":"localstack-hmac-v2"}'
  # Expected: HTTP 202

Monitor:
  psql postgresql://local:local@localhost:5432/tokenisation -c "
    SELECT kv.key_alias, COUNT(*) FROM key_versions kv
    JOIN token_vault tv ON tv.hmac_key_version_id = kv.id
    WHERE kv.status='ROTATING' AND tv.is_active=TRUE GROUP BY kv.key_alias;"

After batch completes, verify dedup still works:
  # Tokenise the same PAN again — should return the same token
  curl -s -X POST http://localhost:8080/api/v1/tokens \
    -H 'Content-Type: application/json' \
    -H 'X-Merchant-ID: MERCHANT_001' \
    -d '{"pan":"4111111111111111","expiryMonth":12,"expiryYear":2030,"cardScheme":"VISA"}'
  # token field must equal $TOKEN

## 9. Rotating the LocalStack KMS Master Key Itself

LocalStack supports key rotation (simulated):
  awslocal kms enable-key-rotation --key-id $KEY_ID --region us-east-1

For a full master key replacement (new CMK replacing old):
  1. Create new key:     awslocal kms create-key --region us-east-1
  2. Update key_versions: insert new KEK row with new KMS key ID
  3. Use the KEK rotation endpoint to migrate all tokens

## 10. Troubleshooting

Startup fails: "No ACTIVE key version found"
  → Check key_versions table has a row with key_type='KEK' and status='ACTIVE'
  → Re-run step 4

KMS decrypt fails: "InvalidCiphertextException"
  → The encrypted_kek_blob was not encrypted with the current LocalStack key
  → Recreate the LocalStack container (resets KMS state) and re-run step 4
  → Note: LocalStack KMS state is not persisted across container restarts unless
    a volume is mounted at /var/lib/localstack

HMAC ring fails: "No ACTIVE HMAC key found"
  → PAN_HASH_SECRET env var was not set; bootstrap service couldn't seed the row
  → Set PAN_HASH_SECRET and restart

Rotation batch not running
  → rotation.batch.cron and rotation.hmac-batch.cron are likely "-" (disabled in test profile)
  → Set to a valid cron expression or trigger via admin endpoint
```

---

## Part 5 — LocalStack Integration Tests

### `KmsConfig.java` change (minimal)

Add optional endpoint override to support LocalStack without changing `AwsKmsAdapter`:

```java
@Bean
public KmsClient kmsClient(
        @Value("${kms.aws.region}") String awsRegion,
        @Value("${kms.aws.endpoint-override:#{null}}") String endpointOverride) {
    KmsClientBuilder builder = KmsClient.builder().region(Region.of(awsRegion));
    if (endpointOverride != null && !endpointOverride.isBlank()) {
        builder.endpointOverride(URI.create(endpointOverride))
               .credentialsProvider(StaticCredentialsProvider.create(
                   AwsBasicCredentials.create("test", "test")));
    }
    return builder.build();
}
```

### Docker Compose files

**`docker-compose.yml`** — Postgres only (local KMS adapter):
```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment: { POSTGRES_DB: tokenisation, POSTGRES_USER: local, POSTGRES_PASSWORD: local }
    ports: ["5432:5432"]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U local -d tokenisation"]
      interval: 5s
      retries: 5
```

**`docker-compose-localstack.yml`** — Postgres + LocalStack:
```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment: { POSTGRES_DB: tokenisation, POSTGRES_USER: local, POSTGRES_PASSWORD: local }
    ports: ["5432:5432"]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U local -d tokenisation"]
      interval: 5s
      retries: 5

  localstack:
    image: localstack/localstack:3
    environment: { SERVICES: kms, DEFAULT_REGION: us-east-1 }
    ports: ["4566:4566"]
    volumes:
      - "./localstack/init-kms.sh:/etc/localstack/init/ready.d/init-kms.sh"
    healthcheck:
      test: ["CMD-SHELL", "awslocal kms list-keys --region us-east-1"]
      interval: 5s
      retries: 10
```

`localstack/init-kms.sh` — creates the KMS master key on container start:
```bash
#!/bin/bash
set -e
awslocal kms create-key --description "tokenisation-master-key" --region us-east-1
```

### New Maven dependency

```xml
<dependency>
    <groupId>org.testcontainers</groupId>
    <artifactId>localstack</artifactId>
    <scope>test</scope>
</dependency>
```

Add `localstack` to surefire excluded groups alongside `load`:
```xml
<surefire.excluded.groups>load,localstack</surefire.excluded.groups>
```

New Maven profile:
```xml
<profile>
    <id>localstack-tests</id>
    <build>
        <plugins>
            <plugin>
                <artifactId>maven-surefire-plugin</artifactId>
                <configuration>
                    <groups>localstack</groups>
                    <excludedGroups></excludedGroups>
                </configuration>
            </plugin>
        </plugins>
    </build>
</profile>
```

### `AbstractLocalStackIntegrationTest.java` (new base class)

Standalone — does NOT extend `AbstractIntegrationTest`. Starts Postgres + LocalStack once per JVM.

```java
@SpringBootTest(webEnvironment = RANDOM_PORT)
@ActiveProfiles({"test", "localstack"})
@Tag("localstack")
public abstract class AbstractLocalStackIntegrationTest {

    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine")...;
    static final LocalStackContainer LOCALSTACK =
        new LocalStackContainer(DockerImageName.parse("localstack/localstack:3"))
            .withServices(LocalStackContainer.Service.KMS);

    static { Startables.deepStart(POSTGRES, LOCALSTACK).join(); }

    private static final String KMS_KEY_ID = createKmsKey();

    @DynamicPropertySource
    static void overrideProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("kms.provider", () -> "aws");
        registry.add("kms.aws.region", LOCALSTACK::getRegion);
        registry.add("kms.aws.endpoint-override",
            () -> LOCALSTACK.getEndpointOverride(LocalStackContainer.Service.KMS).toString());
        registry.add("kms.aws.master-key-arn", () -> KMS_KEY_ID);
    }

    private static String createKmsKey() {
        KmsClient client = KmsClient.builder()
            .region(Region.of(LOCALSTACK.getRegion()))
            .endpointOverride(LOCALSTACK.getEndpointOverride(LocalStackContainer.Service.KMS))
            .credentialsProvider(StaticCredentialsProvider.create(
                AwsBasicCredentials.create("test", "test")))
            .build();
        return client.createKey(r -> r.description("test-key")).keyMetadata().keyId();
    }
}
```

Needs its own `TestDataSeederConfig` that seeds `key_versions` using the LocalStack KMS key (calls `kmsProvider.unwrapKek()` to verify the round-trip works, then loads into ring).

`application-localstack.yml`:
```yaml
# Properties resolved by @DynamicPropertySource; this file just documents the profile
tokenisation:
  pan-hash-secret: "localstack-test-hmac-secret-32b!!"
rotation:
  batch:
    cron: "-"
  hmac-batch:
    cron: "-"
```

### LocalStack test classes

**`LocalStackKmsAdapterIntegrationTest.java`** (`@Tag("localstack")`):
- `unwrapKek_roundTrip` — wrap then unwrap produces same 32-byte KEK
- `wrapDek_differentIvEachCall`
- `rewrapDek_producesDecryptableResult`
- `unwrapKek_wrongEncryptionContext_throwsKmsOperationException`
- `describeKey_returnsExpectedMetadata`

**`LocalStackTokenisationIntegrationTest.java`** (`@Tag("localstack")`):
- `tokenise_andDetokenise_viaRealKms_returnsOriginalPan`
- `tokenise_samePan_returnsSameToken`
- `detokenise_expiredToken_returns404`

**`LocalStackHmacRotationIntegrationTest.java`** (`@Tag("localstack")`):
- `hmacBootstrap_createsEncryptedSecretUnderLocalStackKek`
- `hmacRotation_viaLocalStackKek_reHashesAllTokens_andDedup_stillWorks`
- `kekRotation_followedByHmacRotation_allTokensDetokenisable`

---

## Part 6 — File Summary

### Deleted
| File | Reason |
|------|--------|
| `crypto/TamperDetector.java` | TamperDetector removed |
| `config/TamperDetectionProperties.java` | TamperDetector removed |
| `test/crypto/TamperDetectorTest.java` | TamperDetector removed |

### New production code
| File | Description |
|------|-------------|
| `db/migration/V8__add_hmac_key_type.sql` | `key_type`, `encrypted_secret`, `encrypting_kek_id` on `key_versions`; drop `checksum` |
| `db/migration/V9__add_hmac_version_to_vault.sql` | `hmac_key_version_id` on `token_vault` |
| `domain/KeyType.java` | Enum `KEK`, `HMAC` |
| `crypto/HmacKeyMaterial.java` | In-memory HMAC key wrapper |
| `crypto/InMemoryHmacKeyRing.java` | Single-pointer HMAC ring |
| `kms/HmacKeyBootstrapService.java` | `@Order(5)` bootstrap from env var |
| `kms/LocalDevHmacKeySeeder.java` | `@Order(1)` local dev seeder |
| `rotation/HmacRotationService.java` | Rotation orchestrator |
| `rotation/PanHashBatchProcessor.java` | Re-hash batch |
| `rotation/HmacRotationJob.java` | Scheduled job |
| `exception/RotationConflictException.java` | Warning/409 on conflict |

### New test code
| File | Description |
|------|-------------|
| `test/crypto/HmacKeyMaterialTest.java` | Unit test |
| `test/crypto/InMemoryHmacKeyRingTest.java` | Unit test |
| `test/kms/HmacKeyBootstrapServiceTest.java` | Unit test |
| `test/rotation/HmacRotationServiceTest.java` | Unit test |
| `test/rotation/PanHashBatchProcessorTest.java` | Unit test |
| `test/HmacRotationIntegrationTest.java` | Integration test |
| `test/loadtest/HmacRotationUnderLoadTest.java` | Load test |
| `test/AbstractLocalStackIntegrationTest.java` | LocalStack base class |
| `test/kms/LocalStackKmsAdapterIntegrationTest.java` | LocalStack KMS test |
| `test/LocalStackTokenisationIntegrationTest.java` | LocalStack e2e test |
| `test/LocalStackHmacRotationIntegrationTest.java` | LocalStack HMAC test |
| `test/resources/application-localstack.yml` | LocalStack profile config |

### New infrastructure
| File | Description |
|------|-------------|
| `docker-compose.yml` | Postgres only (local KMS adapter) |
| `docker-compose-localstack.yml` | Postgres + LocalStack |
| `localstack/init-kms.sh` | KMS key provisioning on container start |

### Updated docs
| File | Changes |
|------|---------|
| `docs/key-rotation-runbook.md` | Remove checksum/tamper sections; add HMAC rotation procedure |
| `docs/ops-runbook.md` | Remove `TAMPER_DETECTION_SECRET`; update secrets table and startup validation |
| `docs/localstack-kms-runbook.md` | New file — full LocalStack operator guide |

---

## Part 7 — Env Var Retirement

| Phase | Action |
|-------|--------|
| Deploy | `HmacKeyBootstrapService` reads `PAN_HASH_SECRET`, seeds HMAC row, backfills vault |
| Verify | Logs show HMAC ring loaded; spot-check `key_versions` for HMAC row; `mvn test` green |
| First HMAC rotation | New 32-byte `SecureRandom` key replaces env var value; env var no longer referenced at runtime |
| Post-rotation | Remove `PAN_HASH_SECRET` from secrets manager |
| Remove `TAMPER_DETECTION_SECRET` | Done in this feature — no longer needed |
