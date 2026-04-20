# Card Tokenisation System — Implementation Plan

**Stack:** Spring Boot · PostgreSQL · Testcontainers  
**Approach:** Feature-phased delivery — Tokenisation → Detokenisation → Key Rotation

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture](#2-architecture)
3. [Project Structure](#3-project-structure)
4. [Database Design](#4-database-design)
5. [KMS Abstraction Layer](#5-kms-abstraction-layer)
6. [Phase 1 — Tokenisation](#6-phase-1--tokenisation)
7. [Phase 2 — Detokenisation](#7-phase-2--detokenisation)
8. [Phase 3 — Key Rotation](#8-phase-3--key-rotation)
9. [Security Hardening](#9-security-hardening)
10. [Testing Strategy](#10-testing-strategy) — Unit · Integration · Load (1K → 50K) · Rotation Under Load · Tamper Under Load
11. [Configuration Reference](#11-configuration-reference)
12. [Pitfalls & Mitigations](#12-pitfalls--mitigations)
13. [Clean Code Standards](#13-clean-code-standards)
14. [Progress Tracking](#14-progress-tracking)
15. [Delivery Checklist](#15-delivery-checklist)

---

## 1. Project Overview

### Goals

- Replace raw PANs with opaque, irreversible tokens stored in a secure vault
- Support both **deterministic** tokens (recurring billing — same PAN → same token) and **non-deterministic** tokens (one-off payments — new token each call)
- Abstract all KMS operations behind a provider interface so AWS KMS can be swapped for Azure Key Vault, GCP KMS, or HashiCorp Vault without touching business logic
- Load the master Key Encryption Key (KEK) **once at startup** to minimise runtime KMS dependency
- Support scheduled (compliance) and emergency (compromise) key rotation with zero downtime

### Non-Goals (out of scope for this plan)

- Payment network tokenisation (Visa Token Service, Mastercard MDES) — this is a vault tokenisation system
- Card scheme validation beyond Luhn check
- PCI-DSS audit certification process (though the design supports it)

### Compliance Context

- Tokens must never be reversible without the vault
- PAN must never appear in logs, error messages, or audit trails
- Audit log must be append-only and tamper-evident
- Keys must have a maximum active lifetime (configurable, default 365 days)
- Key rotation history must be retained for the full data retention period

---

## 2. Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                    REST API (mTLS enforced)                    │
│              POST /tokens    GET /tokens/{token}               │
└───────────────────────────────┬───────────────────────────────┘
                                │
┌───────────────────────────────▼───────────────────────────────┐
│                    TokenisationService                         │
│                    DetokenisationService                       │
│                    KeyRotationService                          │
└──────────┬───────────────────────────────────────┬────────────┘
           │                                       │
┌──────────▼──────────┐               ┌────────────▼───────────┐
│  InMemoryKeyRing    │               │   TokenVaultRepository  │
│  (startup-loaded    │               │   KeyVersionRepository  │
│   KEK, versioned)   │               │   AuditLogRepository    │
└──────────┬──────────┘               └────────────┬───────────┘
           │                                       │
┌──────────▼──────────┐               ┌────────────▼───────────┐
│   KmsProvider       │               │      PostgreSQL         │
│   (interface)       │               │                         │
│  ┌───────────────┐  │               │  token_vault            │
│  │AwsKmsAdapter  │  │               │  key_versions           │
│  └───────────────┘  │               │  token_audit_log        │
│  ┌───────────────┐  │               └────────────────────────┘
│  │AzureKvAdapter │  │
│  └───────────────┘  │
│  ┌───────────────┐  │
│  │VaultAdapter   │  │
│  └───────────────┘  │
└─────────────────────┘
```

### Key Design Decisions

| Decision | Choice | Rationale |
|---|---|---|
| KEK loading | Once at startup | Minimise KMS runtime dependency; bounded TTL refresh every 24h |
| Encryption | AES-256-GCM | Authenticated encryption; detects ciphertext tampering |
| Token format | Random UUID or Luhn-valid 16-digit | UUID for simplicity; Luhn-valid if downstream systems validate format |
| PAN de-dup | SHA-256 hash of PAN | Enables deterministic token lookup without storing PAN in clear |
| Audit log | Append-only, separate DB user | Immutability guarantee; supports PCI audit trail |
| Key ring | In-memory `ConcurrentHashMap` | Multiple versions live in memory during rotation cutover |

---

## 3. Project Structure

```
card-tokenisation/
├── src/
│   ├── main/
│   │   ├── java/com/yourorg/tokenisation/
│   │   │   ├── TokenisationApplication.java
│   │   │   │
│   │   │   ├── api/
│   │   │   │   ├── TokenController.java
│   │   │   │   ├── request/
│   │   │   │   │   └── TokeniseRequest.java
│   │   │   │   └── response/
│   │   │   │       ├── TokeniseResponse.java
│   │   │   │       └── DetokeniseResponse.java
│   │   │   │
│   │   │   ├── service/
│   │   │   │   ├── TokenisationService.java
│   │   │   │   ├── DetokenisationService.java
│   │   │   │   └── KeyRotationService.java
│   │   │   │
│   │   │   ├── crypto/
│   │   │   │   ├── AesGcmCipher.java           # local AES-256-GCM encrypt/decrypt
│   │   │   │   ├── PanHasher.java              # SHA-256 HMAC of PAN for de-dup
│   │   │   │   ├── InMemoryKeyRing.java        # versioned in-memory KEK store
│   │   │   │   └── KeyRingInitialiser.java     # startup bean, calls KMS once
│   │   │   │
│   │   │   ├── kms/
│   │   │   │   ├── KmsProvider.java            # interface
│   │   │   │   ├── KmsEncryptResult.java
│   │   │   │   ├── KmsDecryptResult.java
│   │   │   │   ├── AwsKmsAdapter.java
│   │   │   │   ├── AzureKeyVaultAdapter.java   # stub, not implemented yet
│   │   │   │   └── LocalDevKmsAdapter.java     # for local dev / tests
│   │   │   │
│   │   │   ├── domain/
│   │   │   │   ├── TokenVault.java             # JPA entity
│   │   │   │   ├── KeyVersion.java             # JPA entity
│   │   │   │   ├── TokenAuditLog.java          # JPA entity
│   │   │   │   ├── TokenType.java              # RECURRING | ONE_TIME
│   │   │   │   ├── KeyStatus.java              # ACTIVE | ROTATING | RETIRED | COMPROMISED
│   │   │   │   └── RotationReason.java         # SCHEDULED | COMPROMISE | MANUAL
│   │   │   │
│   │   │   ├── repository/
│   │   │   │   ├── TokenVaultRepository.java
│   │   │   │   ├── KeyVersionRepository.java
│   │   │   │   └── AuditLogRepository.java
│   │   │   │
│   │   │   ├── audit/
│   │   │   │   ├── AuditEventType.java
│   │   │   │   └── AuditLogger.java
│   │   │   │
│   │   │   ├── rotation/
│   │   │   │   ├── RotationJob.java            # Spring @Scheduled batch re-encryption
│   │   │   │   ├── RotationBatchProcessor.java
│   │   │   │   └── TamperDetector.java         # HMAC checksum on key_versions rows
│   │   │   │
│   │   │   └── config/
│   │   │       ├── KmsConfig.java
│   │   │       ├── SecurityConfig.java
│   │   │       └── SchedulingConfig.java
│   │   │
│   │   └── resources/
│   │       ├── application.yml
│   │       ├── application-local.yml
│   │       └── db/migration/                   # Flyway migrations
│   │           ├── V1__create_key_versions.sql
│   │           ├── V2__create_token_vault.sql
│   │           ├── V3__create_audit_log.sql
│   │           └── V4__create_indexes.sql
│   │
│   └── test/
│       ├── java/com/yourorg/tokenisation/
│       │   ├── AbstractIntegrationTest.java    # Testcontainers base class
│       │   ├── api/
│       │   │   ├── TokenisationIntegrationTest.java
│       │   │   └── DetokenisationIntegrationTest.java
│       │   ├── service/
│       │   │   ├── TokenisationServiceTest.java
│       │   │   └── DetokenisationServiceTest.java
│       │   ├── crypto/
│       │   │   ├── AesGcmCipherTest.java
│       │   │   └── InMemoryKeyRingTest.java
│       │   └── rotation/
│       │       ├── RotationJobIntegrationTest.java
│       │       └── TamperDetectorTest.java
│       └── resources/
│           └── application-test.yml
│
├── pom.xml
└── README.md
```

---

## 4. Database Design

### Flyway Migration: V1 — Key Versions

```sql
-- V1__create_key_versions.sql
CREATE TABLE key_versions (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kms_key_id       VARCHAR(255)  NOT NULL,
    kms_provider     VARCHAR(50)   NOT NULL,            -- AWS_KMS | AZURE_KV | LOCAL_DEV
    key_alias        VARCHAR(100)  NOT NULL,
    status           VARCHAR(20)   NOT NULL DEFAULT 'ACTIVE',
    rotation_reason  VARCHAR(20),                       -- SCHEDULED | COMPROMISE | MANUAL
    activated_at     TIMESTAMPTZ   NOT NULL DEFAULT now(),
    retired_at       TIMESTAMPTZ,
    rotate_by        TIMESTAMPTZ   NOT NULL,            -- compliance deadline
    created_by       VARCHAR(100)  NOT NULL,
    checksum         VARCHAR(64)   NOT NULL,            -- HMAC integrity check on this row
    CONSTRAINT chk_status CHECK (status IN ('ACTIVE','ROTATING','RETIRED','COMPROMISED'))
);
```

### Flyway Migration: V2 — Token Vault

```sql
-- V2__create_token_vault.sql
CREATE TABLE token_vault (
    token_id         UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    token            VARCHAR(36)   NOT NULL UNIQUE,     -- the surrogate (UUID or Luhn-valid)
    encrypted_pan    BYTEA         NOT NULL,            -- AES-256-GCM ciphertext
    iv               BYTEA         NOT NULL,            -- 12-byte GCM IV, stored per-record
    auth_tag         BYTEA         NOT NULL,            -- 16-byte GCM authentication tag
    encrypted_dek    BYTEA         NOT NULL,            -- DEK wrapped by KEK
    key_version_id   UUID          NOT NULL REFERENCES key_versions(id),
    pan_hash         VARCHAR(64)   NOT NULL,            -- HMAC-SHA256 for de-dup lookup
    token_type       VARCHAR(20)   NOT NULL,            -- RECURRING | ONE_TIME
    last_four        VARCHAR(4)    NOT NULL,            -- stored in clear, not sensitive
    card_scheme      VARCHAR(10),                       -- VISA | MC | AMEX | EFTPOS
    expiry_month     SMALLINT,
    expiry_year      SMALLINT,
    merchant_id      VARCHAR(100),                     -- optional scope — token belongs to this merchant
    created_at       TIMESTAMPTZ   NOT NULL DEFAULT now(),
    expires_at       TIMESTAMPTZ,
    is_active        BOOLEAN       NOT NULL DEFAULT TRUE,
    record_version   INTEGER       NOT NULL DEFAULT 1, -- optimistic locking for rotation updates
    CONSTRAINT chk_token_type CHECK (token_type IN ('RECURRING','ONE_TIME'))
);
```

### Flyway Migration: V3 — Audit Log

```sql
-- V3__create_audit_log.sql
CREATE TABLE token_audit_log (
    id               BIGSERIAL     PRIMARY KEY,
    event_type       VARCHAR(50)   NOT NULL,
    token_id         UUID,
    key_version_id   UUID,
    actor_id         VARCHAR(100),
    actor_ip         INET,
    merchant_id      VARCHAR(100),
    outcome          VARCHAR(10)   NOT NULL,            -- SUCCESS | FAILURE
    failure_reason   VARCHAR(200),
    metadata         JSONB,
    created_at       TIMESTAMPTZ   NOT NULL DEFAULT now()
    -- No UPDATE or DELETE ever. Enforce with DB role:
    -- GRANT INSERT, SELECT ON token_audit_log TO tokenisation_app;
    -- REVOKE UPDATE, DELETE ON token_audit_log FROM tokenisation_app;
);

-- Partition by month for query performance at scale
-- (apply via pg_partman or manual partitioning in production)
```

### Flyway Migration: V4 — Indexes

```sql
-- V4__create_indexes.sql

-- Detokenisation hot path
CREATE UNIQUE INDEX idx_token_vault_token        ON token_vault(token);

-- Deterministic de-dup: "does this PAN already have a RECURRING token?"
CREATE INDEX idx_token_vault_pan_hash            ON token_vault(pan_hash) WHERE token_type = 'RECURRING';

-- Rotation job: "find all tokens that use this key version"
CREATE INDEX idx_token_vault_key_version         ON token_vault(key_version_id) WHERE is_active = TRUE;

-- Merchant scoping
CREATE INDEX idx_token_vault_merchant            ON token_vault(merchant_id);

-- Audit log queries
CREATE INDEX idx_audit_log_token_id              ON token_audit_log(token_id);
CREATE INDEX idx_audit_log_created_at            ON token_audit_log(created_at);

-- Key version lookups
CREATE UNIQUE INDEX idx_key_versions_active      ON key_versions(status) WHERE status = 'ACTIVE';
```

---

## 5. KMS Abstraction Layer

### Interface

```java
public interface KmsProvider {

    /**
     * Called ONCE at startup. Decrypts the stored encrypted KEK blob
     * and returns the raw key bytes to be held in-memory.
     */
    byte[] unwrapKek(String encryptedKekBlob);

    /**
     * Generate a new Data Encryption Key (DEK) and return both the
     * plaintext bytes and the KEK-encrypted blob for storage.
     */
    GeneratedDek generateDek(String keyVersionId);

    /**
     * Re-wrap a DEK under a new key version during rotation.
     * Old KEK decrypts, new KEK re-encrypts — in-memory only.
     */
    byte[] rewrapDek(byte[] encryptedDek, String oldKeyVersionId, String newKeyVersionId);

    /**
     * Describe key metadata — used for tamper reconciliation job.
     */
    KeyMetadata describeKey(String kmsKeyId);
}
```

### AWS KMS Adapter

```java
@Component
@ConditionalOnProperty(name = "kms.provider", havingValue = "aws")
public class AwsKmsAdapter implements KmsProvider {

    private final KmsClient kmsClient;
    private final String masterKeyArn;

    @Override
    public byte[] unwrapKek(String encryptedKekBlob) {
        DecryptRequest request = DecryptRequest.builder()
            .ciphertextBlob(SdkBytes.fromByteArray(Base64.decode(encryptedKekBlob)))
            .keyId(masterKeyArn)
            .encryptionContext(Map.of("purpose", "kek-unwrap"))
            .build();
        return kmsClient.decrypt(request).plaintext().asByteArray();
    }

    @Override
    public GeneratedDek generateDek(String keyVersionId) {
        GenerateDataKeyRequest request = GenerateDataKeyRequest.builder()
            .keyId(masterKeyArn)
            .keySpec(DataKeySpec.AES_256)
            .encryptionContext(Map.of("keyVersionId", keyVersionId))
            .build();
        GenerateDataKeyResponse response = kmsClient.generateDataKey(request);
        return new GeneratedDek(
            response.plaintext().asByteArray(),      // held in memory briefly, then zeroed
            response.ciphertextBlob().asByteArray()  // stored in DB
        );
    }

    // ... rewrapDek, describeKey
}
```

### Local Dev Adapter (for testing without AWS)

```java
@Component
@ConditionalOnProperty(name = "kms.provider", havingValue = "local-dev")
public class LocalDevKmsAdapter implements KmsProvider {
    // Uses a hardcoded local AES key — NEVER for production
    // Allows all unit and integration tests to run without any cloud dependency
}
```

### In-Memory Key Ring

```java
@Component
public class InMemoryKeyRing {

    private final ConcurrentHashMap<String, KeyMaterial> keys = new ConcurrentHashMap<>();
    private volatile String activeKeyVersionId;

    public void load(String keyVersionId, byte[] kek, Instant expiresAt) {
        keys.put(keyVersionId, new KeyMaterial(kek, keyVersionId, expiresAt));
    }

    public void promoteActive(String keyVersionId) {
        if (!keys.containsKey(keyVersionId)) {
            throw new IllegalStateException("Key version not loaded: " + keyVersionId);
        }
        this.activeKeyVersionId = keyVersionId;
    }

    public KeyMaterial getActive() {
        return Optional.ofNullable(keys.get(activeKeyVersionId))
            .orElseThrow(() -> new IllegalStateException("No active key in ring"));
    }

    public KeyMaterial getByVersion(String versionId) {
        return Optional.ofNullable(keys.get(versionId))
            .orElseThrow(() -> new KeyVersionNotFoundException(versionId));
    }

    /** Called during rotation — old version stays in ring for decryption until migration complete */
    public void retire(String keyVersionId) {
        // Mark as retired but don't remove — detokenisation of old tokens still needs it
        keys.computeIfPresent(keyVersionId, (k, v) -> v.asRetired());
    }
}
```

### Startup Initialiser

```java
@Component
@Slf4j
public class KeyRingInitialiser implements ApplicationRunner {

    private final KmsProvider kmsProvider;
    private final KeyVersionRepository keyVersionRepository;
    private final InMemoryKeyRing keyRing;

    @Override
    public void run(ApplicationArguments args) {
        log.info("Initialising key ring from KMS — single startup call");

        List<KeyVersion> activeVersions = keyVersionRepository
            .findByStatusIn(List.of(KeyStatus.ACTIVE, KeyStatus.ROTATING));

        for (KeyVersion version : activeVersions) {
            byte[] kek = kmsProvider.unwrapKek(version.getEncryptedKekBlob());
            keyRing.load(version.getId(), kek, version.getRotateBy());
            log.info("Loaded key version {} into ring", version.getId());
        }

        KeyVersion active = keyVersionRepository.findActiveOrThrow();
        keyRing.promoteActive(active.getId());

        log.info("Key ring initialised. Active version: {}", active.getId());
    }
}
```

---

## 6. Phase 1 — Tokenisation

### Scope

- Accept a PAN + metadata, return a token
- Deterministic: if a RECURRING token already exists for this PAN (+merchant), return it
- Non-deterministic: always generate a new token for ONE_TIME
- Store encrypted PAN using envelope encryption (DEK encrypted by in-memory KEK)
- Emit audit log on every call (success and failure)

### API

```
POST /api/v1/tokens
Content-Type: application/json
Authorization: Bearer <service-token>

{
  "pan": "4111111111111111",
  "expiryMonth": 12,
  "expiryYear": 2027,
  "cardScheme": "VISA",
  "tokenType": "RECURRING",
  "merchantId": "MERCHANT_001"
}

Response 201:
{
  "token": "550e8400-e29b-41d4-a716-446655440000",
  "tokenType": "RECURRING",
  "lastFour": "1111",
  "cardScheme": "VISA",
  "createdAt": "2025-04-16T10:00:00Z"
}
```

### Service Logic

```
TokenisationService.tokenise(request):

1.  Validate PAN format (Luhn check)
2.  Compute panHash = HMAC-SHA256(PAN, hashingSecret)
3.  If tokenType == RECURRING:
      a. Query token_vault WHERE pan_hash = ? AND merchant_id = ? AND token_type = 'RECURRING' AND is_active = TRUE
      b. If found → return existing token (no new crypto, no new DB write, just audit log)
4.  Get active KeyMaterial from InMemoryKeyRing
5.  Generate fresh 256-bit DEK (random, local — no KMS call)
6.  Encrypt DEK with KEK using AES-256-GCM → encryptedDek
7.  Encrypt PAN with DEK using AES-256-GCM → encryptedPan + IV + authTag
8.  Zero the DEK byte array from memory
9.  Generate token value (UUID.randomUUID() or Luhn-valid format)
10. Persist TokenVault record
11. Write TOKENISE SUCCESS to audit log
12. Return TokeniseResponse

On any exception:
  - Write TOKENISE FAILURE to audit log (no PAN in log)
  - Zero any key material in local scope
  - Rethrow as domain exception
```

### Encryption Detail (AesGcmCipher)

```java
public EncryptResult encrypt(byte[] plaintext, byte[] kek) {
    byte[] dek = new byte[32];
    SecureRandom.getInstanceStrong().nextBytes(dek);

    byte[] iv = new byte[12];                          // 96-bit IV for GCM
    SecureRandom.getInstanceStrong().nextBytes(iv);

    try {
        SecretKeySpec dekKey = new SecretKeySpec(dek, "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);  // 128-bit auth tag
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, dekKey, spec);
        byte[] ciphertext = cipher.doFinal(plaintext);

        byte[] encryptedDek = wrapDek(dek, kek);       // AES-KW or AES-GCM wrap

        return new EncryptResult(ciphertext, iv, encryptedDek);
    } finally {
        Arrays.fill(dek, (byte) 0);                    // zero DEK immediately
    }
}
```

### Acceptance Criteria (Phase 1)

- [ ] RECURRING tokenisation of same PAN + merchant returns identical token on repeat calls
- [ ] ONE_TIME tokenisation of same PAN always generates a new token
- [ ] No PAN appears in any log output (verified by log assertion in tests)
- [ ] Tokenisation fails safely if key ring has no active key (returns 503, not 500)
- [ ] DEK byte arrays are zeroed after every encrypt operation
- [ ] Audit log record created for every call (success and failure)

---

## 7. Phase 2 — Detokenisation

### Scope

- Accept a token, return the PAN + card metadata
- Enforce merchant scoping (token issued for merchant A cannot be detokenised by merchant B)
- Rate-limited endpoint — this is the highest-risk operation
- Full audit trail including caller identity and IP

### API

```
GET /api/v1/tokens/{token}
Authorization: Bearer <service-token>
X-Merchant-ID: MERCHANT_001

Response 200:
{
  "pan": "4111111111111111",
  "expiryMonth": 12,
  "expiryYear": 2027,
  "cardScheme": "VISA",
  "lastFour": "1111",
  "tokenType": "RECURRING"
}

Response 403: token does not belong to requesting merchant
Response 404: token not found or inactive
Response 429: rate limit exceeded
```

### Service Logic

```
DetokenisationService.detokenise(token, merchantId):

1.  Look up TokenVault by token value
2.  Verify is_active = TRUE (return 404 if inactive/expired)
3.  Verify merchantId matches token's merchant_id (return 403 if mismatch)
4.  Look up KeyMaterial in InMemoryKeyRing by key_version_id
      - If key status is COMPROMISED → write TAMPER_ALERT to audit log, throw exception
5.  Unwrap DEK: AES-GCM decrypt encryptedDek using KEK from key ring
6.  Decrypt PAN: AES-GCM decrypt encryptedPan using DEK + stored IV + authTag
      - If GCM auth tag fails → data has been tampered with → write TAMPER_ALERT, throw exception
7.  Zero the DEK byte array
8.  Write DETOKENISE SUCCESS to audit log (no PAN in log)
9.  Return DetokeniseResponse

On GCM auth failure:
  - Write TAMPER_ALERT event with token_id and key_version_id
  - Alert security team (publish to internal event topic)
  - Return 500 (do not reveal tamper detail to caller)
```

### Rate Limiting

Apply via Spring `HandlerInterceptor` or a gateway-layer rule:

```yaml
# application.yml
detokenisation:
  rate-limit:
    per-merchant-per-minute: 1000
    per-service-per-minute: 10000
    burst-multiplier: 1.5
```

Use a token bucket implementation backed by Redis (or in-memory Caffeine for single-node deployments).

### Acceptance Criteria (Phase 2)

- [ ] Detokenisation returns correct PAN for a token created in Phase 1
- [ ] Cross-merchant detokenisation returns 403
- [ ] Inactive/expired tokens return 404, not the PAN
- [ ] GCM authentication failure triggers TAMPER_ALERT audit event
- [ ] Key in COMPROMISED status blocks detokenisation
- [ ] DEK zeroed after every operation
- [ ] Rate limiter returns 429 when threshold exceeded
- [ ] PAN does not appear in any log, trace, or error response

---

## 8. Phase 3 — Key Rotation

### Scope

Two distinct rotation flows, sharing the same re-encryption pipeline:

| Flow | Trigger | Urgency | Token access during rotation |
|---|---|---|---|
| **Scheduled** | Compliance deadline (annual) | Low — days to complete | Normal |
| **Emergency** | Compromise detected | High — hours | Detokenisation suspended for affected tokens |

### 8.1 Scheduled Rotation

#### Phase 3a — Prepare

```
Admin calls: POST /api/v1/admin/keys/rotate
  {
    "reason": "SCHEDULED",
    "newKeyAlias": "tokenisation-key-2026"
  }

KeyRotationService.initiateScheduledRotation():

1.  Call KmsProvider.generateNewKeyVersion() → returns new KMS key ID
2.  Call KmsProvider.unwrapKek(newEncryptedBlob) → new KEK bytes
3.  Load new KEK into InMemoryKeyRing (not yet active)
4.  Persist new KeyVersion record (status = ROTATING)
5.  Mark old KeyVersion as ROTATING (still valid for decrypt and encrypt)
6.  Write KEY_ROTATION_STARTED to audit log
7.  Return rotation job ID
```

#### Phase 3b — Batch Re-encryption Job

```java
@Scheduled(cron = "${rotation.batch.cron:0 */15 * * * *}")
public void processRotationBatch() {
    Optional<KeyVersion> rotatingVersion = keyVersionRepository.findOldestRotating();
    if (rotatingVersion.isEmpty()) return;

    String oldVersionId = rotatingVersion.get().getId();
    String newVersionId = keyVersionRepository.findActive().getId();

    // Fetch a batch of tokens still on the old key
    List<TokenVault> batch = tokenVaultRepository
        .findByKeyVersionIdAndIsActive(oldVersionId, true, PageRequest.of(0, BATCH_SIZE));

    for (TokenVault token : batch) {
        try {
            reencryptToken(token, oldVersionId, newVersionId);
        } catch (Exception e) {
            log.error("Re-encryption failed for token {}", token.getTokenId(), e);
            auditLogger.write(RE_ENCRYPTION_FAILURE, token.getTokenId());
            // Continue batch — don't fail entire job on single record error
        }
    }

    // Check if migration complete
    long remaining = tokenVaultRepository.countByKeyVersionId(oldVersionId);
    if (remaining == 0) {
        completeRotation(oldVersionId);
    }
}

private void reencryptToken(TokenVault token, String oldVersionId, String newVersionId) {
    KeyMaterial oldKey = keyRing.getByVersion(oldVersionId);
    KeyMaterial newKey = keyRing.getByVersion(newVersionId);

    // Decrypt DEK with old KEK
    byte[] dek = aesGcmCipher.unwrapDek(token.getEncryptedDek(), oldKey.getKek());

    try {
        // Re-wrap DEK with new KEK
        byte[] newEncryptedDek = aesGcmCipher.wrapDek(dek, newKey.getKek());

        // Update record with optimistic locking
        tokenVaultRepository.reencryptToken(
            token.getTokenId(),
            newEncryptedDek,
            newVersionId,
            token.getRecordVersion()   // fails if concurrent update
        );

        auditLogger.write(TOKEN_REENCRYPTED, token.getTokenId());
    } finally {
        Arrays.fill(dek, (byte) 0);
    }
}
```

#### Phase 3c — Cutover

```
When remaining == 0:

1.  Verify count is truly zero (double-check query with SELECT FOR UPDATE)
2.  Mark old KeyVersion as RETIRED in DB
3.  keyRing.retire(oldVersionId)             // stays in ring for audit lookups
4.  keyRing.promoteActive(newVersionId)      // new tokenisations use new key
5.  Write KEY_ROTATION_COMPLETED to audit log
```

### 8.2 Emergency Rotation (Compromise)

```
Admin calls: POST /api/v1/admin/keys/rotate
  {
    "reason": "COMPROMISE",
    "compromisedVersionId": "uuid-of-compromised-key",
    "suspendDetokenisation": true
  }

KeyRotationService.initiateEmergencyRotation():

1.  Immediately set compromised KeyVersion status = COMPROMISED (synchronous DB write)
2.  keyRing.markCompromised(compromisedVersionId)
3.  Generate + load new KeyVersion (same as scheduled Phase 3a)
4.  Promote new version as active immediately
5.  Write KEY_COMPROMISED + KEY_ROTATION_STARTED to audit log
6.  Alert security team (email/PagerDuty/Slack — configurable)
7.  If suspendDetokenisation=true:
      - Set a flag in Redis/DB that blocks detokenisation for tokens on compromised key
      - Detokenise calls for affected tokens return 503 with a support reference code
8.  Run batch re-encryption job at elevated priority (smaller batch size, higher frequency)
```

### 8.3 Tamper Detection

```java
@Component
public class TamperDetector {

    private final String signingSecret;  // separate from KEK, from app config/Secrets Manager

    public String computeChecksum(KeyVersion kv) {
        String payload = kv.getId()
            + kv.getKmsKeyId()
            + kv.getStatus().name()
            + kv.getActivatedAt().toString();
        return hmacSha256(payload, signingSecret);
    }

    public void assertIntegrity(KeyVersion kv) {
        String expected = computeChecksum(kv);
        if (!MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                kv.getChecksum().getBytes(StandardCharsets.UTF_8))) {
            auditLogger.write(TAMPER_ALERT, kv.getId(), "key_versions row checksum mismatch");
            alertSecurityTeam(kv.getId());
            throw new KeyIntegrityException("Key version integrity check failed: " + kv.getId());
        }
    }
}
```

Run `assertIntegrity` on every key_versions row read during startup and rotation.

### Acceptance Criteria (Phase 3)

- [ ] Scheduled rotation completes with zero tokens remaining on old key
- [ ] New tokenisations use new key immediately after `promoteActive`
- [ ] Detokenisation of tokens created before rotation works correctly (old key stays in ring)
- [ ] Re-encryption job handles failures per-record without aborting the batch
- [ ] Emergency rotation immediately blocks detokenisation of compromised-key tokens (if flag set)
- [ ] Tamper detection on key_versions row throws `KeyIntegrityException` and emits audit event
- [ ] Retired key material is NOT removed from KMS (verifiable via KMS console)
- [ ] Full rotation audit trail persisted in token_audit_log

---

## 9. Security Hardening

### PAN Masking in Logs

```java
// LogbackFilter — applied globally to all appenders
public class PanMaskingFilter extends TurboFilter {
    private static final Pattern PAN_PATTERN =
        Pattern.compile("\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\\b");

    @Override
    public FilterReply decide(..., String message, ...) {
        // Mask PANs in log messages before they reach any appender
        // Applies to message AND any Throwable stack traces
    }
}
```

### Memory Safety

- Use `byte[]` for all key material — never `String` (strings are interned, can't be zeroed)
- Wrap sensitive operations in try/finally with `Arrays.fill(keyBytes, (byte) 0)`
- Avoid logging key material at any level — use key version IDs in logs, never bytes

### Database Roles

```sql
-- Application role: cannot delete or update audit log
CREATE ROLE tokenisation_app;
GRANT SELECT, INSERT, UPDATE ON token_vault TO tokenisation_app;
GRANT SELECT, INSERT, UPDATE ON key_versions TO tokenisation_app;
GRANT SELECT, INSERT ON token_audit_log TO tokenisation_app;   -- INSERT only, no UPDATE/DELETE

-- Rotation job role: same as app but with explicit UPDATE on token_vault
-- Reconciliation / admin role: separate, for ops tooling only
```

### API Security

- mTLS between internal services
- JWT with short expiry (15 minutes) for service-to-service calls
- Merchant ID extracted from JWT claims, not from request body (prevents spoofing)
- Detokenise endpoint rate-limited per merchant + per service

---

## 10. Testing Strategy

Testing is structured in three tiers. All three tiers must pass before any phase is considered shippable.

```
Tier 1 — Unit Tests          Fast, isolated, no Spring context, no DB
Tier 2 — Integration Tests   Full stack with real PostgreSQL (Testcontainers)
Tier 3 — Load Tests          Concurrent volume tests with system metric monitoring
```

---

### 10.1 Testcontainers Base Classes

Two base classes — one for functional integration tests, one for load tests (different container tuning).

```java
/**
 * Base class for all functional integration tests.
 * Provides a real PostgreSQL instance via Testcontainers with container reuse
 * across test classes to reduce total suite time.
 *
 * All subclasses use LocalDevKmsAdapter — no cloud dependency.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
public abstract class AbstractIntegrationTest {

    @Container
    static final PostgreSQLContainer<?> postgres =
        new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("tokenisation_test")
            .withUsername("test")
            .withPassword("test")
            .withReuse(true);

    @DynamicPropertySource
    static void overrideProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("kms.provider", () -> "local-dev");
    }
}
```

```java
/**
 * Base class for load tests.
 * PostgreSQL is tuned for concurrent writes: larger shared_buffers,
 * higher max_connections, and wal_level = minimal for write throughput.
 *
 * Container is NOT reused — each load test class gets a clean database
 * to prevent token vault size from previous runs skewing timings.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("load-test")
@Tag("load")
public abstract class AbstractLoadTest {

    @Container
    static final PostgreSQLContainer<?> postgres =
        new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("tokenisation_load")
            .withUsername("test")
            .withPassword("test")
            .withCommand(
                "postgres",
                "-c", "shared_buffers=256MB",
                "-c", "max_connections=200",
                "-c", "work_mem=16MB",
                "-c", "synchronous_commit=off"    // async commit for load test throughput
            );
            // NOTE: synchronous_commit=off is intentional for load tests only.
            // Production always uses synchronous_commit=on.

    @Autowired
    protected TestRestTemplate restTemplate;

    @Autowired
    protected TokenVaultRepository tokenVaultRepository;

    @Autowired
    protected AuditLogRepository auditLogRepository;

    /** Returns a snapshot of JVM memory and system CPU for metric recording. */
    protected SystemMetrics captureMetrics() {
        Runtime runtime = Runtime.getRuntime();
        OperatingSystemMXBean osMxBean = ManagementFactory.getOperatingSystemMXBean();
        return SystemMetrics.builder()
            .heapUsedMb((runtime.totalMemory() - runtime.freeMemory()) / 1_048_576L)
            .heapMaxMb(runtime.maxMemory() / 1_048_576L)
            .systemLoadAverage(osMxBean.getSystemLoadAverage())
            .availableProcessors(runtime.availableProcessors())
            .capturedAt(Instant.now())
            .build();
    }

    /** Blocks until the virtual thread executor drains or the timeout elapses. */
    protected void awaitCompletion(ExecutorService executor, Duration timeout)
            throws InterruptedException {
        executor.shutdown();
        if (!executor.awaitTermination(timeout.toSeconds(), TimeUnit.SECONDS)) {
            executor.shutdownNow();
            throw new AssertionError("Load test executor did not complete within " + timeout);
        }
    }
}
```

---

### 10.2 Unit Test Coverage Matrix

| Test Class | Type | Scenarios covered |
|---|---|---|
| `AesGcmCipherTest` | Unit | Encrypt/decrypt round-trip; IV uniqueness across calls; GCM auth tag failure; DEK zeroed after encrypt; 32-byte key enforced |
| `PanHasherTest` | Unit | Hash is deterministic; different PANs produce different hashes; hash does not contain PAN substring |
| `InMemoryKeyRingTest` | Unit | Load + promote; getActive returns correct version; getByVersion for retired key; missing version throws; concurrent load does not corrupt state |
| `TamperDetectorTest` | Unit | Checksum matches on unmodified row; checksum mismatch throws `KeyIntegrityException`; mismatch writes TAMPER_ALERT audit event |
| `TokenisationServiceTest` | Unit | Recurring PAN returns same token on repeat; ONE_TIME always generates new token; null PAN throws `PanValidationException`; invalid Luhn throws; audit log called on success; audit log called on failure |
| `DetokenisationServiceTest` | Unit | Correct PAN returned; wrong merchant throws `MerchantScopeException`; inactive token throws `TokenNotFoundException`; compromised key throws and writes audit; tampered ciphertext triggers TAMPER_ALERT |
| `KeyRotationServiceTest` | Unit | Scheduled rotation creates new key version; emergency rotation sets COMPROMISED status synchronously; new version promoted as active |
| `RotationBatchProcessorTest` | Unit | Re-encryption succeeds with optimistic lock; stale `record_version` triggers retry; DEK zeroed after re-encryption |

---

### 10.3 Functional Integration Tests

All tests in this section extend `AbstractIntegrationTest`, use a real PostgreSQL container, and assert on both the HTTP response **and** the resulting database state.

#### Tokenisation

```java
class TokenisationIntegrationTest extends AbstractIntegrationTest {

    @Test
    void tokenise_validRecurringRequest_persistsTokenAndAuditRecord()
    // Assert: HTTP 201; token_vault row exists; audit_log row with TOKENISE/SUCCESS

    @Test
    void tokenise_sameRecurringPanSameMerchant_returnsIdenticalToken()
    // Assert: two calls → same token value; only one token_vault row exists

    @Test
    void tokenise_sameRecurringPanDifferentMerchant_returnsDifferentToken()
    // Assert: two calls with different merchantId → different token values; two rows

    @Test
    void tokenise_oneTimePan_alwaysReturnsNewToken()
    // Assert: two calls with ONE_TIME → different token values; two token_vault rows

    @Test
    void tokenise_invalidLuhnPan_returns400WithNoAuditRecord()
    // Assert: HTTP 400; no token_vault row; no audit_log row

    @Test
    void tokenise_nullPan_returns400()

    @Test
    void panNeverAppearsInAnyLogOutput()
    // Attach ListAppender to root logger; tokenise; assert no event contains PAN
}
```

#### Detokenisation

```java
class DetokenisationIntegrationTest extends AbstractIntegrationTest {

    @Test
    void detokenise_validToken_returnsCorrectPan()
    // Full round-trip: tokenise → detokenise → assert PAN matches original

    @Test
    void detokenise_wrongMerchant_returns403AndWritesAuditRecord()
    // Assert: HTTP 403; audit_log row with DETOKENISE/FAILURE and MERCHANT_SCOPE reason

    @Test
    void detokenise_unknownToken_returns404()

    @Test
    void detokenise_inactiveToken_returns404()
    // Deactivate token in DB; attempt detokenise; assert 404

    @Test
    void detokenise_tamperedCiphertext_triggersTamperAlertAuditEvent()
    // Tokenise; corrupt one byte of encrypted_pan in DB directly via JdbcTemplate;
    // detokenise; assert HTTP 500; assert TAMPER_ALERT event in audit_log

    @Test
    void detokenise_exceedsRateLimit_returns429()
    // Fire requests above per-merchant threshold; assert 429 on excess requests

    @Test
    void panNeverAppearsInAnyLogOutput()
    // Attach ListAppender; detokenise; assert no event contains PAN
}
```

#### Key Rotation

```java
class KeyRotationIntegrationTest extends AbstractIntegrationTest {

    @Test
    void scheduledRotation_allTokensReEncryptedAndDetokenisable()
    // 1. Tokenise 100 tokens under key version V1
    // 2. Trigger rotation → new version V2 created
    // 3. Run batch processor to completion
    // 4. Assert zero token_vault rows still reference V1
    // 5. Assert all 100 tokens still detokenise correctly returning original PAN

    @Test
    void scheduledRotation_newTokenisationsUseNewKeyImmediatelyAfterPromotion()
    // 1. Initiate rotation
    // 2. Promote V2
    // 3. Tokenise new PAN; assert resulting token_vault row references V2

    @Test
    void scheduledRotation_rotationAuditTrailIsComplete()
    // Assert: KEY_ROTATION_STARTED, TOKEN_REENCRYPTED (×N), KEY_ROTATION_COMPLETED all present

    @Test
    void emergencyRotation_compromisedKeyStatusSetSynchronously()
    // 1. Initiate emergency rotation with COMPROMISE reason
    // 2. Immediately query key_versions; assert status = COMPROMISED without waiting

    @Test
    void emergencyRotation_detokenisationSuspendedForAffectedTokens()
    // 1. Tokenise under V1; initiate emergency rotation with suspendDetokenisation=true
    // 2. Attempt detokenise before re-encryption; assert 503

    @Test
    void emergencyRotation_detokenisationRestoredAfterReEncryption()
    // 1. Complete emergency rotation re-encryption batch
    // 2. Detokenise; assert HTTP 200 and correct PAN

    @Test
    void tamperDetection_modifiedKeyVersionRow_throwsAndAlertsOnNextRead()
    // 1. Directly UPDATE key_versions SET kms_key_id = 'tampered' via JdbcTemplate
    // 2. Trigger any operation that reads the key version (e.g. rotation initiation)
    // 3. Assert KeyIntegrityException is thrown
    // 4. Assert TAMPER_ALERT event written to audit_log

    @Test
    void tamperDetection_retiredKeyRemainsReadableForDetokenisation()
    // Assert old tokens (pre-rotation) can still be detokenised after key retirement
}
```

---

### 10.4 Load Tests

Load tests live in a dedicated Maven profile (`-P load-tests`) and are excluded from the standard `mvn test` run. They are run explicitly — in CI on a scheduled pipeline, or manually before a production release.

```xml
<!-- pom.xml — load test profile -->
<profile>
    <id>load-tests</id>
    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-surefire-plugin</artifactId>
                <configuration>
                    <groups>load</groups>
                    <argLine>-Xmx2g -Xms512m</argLine>
                </configuration>
            </plugin>
        </plugins>
    </build>
</profile>
```

#### Load Test Architecture

Each load test follows the same structure:

```
1. Pre-warm     — seed the DB with a realistic baseline token population
2. Ramp         — begin concurrent request execution via virtual threads
3. Execute      — run at full concurrency for the defined duration
4. Drain        — wait for all in-flight requests to complete
5. Assert       — verify correctness AND performance thresholds
6. Report       — write LoadTestResult to target/load-test-results/
```

#### Virtual Thread Executor

All load tests use Java virtual threads (Project Loom) to simulate high concurrency without the overhead of OS threads:

```java
/**
 * Creates a virtual thread executor capped at {@code concurrency} simultaneous tasks.
 * Virtual threads are used throughout to simulate high I/O concurrency
 * without the memory overhead of platform thread pools.
 *
 * @param concurrency  the maximum number of tasks executing simultaneously
 * @return             a bounded virtual thread executor
 */
protected ExecutorService buildVirtualThreadExecutor(int concurrency) {
    Semaphore semaphore = new Semaphore(concurrency);
    return Executors.newThreadPerTaskExecutor(
        Thread.ofVirtual()
            .name("load-test-worker-", 0)
            .factory()
    );
}
```

#### Metrics Capture

Every load test captures metrics at three points:

```java
SystemMetrics before = captureMetrics();   // baseline before ramp
SystemMetrics peak   = captureMetrics();   // captured mid-execution at 50% completion
SystemMetrics after  = captureMetrics();   // after all requests drained
```

Captured fields per snapshot:

| Metric | Source | What it tells you |
|---|---|---|
| `heapUsedMb` | `Runtime.getRuntime()` | Memory pressure — watch for linear growth indicating a leak |
| `heapMaxMb` | `Runtime.getRuntime()` | Available headroom |
| `systemLoadAverage` | `OperatingSystemMXBean` | CPU saturation across all cores |
| `availableProcessors` | `Runtime.getRuntime()` | Context for load average interpretation |
| `gcCollectionCount` | `GarbageCollectorMXBean` | GC pressure — high count under load indicates memory churn |
| `gcCollectionTimeMs` | `GarbageCollectorMXBean` | GC pause time — if high, throughput is being lost to GC |

#### Load Test Result Record

Every test writes a result to `target/load-test-results/<TestName>-<timestamp>.json`:

```java
@Builder
public record LoadTestResult(
    String testName,
    int targetRequests,
    int concurrency,
    long totalDurationMs,
    long successCount,
    long failureCount,
    double requestsPerSecond,
    long p50LatencyMs,
    long p95LatencyMs,
    long p99LatencyMs,
    long maxLatencyMs,
    SystemMetrics metricsBefore,
    SystemMetrics metricsPeak,
    SystemMetrics metricsAfter,
    List<String> assertionFailures   // empty if test passed
) {}
```

---

#### Load Tier 1 — Tokenisation Load Tests

**Test class:** `TokenisationLoadTest`

Five scenarios, run sequentially in one test class. Each scenario builds on the previous result to confirm linear scalability holds as volume increases.

| Scenario | Total Requests | Concurrency | Max Allowed Duration | Max p99 Latency | Max Heap Growth |
|---|---|---|---|---|---|
| L1-T-1K  | 1,000  | 50  | 30s  | 500ms  | +128 MB |
| L1-T-5K  | 5,000  | 100 | 90s  | 600ms  | +256 MB |
| L1-T-10K | 10,000 | 150 | 180s | 700ms  | +384 MB |
| L1-T-20K | 20,000 | 200 | 360s | 800ms  | +512 MB |
| L1-T-50K | 50,000 | 200 | 900s | 1000ms | +768 MB |

```java
@Tag("load")
class TokenisationLoadTest extends AbstractLoadTest {

    /**
     * Executes a tokenisation load scenario and asserts throughput, latency,
     * and system resource thresholds are not breached.
     *
     * @param totalRequests     total number of tokenise calls to make
     * @param concurrency       maximum simultaneous in-flight requests
     * @param maxDurationMs     wall-clock deadline for all requests to complete
     * @param maxP99LatencyMs   p99 response time must not exceed this value
     * @param maxHeapGrowthMb   heap used after load must not exceed heap before + this value
     */
    @ParameterizedTest(name = "tokenisation_load_{0}_requests")
    @MethodSource("loadScenarios")
    void tokenisation_sustainedLoad_meetsThresholds(
            int totalRequests,
            int concurrency,
            long maxDurationMs,
            long maxP99LatencyMs,
            long maxHeapGrowthMb) throws InterruptedException {

        // ARRANGE
        List<Long> latencies = new CopyOnWriteArrayList<>();
        AtomicLong successCount = new AtomicLong();
        AtomicLong failureCount = new AtomicLong();
        ExecutorService executor = buildVirtualThreadExecutor(concurrency);
        SystemMetrics before = captureMetrics();
        long startTime = System.currentTimeMillis();

        // ACT — ramp to full concurrency and fire all requests
        for (int i = 0; i < totalRequests; i++) {
            final String pan = PanGenerator.randomValid();   // generates valid Luhn PANs
            executor.submit(() -> {
                long requestStart = System.nanoTime();
                try {
                    ResponseEntity<TokeniseResponse> response = restTemplate.postForEntity(
                        "/api/v1/tokens",
                        buildTokeniseRequest(pan, TokenType.ONE_TIME),
                        TokeniseResponse.class
                    );
                    if (response.getStatusCode().is2xxSuccessful()) {
                        successCount.incrementAndGet();
                    } else {
                        failureCount.incrementAndGet();
                    }
                } catch (Exception e) {
                    failureCount.incrementAndGet();
                } finally {
                    latencies.add(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - requestStart));
                }
            });
        }

        awaitCompletion(executor, Duration.ofMillis(maxDurationMs + 10_000));
        SystemMetrics after = captureMetrics();
        long totalDurationMs = System.currentTimeMillis() - startTime;

        // ASSERT — correctness
        assertThat(failureCount.get())
            .as("Failure count must be zero — every request must succeed")
            .isZero();

        assertThat(successCount.get())
            .as("Success count must equal total requests")
            .isEqualTo(totalRequests);

        // ASSERT — latency
        long p99 = percentile(latencies, 99);
        long p95 = percentile(latencies, 95);
        long p50 = percentile(latencies, 50);

        assertThat(p99)
            .as("p99 latency %dms exceeds threshold %dms", p99, maxP99LatencyMs)
            .isLessThanOrEqualTo(maxP99LatencyMs);

        // ASSERT — duration
        assertThat(totalDurationMs)
            .as("Total duration %dms exceeded max allowed %dms", totalDurationMs, maxDurationMs)
            .isLessThanOrEqualTo(maxDurationMs);

        // ASSERT — memory
        long heapGrowthMb = after.heapUsedMb() - before.heapUsedMb();
        assertThat(heapGrowthMb)
            .as("Heap grew by %dMB which exceeds max allowed growth of %dMB",
                heapGrowthMb, maxHeapGrowthMb)
            .isLessThanOrEqualTo(maxHeapGrowthMb);

        // ASSERT — CPU (warn, not fail — shared CI hosts have variable load)
        if (after.systemLoadAverage() > after.availableProcessors() * 0.9) {
            System.err.printf("[WARN] CPU load average %.2f is near saturation (%d cores)%n",
                after.systemLoadAverage(), after.availableProcessors());
        }

        // REPORT
        writeLoadTestResult(LoadTestResult.builder()
            .testName("tokenisation_load_" + totalRequests)
            .targetRequests(totalRequests)
            .concurrency(concurrency)
            .totalDurationMs(totalDurationMs)
            .successCount(successCount.get())
            .failureCount(failureCount.get())
            .requestsPerSecond((double) totalRequests / (totalDurationMs / 1000.0))
            .p50LatencyMs(p50)
            .p95LatencyMs(p95)
            .p99LatencyMs(p99)
            .maxLatencyMs(Collections.max(latencies))
            .metricsBefore(before)
            .metricsAfter(after)
            .build());
    }

    static Stream<Arguments> loadScenarios() {
        //                requests  concurrency  maxDurationMs  maxP99Ms  maxHeapGrowthMb
        return Stream.of(
            Arguments.of(  1_000,   50,   30_000,   500,  128),
            Arguments.of(  5_000,  100,   90_000,   600,  256),
            Arguments.of( 10_000,  150,  180_000,   700,  384),
            Arguments.of( 20_000,  200,  360_000,   800,  512),
            Arguments.of( 50_000,  200,  900_000,  1000,  768)
        );
    }
}
```

---

#### Load Tier 2 — Detokenisation Load Tests

**Test class:** `DetokenisationLoadTest`

Detokenisation is a read-heavy operation with cryptographic cost. The test pre-seeds the vault with the target token population before measuring detokenisation throughput.

| Scenario | Pre-seeded Tokens | Total Requests | Concurrency | Max p99 Latency | Max Heap Growth |
|---|---|---|---|---|---|
| L2-D-1K  | 1,000  | 1,000  | 50  | 400ms  | +128 MB |
| L2-D-5K  | 5,000  | 5,000  | 100 | 500ms  | +256 MB |
| L2-D-10K | 10,000 | 10,000 | 150 | 600ms  | +384 MB |
| L2-D-20K | 20,000 | 20,000 | 200 | 700ms  | +512 MB |
| L2-D-50K | 50,000 | 50,000 | 200 | 900ms  | +768 MB |

```java
@Tag("load")
class DetokenisationLoadTest extends AbstractLoadTest {

    /**
     * Seeds the token vault with {@code count} tokens and returns their token values.
     * Seeding is done via direct service calls (not HTTP) to avoid the load test
     * timing being affected by the seed phase.
     *
     * @param count  number of tokens to pre-create
     * @return       list of token strings ready for detokenisation requests
     */
    private List<String> seedVault(int count) { ... }

    @ParameterizedTest(name = "detokenisation_load_{0}_requests")
    @MethodSource("loadScenarios")
    void detokenisation_sustainedLoad_meetsThresholds(
            int totalRequests, int concurrency,
            long maxDurationMs, long maxP99LatencyMs, long maxHeapGrowthMb)
            throws InterruptedException {

        List<String> tokens = seedVault(totalRequests);
        // ... same executor + metrics + assertion pattern as tokenisation load test
    }
}
```

---

#### Load Tier 3 — Mixed Workload Load Tests

**Test class:** `MixedWorkloadLoadTest`

Real-world traffic is not homogeneous. This test simulates a realistic mixed workload:

| Operation | Share of traffic |
|---|---|
| Tokenise (ONE_TIME) | 40% |
| Tokenise (RECURRING) | 20% |
| Detokenise | 35% |
| Token status check (HEAD) | 5% |

```java
@Tag("load")
class MixedWorkloadLoadTest extends AbstractLoadTest {

    @ParameterizedTest(name = "mixed_workload_{0}_requests")
    @MethodSource("loadScenarios")
    void mixedWorkload_sustainedLoad_meetsThresholds(
            int totalRequests, int concurrency,
            long maxDurationMs, long maxP99LatencyMs) throws InterruptedException {

        // Pre-seed 50% of totalRequests as existing RECURRING tokens
        // (realistic: vault already has existing customers)
        List<String> existingTokens = seedVault(totalRequests / 2);

        // Weight-based request dispatcher
        RandomWorkloadDispatcher dispatcher = RandomWorkloadDispatcher.builder()
            .addOperation(0.40, () -> tokenise(PanGenerator.randomValid(), ONE_TIME))
            .addOperation(0.20, () -> tokenise(PanGenerator.randomValid(), RECURRING))
            .addOperation(0.35, () -> detokenise(existingTokens.get(random.nextInt(existingTokens.size()))))
            .addOperation(0.05, () -> checkStatus(existingTokens.get(random.nextInt(existingTokens.size()))))
            .build();

        // Execute with same executor + metrics + assertion pattern
    }

    static Stream<Arguments> loadScenarios() {
        //                requests  concurrency  maxDurationMs  maxP99Ms
        return Stream.of(
            Arguments.of(  1_000,   50,   30_000,   600),
            Arguments.of(  5_000,  100,   90_000,   700),
            Arguments.of( 10_000,  150,  180_000,   800),
            Arguments.of( 20_000,  200,  360_000,   900),
            Arguments.of( 50_000,  200,  900_000,  1200)
        );
    }
}
```

---

#### Load Tier 4 — Key Rotation Under Load

**Test class:** `KeyRotationUnderLoadTest`

This is the highest-risk operational scenario. The system must handle normal tokenisation and detokenisation traffic while a key rotation batch runs concurrently in the background. This test verifies there is no throughput degradation or correctness failure during rotation.

```java
/**
 * Verifies that key rotation can execute concurrently with live traffic
 * without causing request failures, data corruption, or throughput degradation.
 *
 * <p>Test sequence:
 * <ol>
 *   <li>Pre-seed 10,000 tokens under key version V1</li>
 *   <li>Start a background thread continuously tokenising and detokenising</li>
 *   <li>Trigger scheduled rotation to V2</li>
 *   <li>Run rotation batch processor to completion while live traffic continues</li>
 *   <li>Assert: zero errors during rotation; all pre-rotation tokens still detokenisable</li>
 *   <li>Assert: all post-rotation tokens use V2</li>
 *   <li>Assert: throughput during rotation is within 20% of baseline (pre-rotation) throughput</li>
 * </ol>
 */
@Test
@Tag("load")
void keyRotation_underConcurrentLoad_noErrorsAndAcceptableThroughputDegradation()
        throws InterruptedException {

    int preSeededTokens = 10_000;
    int concurrentRequestsDuringRotation = 100;

    // Phase 1 — seed vault and measure baseline throughput
    List<String> preRotationTokens = seedVault(preSeededTokens);
    double baselineThroughput = measureBaselineThroughput(concurrentRequestsDuringRotation);
    SystemMetrics beforeRotation = captureMetrics();

    // Phase 2 — start live traffic in background
    AtomicBoolean stopTraffic = new AtomicBoolean(false);
    AtomicLong liveTrafficErrors = new AtomicLong();
    CompletableFuture<Void> liveTrafficFuture = startLiveTraffic(
        preRotationTokens, concurrentRequestsDuringRotation, stopTraffic, liveTrafficErrors);

    // Phase 3 — trigger rotation and run batch to completion
    String newVersionId = keyRotationService.initiateScheduledRotation("load-test-rotation");
    rotationJob.runUntilComplete(newVersionId);   // blocking in test context

    // Phase 4 — stop live traffic and collect results
    stopTraffic.set(true);
    liveTrafficFuture.join();
    SystemMetrics afterRotation = captureMetrics();

    // ASSERT — correctness: no errors during rotation
    assertThat(liveTrafficErrors.get())
        .as("Live traffic errors during rotation must be zero")
        .isZero();

    // ASSERT — correctness: all pre-rotation tokens still detokenisable
    long failedDetokenisations = preRotationTokens.parallelStream()
        .filter(token -> !canDetokenise(token))
        .count();
    assertThat(failedDetokenisations)
        .as("%d pre-rotation tokens could not be detokenised after rotation", failedDetokenisations)
        .isZero();

    // ASSERT — correctness: zero tokens remain on old key
    long tokensOnOldKey = tokenVaultRepository.countByKeyVersionId(/* old version id */);
    assertThat(tokensOnOldKey)
        .as("All tokens must be re-encrypted to new key version")
        .isZero();

    // ASSERT — performance: throughput during rotation within 20% of baseline
    double rotationThroughput = measureCurrentThroughput();
    double degradationPercent = (baselineThroughput - rotationThroughput) / baselineThroughput * 100;
    assertThat(degradationPercent)
        .as("Throughput degraded by %.1f%% during rotation (max allowed: 20%%)", degradationPercent)
        .isLessThanOrEqualTo(20.0);

    // ASSERT — memory: heap growth during rotation is bounded
    long heapGrowthMb = afterRotation.heapUsedMb() - beforeRotation.heapUsedMb();
    assertThat(heapGrowthMb)
        .as("Heap grew by %dMB during rotation (max allowed: 512MB)", heapGrowthMb)
        .isLessThanOrEqualTo(512);
}
```

---

#### Load Tier 5 — Tampered Key Detection Under Load

**Test class:** `TamperedKeyUnderLoadTest`

Verifies that tamper detection fires correctly even when the system is under concurrent request load — i.e., the tamper check is not bypassed by race conditions or thread-local state.

```java
/**
 * Verifies that key tamper detection is reliable under concurrent request load.
 *
 * <p>Test sequence:
 * <ol>
 *   <li>Pre-seed 5,000 tokens</li>
 *   <li>Start concurrent detokenisation traffic (100 threads)</li>
 *   <li>Directly corrupt the key_versions row via JdbcTemplate (simulate DB-level tamper)</li>
 *   <li>Trigger a key read operation (rotation initiation)</li>
 *   <li>Assert: KeyIntegrityException thrown immediately</li>
 *   <li>Assert: TAMPER_ALERT audit event written within 1 second of corruption</li>
 *   <li>Assert: no concurrent request returned a PAN after the tamper was committed</li>
 *   <li>Assert: system remains responsive (live traffic continues after tamper isolation)</li>
 * </ol>
 */
@Test
@Tag("load")
void tamperedKey_detectedUnderConcurrentLoad_alertsFiredAndSystemIsolated()
        throws InterruptedException {

    List<String> tokens = seedVault(5_000);
    AtomicBoolean stopTraffic = new AtomicBoolean(false);
    AtomicLong successfulDetokenisations = new AtomicLong();
    Instant tamperCommittedAt = new AtomicReference<>();

    // Start concurrent detokenisation
    CompletableFuture<Void> trafficFuture = startDetokenisationTraffic(
        tokens, 100, stopTraffic, successfulDetokenisations);

    // Commit tamper directly to DB
    Thread.sleep(500);  // allow some normal traffic to flow first
    jdbcTemplate.update(
        "UPDATE key_versions SET kms_key_id = 'TAMPERED_VALUE' WHERE status = 'ACTIVE'");
    tamperCommittedAt.set(Instant.now());

    // Trigger key read
    assertThatThrownBy(() -> keyRotationService.initiateScheduledRotation("tamper-test"))
        .isInstanceOf(KeyIntegrityException.class);

    // Stop traffic and collect
    stopTraffic.set(true);
    trafficFuture.join();

    // ASSERT — tamper alert written promptly
    List<TokenAuditLog> tamperAlerts = auditLogRepository
        .findByEventTypeAndCreatedAtAfter(TAMPER_ALERT, tamperCommittedAt.get().minusSeconds(1));
    assertThat(tamperAlerts)
        .as("At least one TAMPER_ALERT must be recorded after the key was corrupted")
        .isNotEmpty();

    // ASSERT — no PAN returned after tamper was committed (check audit log has no post-tamper successes)
    long postTamperSuccesses = auditLogRepository
        .countByEventTypeAndOutcomeAndCreatedAtAfter(
            DETOKENISE, SUCCESS, tamperCommittedAt.get());
    assertThat(postTamperSuccesses)
        .as("No successful detokenisations should occur after tamper was committed")
        .isZero();
}
```

---

### 10.5 Load Test Thresholds Summary

| Scenario | Volume | p99 Latency | Duration | Heap Growth | Error Rate |
|---|---|---|---|---|---|
| Tokenise only | 1K | ≤ 500ms | ≤ 30s | ≤ +128MB | 0% |
| Tokenise only | 5K | ≤ 600ms | ≤ 90s | ≤ +256MB | 0% |
| Tokenise only | 10K | ≤ 700ms | ≤ 180s | ≤ +384MB | 0% |
| Tokenise only | 20K | ≤ 800ms | ≤ 360s | ≤ +512MB | 0% |
| Tokenise only | 50K | ≤ 1000ms | ≤ 900s | ≤ +768MB | 0% |
| Detokenise only | 1K–50K | ≤ tokenise - 100ms | same | same | 0% |
| Mixed workload | 1K–50K | ≤ 1200ms at 50K | same | same | 0% |
| Rotation under load | 10K vault | ≤ 20% degradation | — | ≤ +512MB | 0% |
| Tampered key under load | 5K vault | detect within 1s | — | — | 0% post-tamper |

**Error rate is always 0%.** If any request returns an unexpected error (5xx, or 4xx that is not a test-controlled scenario), the load test fails.

### 10.6 Load Test Results Archival

Results are written to `target/load-test-results/` as JSON files. In CI, these are published as build artifacts. When running load tests locally, compare against the previous result file for the same scenario to detect regressions:

```bash
# Run load tests
mvn test -P load-tests

# Results written to:
# target/load-test-results/TokenisationLoadTest-1000-2025-04-16T10:30:00.json
# target/load-test-results/TokenisationLoadTest-5000-2025-04-16T10:32:15.json
# ... etc
```

A regression is defined as any result where p99 latency increases by more than 15% compared to the previous recorded result for the same scenario, or where heap growth increases by more than 20%. The CI pipeline must fail on regression.

---

## 11. Configuration Reference

```yaml
# application.yml

spring:
  datasource:
    url: ${DATASOURCE_URL}
    username: ${DATASOURCE_USER}
    password: ${DATASOURCE_PASSWORD}
  jpa:
    hibernate:
      ddl-auto: validate   # Flyway manages schema, Hibernate only validates
  flyway:
    enabled: true
    locations: classpath:db/migration

kms:
  provider: ${KMS_PROVIDER:aws}            # aws | azure-kv | local-dev
  aws:
    region: ${AWS_REGION:ap-southeast-2}
    master-key-arn: ${AWS_KMS_KEY_ARN}
  key-ring:
    ttl-hours: 24                          # force re-fetch from KMS every 24h
    startup-timeout-seconds: 30            # fail fast if KMS unreachable at startup

tokenisation:
  token-format: UUID                       # UUID | LUHN_16
  pan-hash-secret: ${PAN_HASH_SECRET}      # separate from KEK, for HMAC de-dup
  default-token-ttl-days: 1825            # 5 years

detokenisation:
  rate-limit:
    per-merchant-per-minute: 1000
    per-service-per-minute: 10000

rotation:
  batch:
    cron: "0 */15 * * * *"               # every 15 minutes
    size: 500
    emergency-size: 100                   # smaller batches, higher frequency for emergency
  compliance:
    max-key-age-days: 365

audit:
  retention-years: 7                      # PCI-DSS minimum

logging:
  level:
    com.yourorg.tokenisation: INFO
  # PAN masking filter applied globally — see SecurityConfig
```

---

## 12. Pitfalls & Mitigations

| # | Pitfall | Impact | Mitigation |
|---|---|---|---|
| 1 | PAN appears in exception message or stack trace | Critical — PCI breach | Custom exception types that never include PAN; Logback PAN masking filter |
| 2 | IV reuse in AES-GCM | Critical — breaks encryption | Generate fresh `SecureRandom` IV per encrypt operation, never reuse |
| 3 | DEK held in memory past single operation | High | try/finally with `Arrays.fill(dek, 0)` — always |
| 4 | Rotation job holds table lock | Medium — degrades throughput | Small batches (500), off-peak scheduling, optimistic locking via `record_version` |
| 5 | KMS unavailable blocks all detokenisation | High | KEK loaded at startup; outage only affects new startups, not running instances |
| 6 | Retired key deleted from KMS too early | Critical — past tokens unreadable | Policy: never delete KMS key material; retire status only; set KMS key deletion window to maximum |
| 7 | Token scoping not enforced at DB level | High | Merchant ID always extracted from authenticated JWT, never request body |
| 8 | Audit log mutated or deleted | High — compliance failure | DB role: INSERT only on audit table; periodic archive to WORM S3 |
| 9 | Key ring not refreshed after TTL | Medium | Scheduled `@Scheduled` TTL check; force refresh before `expiresAt` |
| 10 | Emergency rotation still slow | High | Pre-provision a standby key version so emergency promotion is instant |

---

## 13. Clean Code Standards

Every class and method produced in this project **must** comply with the following standards without exception. These are not aspirational — they are acceptance criteria. A task is not complete until its code meets all of them.

### 13.1 General Principles

- **Single Responsibility** — every class does one thing; every method does one thing. If you need the word "and" to describe what a method does, split it.
- **Intention-revealing names** — no abbreviations (`encDek` → `encryptedDek`), no generic names (`data`, `result`, `temp`), no hungarian notation.
- **No magic numbers or strings** — all constants are named and live in a dedicated `Constants` class or as `static final` fields on the owning class.
- **Fail fast** — validate inputs at the top of every public method; throw specific, descriptive exceptions immediately rather than letting invalid state propagate.
- **Small methods** — aim for methods under 20 lines. If a method needs a comment to explain a block of code, that block is a candidate for extraction.
- **No dead code** — no commented-out code, no unused imports, no unreachable branches.

### 13.2 Javadoc Requirements

Every `public` class and every `public` or `protected` method **must** have a Javadoc comment. The Javadoc must answer:

1. **What** the method does (not how)
2. **Why** any non-obvious design decision was made
3. **`@param`** for every parameter — describe valid range, nullability, and units where relevant
4. **`@return`** for every non-void method
5. **`@throws`** for every checked and meaningful unchecked exception

```java
/**
 * Encrypts a PAN using AES-256-GCM with a freshly generated Data Encryption Key (DEK).
 *
 * <p>A new random IV is generated per invocation to ensure ciphertext uniqueness even
 * when the same PAN is encrypted multiple times. The DEK is zeroed from memory
 * immediately after use regardless of whether encryption succeeds or fails.
 *
 * @param pan       the raw PAN bytes to encrypt; must not be null or empty
 * @param kek       the Key Encryption Key used to wrap the DEK; must be 32 bytes (AES-256)
 * @return          an {@link EncryptResult} containing the ciphertext, IV, auth tag,
 *                  and the KEK-wrapped DEK — all safe to persist
 * @throws IllegalArgumentException  if {@code pan} is null/empty or {@code kek} is not 32 bytes
 * @throws EncryptionException       if the underlying JCE operation fails
 */
public EncryptResult encrypt(byte[] pan, byte[] kek) { ... }
```

### 13.3 Exception Handling

- **Never catch and swallow** — `catch (Exception e) { log.error(...) }` without rethrowing is forbidden unless the method contract explicitly says failures are non-fatal (e.g., a best-effort audit log write).
- **Domain exceptions over generic ones** — define a clear exception hierarchy:

```
TokenisationException (base)
  ├── PanValidationException          — invalid PAN format
  ├── TokenNotFoundException          — token does not exist or is inactive
  ├── MerchantScopeException          — cross-merchant access attempt
  ├── KeyVersionNotFoundException     — requested key version not in ring
  ├── KeyIntegrityException           — tamper detected on key metadata
  ├── EncryptionException             — AES/GCM failure
  └── RotationException               — key rotation operation failure
```

- **Never include PAN in exception messages** — ever, under any circumstances.
- **Log at the right level** — `ERROR` for unrecoverable failures, `WARN` for recoverable anomalies, `INFO` for significant state changes, `DEBUG` for flow tracing. No `INFO` in hot paths.

### 13.4 Immutability & Thread Safety

- Domain objects (`TokenVault`, `KeyVersion`) are immutable once constructed — use Lombok `@Value` or record types where appropriate.
- `InMemoryKeyRing` operations on the `ConcurrentHashMap` must be atomic — use `computeIfAbsent`, `computeIfPresent`, not separate get/put calls.
- `KeyMaterial` holding raw key bytes must be a `final` class with no setters. Expose bytes only through a method that copies the array, not a direct reference.

### 13.5 Dependency Injection

- Constructor injection only — no field injection (`@Autowired` on fields), no setter injection. This makes dependencies explicit and classes unit-testable without a Spring context.
- Mark all injected collaborators `private final`.

```java
// Correct
@Service
public class TokenisationService {
    private final TokenVaultRepository tokenVaultRepository;
    private final InMemoryKeyRing keyRing;
    private final AesGcmCipher cipher;
    private final AuditLogger auditLogger;

    public TokenisationService(
            TokenVaultRepository tokenVaultRepository,
            InMemoryKeyRing keyRing,
            AesGcmCipher cipher,
            AuditLogger auditLogger) {
        this.tokenVaultRepository = tokenVaultRepository;
        this.keyRing = keyRing;
        this.cipher = cipher;
        this.auditLogger = auditLogger;
    }
}
```

### 13.6 Testing Standards

Every production class must have a corresponding test class. Tests are not optional and are not written after the fact — they are part of the definition of done for each task.

#### Unit Tests

- One test class per production class, named `<ClassName>Test`
- Use `@ExtendWith(MockitoExtension.class)` — no Spring context, fast execution
- Every public method must have tests for: happy path, all documented failure modes, edge cases (null, empty, boundary values)
- Test method names follow `methodName_condition_expectedBehaviour`:

```java
@Test
void tokenise_recurringPan_returnsSameTokenOnSubsequentCall() { ... }

@Test
void tokenise_nullPan_throwsPanValidationException() { ... }

@Test
void encrypt_dekZeroedAfterEncryption_verifiedBySecurityManager() { ... }
```

- No logic in tests — no `if`, no loops. One scenario per test.
- Use `@ParameterizedTest` for input variation, not multiple near-identical test methods.

#### Integration Tests

- One integration test class per feature slice, named `<Feature>IntegrationTest`
- Extend `AbstractIntegrationTest` — real PostgreSQL via Testcontainers, `LocalDevKmsAdapter`
- Test the full stack: HTTP request → service → DB → response
- Assert on DB state directly after operations (not just response body)
- Assert audit log records were created with correct event types

#### What "done" means for a task

A task is only marked complete in `progress.md` when ALL of the following are true:

1. Production code compiles with zero warnings
2. All Javadoc is present and accurate
3. Unit tests written, passing, coverage ≥ 90% of lines for that class
4. Integration test written and passing
5. No PAN appears in any log output (asserted in tests where relevant)
6. Code reviewed against clean code checklist in this section
7. **Full standard test suite passes with zero failures:**
   ```bash
   JAVA_HOME=/opt/homebrew/opt/openjdk@21 mvn test   # or: make test
   ```
   A passing compile is not sufficient. New code must not break any existing test.
   If failures exist before work starts, record them in `progress.md` Deviations first.

---

## 14. Progress Tracking

### How progress.md Works

A `progress.md` file **must be created at the root of the project** at the start of the implementation and updated after every completed task. Its purpose is to serve as a reliable recovery checkpoint — if a session ends unexpectedly or tokens run out, the next session picks up `progress.md` first and knows exactly what is done and what comes next.

#### Rules

1. **Update `progress.md` before moving to the next task** — not at the end of a session.
2. **Mark a task `[x]` only when the definition of done is fully met** (see Section 13.6). Partial work stays `[ ]`.
3. **Record the completion timestamp** next to each completed item.
4. **Record any deviations** — if a task was implemented differently from the plan, note it in the Deviations section.
5. **Record blockers** — if a task is blocked, note it with the reason so the next session can address it immediately.

### progress.md Template

> This file must be created at `<project-root>/progress.md` before any code is written.

```markdown
# Card Tokenisation — Progress Tracker

> Recovery guide: read this file first at the start of every session.
> A task is only marked [x] when unit tests, integration tests, Javadoc,
> and the clean code checklist (PLAN.md §13) are all satisfied.

Last updated: YYYY-MM-DD HH:MM NZST
Current phase: Phase 1 — Tokenisation
Next task: <name of the very next incomplete task>

---

## Session Log

| Session | Date | Completed | Stopped At |
|---------|------|-----------|------------|
| 1 | YYYY-MM-DD | P1-T1, P1-T2 | P1-T3 blocked — see blockers |

---

## Phase 1 — Tokenisation

### Foundation
- [ ] P1-F1 — Create project structure, pom.xml, application.yml skeleton
- [ ] P1-F2 — Flyway migrations V1–V4 (key_versions, token_vault, audit_log, indexes)
- [ ] P1-F3 — JPA entities: TokenVault, KeyVersion, TokenAuditLog
- [ ] P1-F4 — Repository interfaces: TokenVaultRepository, KeyVersionRepository, AuditLogRepository
- [ ] P1-F5 — AbstractIntegrationTest base class (Testcontainers PostgreSQL)

### KMS Layer
- [ ] P1-K1 — KmsProvider interface + data types (GeneratedDek, KeyMetadata, etc.)
- [ ] P1-K2 — LocalDevKmsAdapter (for tests, no cloud dependency)
- [ ] P1-K3 — AwsKmsAdapter (unwrapKek, generateDek, rewrapDek, describeKey)
- [ ] P1-K4 — Unit tests: LocalDevKmsAdapterTest, AwsKmsAdapterTest (mocked KMS client)

### Crypto Layer
- [ ] P1-C1 — AesGcmCipher (encrypt, decrypt, wrapDek, unwrapDek) with DEK zeroing
- [ ] P1-C2 — PanHasher (HMAC-SHA256 of PAN for de-dup)
- [ ] P1-C3 — InMemoryKeyRing (load, promoteActive, getActive, getByVersion, retire)
- [ ] P1-C4 — KeyRingInitialiser (ApplicationRunner, startup KMS call)
- [ ] P1-C5 — Unit tests: AesGcmCipherTest, PanHasherTest, InMemoryKeyRingTest
- [ ] P1-C6 — Integration test: KeyRingInitialiserIntegrationTest

### Tokenisation Feature
- [ ] P1-T1 — Exception hierarchy (TokenisationException and all subtypes)
- [ ] P1-T2 — TokeniseRequest / TokeniseResponse DTOs with validation annotations
- [ ] P1-T3 — TokenisationService (tokenise, de-dup logic, audit log)
- [ ] P1-T4 — TokenController (POST /api/v1/tokens)
- [ ] P1-T5 — PAN masking Logback filter
- [ ] P1-T6 — AuditLogger component
- [ ] P1-T7 — Unit tests: TokenisationServiceTest (happy path, de-dup, failures, null inputs)
- [ ] P1-T8 — Integration test: TokenisationIntegrationTest (full HTTP → DB → audit log)
- [ ] P1-T9 — Log assertion test: PanNeverInLogsTest

---

## Phase 2 — Detokenisation

- [ ] P2-D1 — DetokeniseResponse DTO
- [ ] P2-D2 — DetokenisationService (detokenise, merchant scope check, tamper detection)
- [ ] P2-D3 — TokenController extension (GET /api/v1/tokens/{token})
- [ ] P2-D4 — Rate limiter (per-merchant + per-service, configurable thresholds)
- [ ] P2-D5 — Unit tests: DetokenisationServiceTest (happy path, wrong merchant, compromised key, tampered ciphertext)
- [ ] P2-D6 — Integration test: DetokenisationIntegrationTest (round-trip, cross-merchant 403, rate limit 429)

---

## Phase 3 — Key Rotation

- [ ] P3-R1 — TamperDetector (HMAC checksum compute + assert on key_versions rows)
- [ ] P3-R2 — KeyRotationService (initiateScheduledRotation, initiateEmergencyRotation)
- [ ] P3-R3 — RotationBatchProcessor (re-encrypt single token, optimistic locking)
- [ ] P3-R4 — RotationJob (@Scheduled, batch loop, completion check, cutover)
- [ ] P3-R5 — Admin endpoint: POST /api/v1/admin/keys/rotate
- [ ] P3-R6 — Security alert integration (configurable webhook/email)
- [ ] P3-R7 — Unit tests: TamperDetectorTest, KeyRotationServiceTest, RotationBatchProcessorTest
- [ ] P3-R8 — Integration test: ScheduledRotationIntegrationTest (full batch, tokens detokenisable after)
- [ ] P3-R9 — Integration test: EmergencyRotationIntegrationTest (compromise → suspension → re-encryption)

---

## Pre-Production Hardening

- [ ] PP-1 — DB roles locked down (INSERT-only on audit log, verified in integration test)
- [ ] PP-2 — AwsKmsAdapter verified against AWS sandbox with IAM role
- [ ] PP-3 — mTLS configuration
- [ ] PP-4 — Key TTL refresh scheduled job
- [ ] PP-5 — Runbook: emergency rotation procedure
- [ ] PP-6 — Runbook: startup failure when KMS unreachable

---

## Deviations from Plan

| Task | Plan Says | Actual | Reason |
|------|-----------|--------|--------|
| | | | |

---

## Blockers

| Task | Blocker | Raised | Resolved |
|------|---------|--------|----------|
| | | | |

---

## Notes for Next Session

<!-- Update this before ending every session -->
- Current state: ...
- Immediate next step: ...
- Any context the next session needs to know: ...
```

### How to Resume After a Token Limit

When starting a new session after hitting a token limit:

1. Read `progress.md` — identify `Next task` at the top
2. Scan the Session Log to understand what was completed last session
3. Check the Deviations and Blockers tables
4. Read the "Notes for Next Session" section
5. Continue from the first `[ ]` task in the current phase

---

## 15. Delivery Checklist

> This is the final gate before each phase is considered shippable.
> Every item must be `[x]` in `progress.md` before the phase is closed.

### Phase 1 — Tokenisation
- [ ] All P1-F, P1-K, P1-C, P1-T tasks marked complete in `progress.md`
- [ ] `KmsProvider` interface + `LocalDevKmsAdapter` implemented
- [ ] `InMemoryKeyRing` + `KeyRingInitialiser` implemented and integration tested
- [ ] `AesGcmCipher` with DEK zeroing — unit tested including zeroing assertion
- [ ] Flyway migrations V1–V4 applied and validated
- [ ] `TokenisationService` with deterministic de-dup logic — unit tested
- [ ] `POST /api/v1/tokens` endpoint — integration tested
- [ ] PAN masking Logback filter verified by `PanNeverInLogsTest`
- [ ] Audit log written on every tokenise call (success and failure) — asserted in tests
- [ ] All public methods have Javadoc
- [ ] Zero compiler warnings
- [ ] `AwsKmsAdapter` smoke tested against AWS sandbox

### Phase 2 — Detokenisation
- [ ] All P2-D tasks marked complete in `progress.md`
- [ ] `DetokenisationService` with merchant scoping — unit tested
- [ ] GCM auth tag failure triggers `TAMPER_ALERT` — unit tested
- [ ] `GET /api/v1/tokens/{token}` endpoint — integration tested
- [ ] Rate limiter returning 429 — integration tested
- [ ] Merchant ID sourced from JWT, not request body — asserted in tests
- [ ] Cross-merchant rejection returning 403 — integration tested
- [ ] All public methods have Javadoc
- [ ] Zero compiler warnings

### Phase 3 — Key Rotation
- [ ] All P3-R tasks marked complete in `progress.md`
- [ ] `TamperDetector` checksum mismatch throws and emits audit event — unit tested
- [ ] `RotationJob` batch re-encryption handles per-record failures without aborting — unit tested
- [ ] Scheduled rotation end-to-end: zero tokens remain on old key after completion — integration tested
- [ ] Tokens created before rotation detokenisable after rotation — integration tested
- [ ] Emergency rotation: detokenisation suspended for compromised-key tokens — integration tested
- [ ] Retired key remains in KMS — verified manually against AWS sandbox
- [ ] All public methods have Javadoc
- [ ] Zero compiler warnings

### Load Tests — Tokenisation & Detokenisation
- [ ] `AbstractLoadTest` base class implemented with `captureMetrics()` and `SystemMetrics` record
- [ ] `LoadTestResult` record and JSON writer implemented
- [ ] `PanGenerator` utility for valid Luhn PAN generation
- [ ] `TokenisationLoadTest` — all 5 volume scenarios pass (1K, 5K, 10K, 20K, 50K)
- [ ] `DetokenisationLoadTest` — all 5 volume scenarios pass
- [ ] `MixedWorkloadLoadTest` — all 5 volume scenarios pass with mixed 40/20/35/5 split
- [ ] Load test Maven profile (`-P load-tests`) configured and working
- [ ] Results written to `target/load-test-results/` as JSON
- [ ] CI pipeline runs load tests on schedule and fails on regression (>15% p99 increase)

### Load Tests — Rotation and Tamper Under Load
- [ ] `KeyRotationUnderLoadTest` — 10K vault, rotation completes with 0 errors, ≤20% throughput degradation
- [ ] `TamperedKeyUnderLoadTest` — tamper detected within 1s, zero post-tamper detokenisations succeed
- [ ] All pre-rotation tokens detokenisable after rotation completes — verified in load test
- [ ] No heap leak observed across repeated load test runs (heap growth stays within thresholds)

### Before Production
- [ ] All PP tasks marked complete in `progress.md`
- [ ] `AwsKmsAdapter` using IAM role (not access keys)
- [ ] DB roles locked down — INSERT-only on audit log verified by integration test
- [ ] mTLS between services configured
- [ ] Key TTL refresh job running and tested
- [ ] Emergency rotation runbook written and reviewed
- [ ] KMS startup failure runbook written and reviewed

---

*Last updated: April 2025 — v1.1*
