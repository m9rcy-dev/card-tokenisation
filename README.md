# Card Tokenisation System

A PCI-DSS aligned card tokenisation vault built with Spring Boot 3.3, PostgreSQL, and AES-256-GCM envelope encryption.

Replaces raw PANs (Primary Account Numbers) with opaque, irreversible tokens. Supports scheduled and emergency key rotation with zero downtime.

---

## Table of Contents

- [Quick Start](#quick-start)
- [API Reference](#api-reference)
- [Configuration](#configuration)
- [Running Tests](#running-tests)
- [Load Testing](#load-testing)
  - [Load test design constraints and pitfalls](#load-test-design-constraints-and-pitfalls)
- [Architecture](#architecture)
- [Key Rotation](#key-rotation)
- [Security and Production Readiness](#security-and-production-readiness)
- [Contributing](#contributing)

---

## Quick Start

### Prerequisites

- Java 21 (`JAVA_HOME` must point to a Java 21 JDK)
- Maven 3.9+
- Docker (for Testcontainers in tests)

```bash
# Verify Java version
java -version   # must be 21

# Verify Maven resolves with Java 21
JAVA_HOME=/opt/homebrew/opt/openjdk@21 mvn -version
```

### Running locally

```bash
# 1. Set required environment variables
export DATASOURCE_URL=jdbc:postgresql://localhost:5432/tokenisation
export DATASOURCE_USER=tokenisation_app
export DATASOURCE_PASSWORD=change_me
export PAN_HASH_SECRET=your-32-byte-secret-here!!!!!!!!
export TAMPER_DETECTION_SECRET=another-32-byte-secret-here!!!!!
export KMS_PROVIDER=local-dev

# 2. Start with local dev KMS (no AWS needed)
JAVA_HOME=/opt/homebrew/opt/openjdk@21 mvn spring-boot:run
```

The application starts on port 8080. Swagger UI is available at:
```
http://localhost:8080/swagger-ui.html
```

### Running with AWS KMS

```bash
export KMS_PROVIDER=aws
export AWS_REGION=ap-southeast-2
export AWS_KMS_KEY_ARN=arn:aws:kms:ap-southeast-2:123456789012:key/your-key-id
# Use IAM role — do not set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY in production
```

---

## API Reference

Full interactive documentation is available at `/swagger-ui.html`. Quick reference:

### Tokenise a PAN

```http
POST /api/v1/tokens
Content-Type: application/json

{
  "pan": "4111111111111111",
  "expiryMonth": 12,
  "expiryYear": 2027,
  "cardScheme": "VISA",
  "tokenType": "ONE_TIME",
  "merchantId": "MERCHANT_001"
}
```

**Response (201 Created):**
```json
{
  "token": "3a4f9d2e-1b5c-4f8a-a3e7-c6d9f0b2a1e4",
  "tokenType": "ONE_TIME",
  "lastFour": "1111",
  "cardScheme": "VISA",
  "createdAt": "2026-04-17T00:00:00Z"
}
```

**Token types:**
- `ONE_TIME` — unique token per request (e.g. one-off payment)
- `RECURRING` — deterministic; same PAN + merchant always returns the same token (e.g. subscription billing)

### Detokenise a token

```http
GET /api/v1/tokens/3a4f9d2e-1b5c-4f8a-a3e7-c6d9f0b2a1e4
X-Merchant-ID: MERCHANT_001
```

**Response (200 OK):**
```json
{
  "pan": "4111111111111111",
  "lastFour": "1111",
  "cardScheme": "VISA",
  "tokenType": "ONE_TIME",
  "expiryMonth": 12,
  "expiryYear": 2027
}
```

**Error responses:**
- `403` — `X-Merchant-ID` does not match the token's owner
- `404` — Token not found or inactive
- `429` — Rate limit exceeded
- `500` — Crypto failure or compromised key

### Health check

```http
GET /api/v1/health
```

Returns `200 UP` when the database and key ring are healthy, `503 DEGRADED` otherwise.

### Metrics

```http
GET /api/v1/metrics
```

Returns uptime, tokenise/detokenise request counts, and server error count since last restart.

### Key rotation (admin)

```http
POST /api/v1/admin/keys/rotate
Content-Type: application/json

{
  "reason": "SCHEDULED",
  "newKeyAlias": "vault-key-2026-q2"
}
```

For emergency rotation:
```json
{
  "reason": "COMPROMISE",
  "compromisedVersionId": "uuid-of-compromised-key",
  "newKeyAlias": "emergency-2026-04-17"
}
```

See [key-rotation-runbook.md](docs/key-rotation-runbook.md) for the full procedure.

---

## Configuration

All configuration is in `src/main/resources/application.yml`. Sensitive values are loaded from environment variables.

| Environment variable | Purpose | Required |
|----------------------|---------|----------|
| `DATASOURCE_URL` | PostgreSQL JDBC URL | Yes |
| `DATASOURCE_USER` | DB username (use `tokenisation_app` in prod) | Yes |
| `DATASOURCE_PASSWORD` | DB password | Yes |
| `PAN_HASH_SECRET` | HMAC-SHA256 secret for PAN deduplication | Yes |
| `TAMPER_DETECTION_SECRET` | HMAC-SHA256 secret for key_versions row integrity | Yes |
| `KMS_PROVIDER` | `aws` or `local-dev` | Yes |
| `AWS_REGION` | AWS region (when `KMS_PROVIDER=aws`) | AWS only |
| `AWS_KMS_KEY_ARN` | CMK ARN (when `KMS_PROVIDER=aws`) | AWS only |

### Key application.yml settings

```yaml
rotation:
  batch:
    cron: "0 */15 * * * *"   # run rotation batches every 15 minutes
    size: 500                  # tokens per batch (scheduled)
    emergency-size: 100        # tokens per batch (emergency)
  compliance:
    max-key-age-days: 365      # rotate before this age

detokenisation:
  rate-limit:
    per-merchant-per-minute: 1000
    per-service-per-minute: 10000
```

---

## Running Tests

```bash
# All unit and integration tests (requires Docker for Testcontainers)
JAVA_HOME=/opt/homebrew/opt/openjdk@21 mvn test

# Specific test class
JAVA_HOME=/opt/homebrew/opt/openjdk@21 mvn test -Dtest=TokenisationIntegrationTest
```

The test suite uses Testcontainers to start a real PostgreSQL 16 instance — no manual DB setup required. The `LocalDevKmsAdapter` is used so no AWS credentials are needed.

### Test structure

| Package | Type | What it covers |
|---------|------|----------------|
| `com.yourorg.tokenisation` | Integration | Full HTTP → DB → audit log round trips |
| `com.yourorg.tokenisation.service` | Unit | Service layer business logic |
| `com.yourorg.tokenisation.crypto` | Unit | AES-GCM cipher, key ring, tamper detector |
| `com.yourorg.tokenisation.kms` | Unit | KMS adapter (mocked KMS client) |
| `com.yourorg.tokenisation.rotation` | Unit + Integration | Key rotation service and batch processor |
| `com.yourorg.tokenisation.api` | Unit | Controller request/response handling |
| `com.yourorg.tokenisation.security` | Unit | PAN log masking |

---

## Load Testing

Load tests are excluded from the standard `mvn test` run. They require Docker and take several minutes to complete.

```bash
# Run all load tests
make load-test

# Run only the 1K-scale methods across all throughput test classes
make load-test SCALE=1k

# Run only the 5K-scale methods
make load-test SCALE=5k

# Other valid values: 10k, 20k, 50k
make load-test SCALE=10k
make load-test SCALE=50k
```

When `SCALE` is set, only `TokenisationLoadTest`, `DetokenisationLoadTest`, and `MixedWorkloadLoadTest` methods for that scale are executed. `KeyRotationUnderLoadTest` and `TamperedKeyUnderLoadTest` are scenario tests with no scale variants — they run only when `SCALE` is omitted.

Results are written as JSON to `target/load-test-results/` after each test.

### Load test scenarios

| Test class | Scenario | Scale | Max concurrency |
|------------|----------|-------|-----------------|
| `TokenisationLoadTest` | `POST /api/v1/tokens` only | 1K → 50K requests | 20 |
| `DetokenisationLoadTest` | `GET /api/v1/tokens/{token}` only | 1K → 50K requests | 20 |
| `MixedWorkloadLoadTest` | 40% tokenise + 35% detokenise + 20% recurring + 5% status | 1K → 50K requests | 20 |
| `KeyRotationUnderLoadTest` | Full rotation while live traffic continues | 1K pre-seeded tokens | 20 |
| `TamperedKeyUnderLoadTest` | DB-level key tamper during load | 500 pre-seeded tokens | 20 |

### Performance targets

| Operation | p99 target (developer laptop) |
|-----------|-------------------------------|
| Tokenise | ≤ 2000ms |
| Detokenise | ≤ 2000ms |
| Mixed workload | ≤ 2000ms |

These targets are intentionally conservative to accommodate the variable performance of a Testcontainers PostgreSQL container on a developer laptop. A production-grade load test against a dedicated PostgreSQL instance would use tighter thresholds (sub-500ms p99).

---

### Load test design constraints and pitfalls

This section documents the failure modes discovered during development so that future changes do not reintroduce them.

#### Rule: pool size must be significantly larger than max concurrency

**Invariant:** `HikariCP maximum-pool-size ≥ 2 × max-concurrency`

The load tests run inside `@SpringBootTest(RANDOM_PORT)`. The embedded Tomcat server and the test code (seeding `JdbcTemplate`, `@BeforeEach` cleanup) share the **same** HikariCP connection pool. This means the pool must serve both the test-generated HTTP requests AND the background connection usage of the Spring framework itself:

- HikariCP housekeeper thread (periodic connection validation and eviction)
- Spring JPA `EntityManagerFactory` internal threads
- `@BeforeEach` `JdbcTemplate` cleanup that runs between test methods
- Any Spring Boot auto-configuration that briefly touches the `DataSource`

If you set `maximum-pool-size == max-concurrency`, the pool is fully saturated during seeding or test phases and background threads cannot acquire connections. The timeout fires even when test concurrency is below the pool limit:

```
HikariPool-1 - Connection is not available, request timed out after 10003ms
(total=20, active=20, idle=0, waiting=10)
```

**Fix applied:** `application-load-test.yml` sets `maximum-pool-size: 40` and `minimum-idle: 5`. With max test concurrency of 20, the pool has a 20-connection buffer for all background activity.

**Anti-pattern:** do NOT set `minimum-idle == maximum-pool-size`. This creates a fully-saturated fixed-size pool that exposes the zero-margin problem immediately.

#### Pitfall: seeding phases also exhaust the pool

The `DetokenisationLoadTest`, `KeyRotationUnderLoadTest`, and `TamperedKeyUnderLoadTest` all pre-seed tokens before the measured test phase runs. The seeding phase submits N tasks to a parallel executor. If the seeding executor uses a higher parallelism than the pool size (e.g. `parallelism=100` with `pool-size=40`), the seeding phase itself exhausts the pool before the test even starts.

**Fix applied:** All `seedTokens()` and `seedInitialPool()` calls use `parallelism=20`.

#### Pitfall: Tomcat platform threads block OS threads while waiting for connections

When Spring uses Tomcat with platform (OS) threads (`spring.threads.virtual.enabled=false`, the default), a platform thread that is blocked inside `HikariCP.getConnection()` occupies an OS thread for the full `connection-timeout` duration. With 200 concurrent load requests and `connection-timeout=30s`, this produces a 16-minute stall — each OS thread is frozen waiting for a connection that never arrives.

Switching to virtual threads (`spring.threads.virtual.enabled=true`) mitigates this because a virtual thread *parks* (yields its carrier OS thread back) rather than blocking while waiting. However, this is a mitigation, not a solution — the correct fix is ensuring concurrency never exceeds pool size.

#### Pitfall: virtual thread pinning under JDBC synchronized blocks

The PostgreSQL JDBC driver uses `synchronized` blocks for socket I/O. A virtual thread inside a `synchronized` block is *pinned* to its carrier OS thread and cannot park. The JVM's virtual-thread scheduler defaults to `availableProcessors` carrier threads. With 200 virtual threads all pinned in JDBC calls simultaneously, only N-core threads make progress; the rest stall waiting for a carrier.

The `load-tests` Maven profile adds these JVM flags via the Surefire `argLine`:

```xml
-Djdk.virtualThreadScheduler.parallelism=256
-Djdk.virtualThreadScheduler.maxPoolSize=512
```

This gives the scheduler enough carrier threads to run all concurrently-pinned virtual threads. However, as with the Tomcat platform-thread issue, this is a mitigation. The primary fix is keeping concurrency ≤ 20.

#### Pitfall: shared PAN for RECURRING tokenisation causes NonUniqueResultException

`MixedWorkloadLoadTest` originally used a fixed PAN (`"4111111111111111"`) for all `TOKENISE_RECURRING` operations to exercise the deduplication path. Under concurrent load (15+ threads), this causes a race condition:

1. Multiple threads call `findActiveRecurringByPanHashAndMerchant` simultaneously.
2. All find zero results (no token exists yet).
3. All insert a new `RECURRING` token for the same PAN + merchant.
4. The next call to the same query finds N rows and throws `NonUniqueResultException` because Spring Data JPA's `Optional<T>` return type uses `getSingleResult()` internally.

The symptom appears at 5K scale (1,000 RECURRING requests at 15 concurrency) but not at 1K scale (200 RECURRING requests at 10 concurrency) — higher concurrency means more simultaneous inserts.

**Fix applied:** All tokenisation requests (ONE_TIME and RECURRING) use `PanGenerator.generateVisa16()` to generate unique PANs. No two threads compete for the same PAN+merchant slot, so there is never more than one token per key. Dedup correctness under concurrent writes is covered by `DetokenisationIntegrationTest`, not by the load tests.

#### Pitfall: Testcontainers PostgreSQL has a low default connection limit

The official PostgreSQL Alpine Docker image defaults to `max_connections=100`. With a load test pool of 100 and normal Spring Boot connection overhead, the container's server-side limit is hit before Hikari's client-side limit. The symptom is a PostgreSQL `FATAL: sorry, too many clients already` error rather than a Hikari timeout.

**Fix applied:** `AbstractIntegrationTest` starts the container with:

```java
.withCommand("postgres", "-c", "max_connections=300")
```

This gives the container enough headroom for the load test pool (20) plus the integration test suite running concurrently.

#### Summary: the three-layer constraint

For load tests to run reliably on a developer laptop:

```
load-test concurrency  <  HikariCP pool size  ≤  PostgreSQL max_connections
       20              <        40            ≤          300
```

The `<` (strict less-than) between concurrency and pool size is intentional — there must be a buffer for background framework connections. Setting concurrency == pool size leaves zero margin and causes timeouts. Breaking any layer causes failures in that layer.

---

## Architecture

For a detailed explanation of how the system works — including plain-language definitions of DEK, KEK, KMS, envelope encryption, and tamper detection — see [docs/design.md](docs/design.md).

### Component overview

```
REST API
  TokenController          → POST /api/v1/tokens, GET /api/v1/tokens/{token}
  AdminKeyController       → POST /api/v1/admin/keys/rotate
  HealthController         → GET /api/v1/health
  MetricsController        → GET /api/v1/metrics

Service Layer
  TokenisationService      → PAN validation, dedup, envelope encrypt, audit
  DetokenisationService    → scope check, DEK unwrap, GCM decrypt, audit
  KeyRotationService       → scheduled / emergency rotation initiation

Crypto Layer
  AesGcmCipher             → AES-256-GCM encrypt / decrypt / wrap DEK
  PanHasher                → HMAC-SHA256 PAN fingerprint (dedup)
  InMemoryKeyRing          → versioned in-memory KEK store
  TamperDetector           → HMAC-SHA256 row integrity check

KMS Layer
  KmsProvider              → interface: generateDek, rewrapDek, unwrapKek
  AwsKmsAdapter            → AWS KMS implementation
  LocalDevKmsAdapter       → in-process implementation (tests + local dev)

Monitoring
  HealthService            → DB + key ring liveness checks
  MetricsCollector         → AtomicLong counters for request/error tracking
  MetricsInterceptor       → HandlerInterceptor to count requests by type

Rotation
  RotationJob              → @Scheduled batch driver
  RotationBatchProcessor   → per-token re-encryption with optimistic locking
```

---

## Key Rotation

See the full operational runbook at [docs/key-rotation-runbook.md](docs/key-rotation-runbook.md).

**Quick reference:**

```bash
# Scheduled rotation
curl -X POST http://localhost:8080/api/v1/admin/keys/rotate \
  -H 'Content-Type: application/json' \
  -d '{"reason":"SCHEDULED","newKeyAlias":"vault-key-2026-q2"}'

# Emergency rotation (key compromise)
curl -X POST http://localhost:8080/api/v1/admin/keys/rotate \
  -H 'Content-Type: application/json' \
  -d '{"reason":"COMPROMISE","compromisedVersionId":"<uuid>","newKeyAlias":"emergency-key"}'
```

Both return HTTP 202. Batch re-encryption runs automatically via `RotationJob` (every 15 minutes by default).

---

## Security and Production Readiness

### Known gaps before production deployment

The following items are implemented as stubs or deferred to Phase 2. **Do not deploy to production until they are addressed.**

| Severity | Item | Location | Status |
|----------|------|----------|--------|
| CRITICAL | All API endpoints allow unauthenticated access | `SecurityConfig.java` | Phase 2 — JWT stub in place |
| CRITICAL | Merchant ID accepted from request body (should come from JWT) | `TokenController.java` | Resolved when JWT is wired up |
| CRITICAL | Admin key rotation endpoint has no authentication | `AdminKeyController.java` | Protect with mTLS or admin JWT role before deploy |
| HIGH | Swagger UI accessible without auth | `application.yml` springdoc section | Disable in production profile |
| HIGH | Rate limiting is single-node only (Caffeine in-memory) | `RateLimitInterceptor.java` | Redis-backed for multi-node |

### What is hardened

- AES-256-GCM envelope encryption with a fresh DEK and IV per tokenisation
- All key material (`kek`, `panBytes`, `newEncryptedDek`) zeroed in `finally` blocks
- PAN never written to logs, audit records, or exception messages (enforced by `PanMaskingTurboFilter`)
- HMAC-SHA256 tamper detection on all `key_versions` rows; integrity failure during rotation now halts and raises a `TAMPER_ALERT` audit event
- In-memory key ring state verified by the health endpoint (not just the database)
- HikariCP default removed; KEK has no hardcoded fallback in `application.yml`
- Database role `tokenisation_app` has minimum-privilege grants; audit log is append-only at DB layer
- No passwords committed to source control (`V6__setup_db_roles.sql` creates role without password)
- Caffeine rate limiter bounded to 10,000 merchant entries; header length validated at ≤256 characters

### Documentation

| Document | Contents |
|----------|----------|
| [`docs/ops-runbook.md`](docs/ops-runbook.md) | mTLS setup, database high-throughput tuning, monitoring, JWT auth, distributed rate limiting, incident response |
| [`docs/pre-production-hardening.md`](docs/pre-production-hardening.md) | PP-1 through PP-6 hardening checklist |
| [`docs/key-rotation-runbook.md`](docs/key-rotation-runbook.md) | Scheduled and emergency key rotation procedures |

---

## Contributing

### Code standards

See [docs/agent-code-standards.md](docs/agent-code-standards.md) and [docs/agent-test-standards.md](docs/agent-test-standards.md).

### Key rules

- No PAN in logs, errors, or audit records — the `PanMaskingTurboFilter` enforces this but do not rely on it.
- Constructor injection only — no `@Autowired` on fields.
- Every new class needs a Javadoc comment explaining its purpose.
- Integration tests must use Testcontainers PostgreSQL — no in-memory DB.
- A task is only complete when unit tests, integration tests, and Javadoc are all satisfied.

### Running the full suite before a PR

```bash
JAVA_HOME=/opt/homebrew/opt/openjdk@21 mvn verify
```

Expected: `BUILD SUCCESS` with 0 failures and 0 errors.
