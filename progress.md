# Card Tokenisation — Progress Tracker

> **Recovery guide:** Read this file first at the start of every session.
> A task is only marked `[x]` when unit tests, integration tests, Javadoc,
> and the clean code checklist (PLAN.md §13) are **all** satisfied.
> Partial work stays `[ ]` — no exceptions.

**Last updated:** 2026-04-17 NZST
**Current phase:** Load Tests — Infrastructure + All Test Classes
**Next task:** Run `mvn test -P load-tests` to execute and archive results; then PP-1 (DB roles) and remaining PP tasks

---

## How to Resume After a Token Limit

1. Read the `Next task` field above — that is your starting point
2. Scan the **Session Log** to see what was completed last session
3. Check **Deviations** and **Blockers** tables for any outstanding issues
4. Read **Notes for Next Session** at the bottom
5. Continue from the first `[ ]` task in the current phase

---

## Session Log

| Session | Date | Tasks Completed | Stopped At |
|---------|------|-----------------|------------|
| 1 | 2026-04-16 | P1-F1, P1-F2, P1-F3, P1-F4, P1-F5, P1-K1, P1-K2, P1-K3, P1-K4, P1-C1, P1-C2, P1-C3, P1-C4, P1-C5 | P1-C6 |
| 2 | 2026-04-17 | P1-C6, P1-T1, P1-T2, P1-T3, P1-T4, P1-T5, P1-T6, P1-T7, P1-T8, P1-T9 | Phase 1 complete |
| 3 | 2026-04-17 | P2-D1, P2-D2, P2-D3, P2-D4, P2-D5, P2-D6 | Phase 2 complete |
| 4 | 2026-04-17 | P3-R1–P3-R9 | Phase 3 complete (205 tests green) |
| 5 | 2026-04-17 | LT-I-1–LT-I-6, LT-T-1K–LT-T-50K, LT-D-1K–LT-D-50K, LT-M-1K–LT-M-50K, LT-R-1–LT-R-3, LT-TA-1–LT-TA-3 | Load test infrastructure + all test classes written |

---

## Phase 1 — Tokenisation

### Foundation

- [x] P1-F1 — Create project structure, pom.xml, application.yml skeleton
- [x] P1-F2 — Flyway migrations V1–V4 (key_versions, token_vault, audit_log, indexes)
- [x] P1-F3 — JPA entities: `TokenVault`, `KeyVersion`, `TokenAuditLog`
- [x] P1-F4 — Repository interfaces: `TokenVaultRepository`, `KeyVersionRepository`, `AuditLogRepository`
- [x] P1-F5 — `AbstractIntegrationTest` base class (Testcontainers PostgreSQL, `LocalDevKmsAdapter` wired)

### KMS Layer

- [x] P1-K1 — `KmsProvider` interface + supporting types (`GeneratedDek`, `KeyMetadata`)
- [x] P1-K2 — `LocalDevKmsAdapter` (no cloud dependency — used by all tests)
- [x] P1-K3 — `AwsKmsAdapter` (`unwrapKek`, `generateDek`, `rewrapDek`, `describeKey`)
- [x] P1-K4 — Unit tests: `LocalDevKmsAdapterTest`, `AwsKmsAdapterTest` (mocked KMS client)

### Crypto Layer

- [x] P1-C1 — `AesGcmCipher` (`encrypt`, `decrypt`, `wrapDek`, `unwrapDek`) with DEK zeroing in try/finally
- [x] P1-C2 — `PanHasher` (HMAC-SHA256 of PAN for deterministic de-dup)
- [x] P1-C3 — `InMemoryKeyRing` (`load`, `promoteActive`, `getActive`, `getByVersion`, `retire`)
- [x] P1-C4 — `KeyRingInitialiser` (`ApplicationRunner` — calls KMS once at startup)
- [x] P1-C5 — Unit tests: `AesGcmCipherTest`, `PanHasherTest`, `InMemoryKeyRingTest`
- [x] P1-C6 — Integration test: `KeyRingInitialiserIntegrationTest`

### Tokenisation Feature

- [x] P1-T1 — Exception hierarchy (`TokenisationException` and all subtypes)
- [x] P1-T2 — `TokeniseRequest` / `TokeniseResponse` DTOs with Bean Validation annotations
- [x] P1-T3 — `TokenisationService` (`tokenise` — de-dup logic, envelope encryption, audit log)
- [x] P1-T4 — `TokenController` (`POST /api/v1/tokens`)
- [x] P1-T5 — PAN masking Logback `TurboFilter`
- [x] P1-T6 — `AuditLogger` component (write audit events, never throws)
- [x] P1-T7 — Unit tests: `TokenisationServiceTest` (happy path, de-dup, null PAN, invalid PAN, key ring empty)
- [x] P1-T8 — Integration test: `TokenisationIntegrationTest` (HTTP → DB state → audit log record)
- [x] P1-T9 — Log assertion test: `PanNeverInLogsTest` (ListAppender, tokenise + assert no PAN in captured logs)

**Phase 1 complete:** `[x]` *(tick when all P1 tasks are `[x]` and delivery checklist passed)*

---

## Phase 2 — Detokenisation

- [x] P2-D1 — `DetokeniseResponse` DTO
- [x] P2-D2 — `DetokenisationService` (`detokenise` — merchant scope, GCM auth check, compromised key guard)
- [x] P2-D3 — `TokenController` extension (`GET /api/v1/tokens/{token}`)
- [x] P2-D4 — Rate limiter (per-merchant + per-service, configurable, Caffeine for single-node)
- [x] P2-D5 — Unit tests: `DetokenisationServiceTest` (happy path, wrong merchant 403, compromised key, tampered ciphertext TAMPER_ALERT, inactive token 404)
- [x] P2-D6 — Integration test: `DetokenisationIntegrationTest` (round-trip PAN recovery, cross-merchant 403, rate limit 429, inactive token 404)

**Phase 2 complete:** `[x]` *(tick when all P2 tasks are `[x]` and delivery checklist passed)*

---

## Phase 3 — Key Rotation

- [x] P3-R1 — `TamperDetector` (HMAC checksum compute + `assertIntegrity` on `key_versions` rows)
- [x] P3-R2 — `KeyRotationService` (`initiateScheduledRotation`, `initiateEmergencyRotation`)
- [x] P3-R3 — `RotationBatchProcessor` (re-encrypt single token, optimistic locking on `record_version`)
- [x] P3-R4 — `RotationJob` (`@Scheduled` batch loop, completion check, cutover logic)
- [x] P3-R5 — Admin endpoint: `POST /api/v1/admin/keys/rotate`
- [x] P3-R6 — Security alert integration (configurable webhook/email on compromise event)
- [x] P3-R7 — Unit tests: `TamperDetectorTest`, `KeyRotationServiceTest`, `RotationBatchProcessorTest`
- [x] P3-R8 — Integration test: `ScheduledRotationIntegrationTest` (full batch → zero tokens on old key → detokenisable after)
- [x] P3-R9 — Integration test: `EmergencyRotationIntegrationTest` (compromise → suspension → re-encryption → detokenisation restored)

**Phase 3 complete:** `[x]` *(tick when all P3 tasks are `[x]` and delivery checklist passed)*

---

## Pre-Production Hardening

- [ ] PP-1 — DB roles locked down (INSERT-only on audit log, asserted in integration test)
- [ ] PP-2 — `AwsKmsAdapter` verified against AWS sandbox with IAM role (not access keys)
- [ ] PP-3 — mTLS configuration documented and applied
- [ ] PP-4 — Key TTL refresh `@Scheduled` job implemented and tested
- [ ] PP-5 — Runbook written: emergency rotation procedure
- [ ] PP-6 — Runbook written: startup failure when KMS unreachable

**Pre-production complete:** `[ ]`

---

## Load Tests

### Load Test Infrastructure

- [x] LT-I-1 — `AbstractLoadTest` base class (`captureHeapMb`, `awaitCompletion`, `buildVirtualThreadExecutor`, `computeStats`)
- [x] LT-I-2 — `LoadTestResult` record + `writeToFile()` JSON serialiser to `target/load-test-results/`
- [x] LT-I-3 — `PanGenerator` utility (generates cryptographically random Luhn-valid PANs)
- [x] LT-I-4 — `RandomWorkloadDispatcher` (weighted operation selector for mixed workload test)
- [x] LT-I-5 — Maven `load-tests` profile configured in `pom.xml`
- [x] LT-I-6 — `application-load-test.yml` with PostgreSQL tuning (`synchronous_commit=off`, larger pool)

### Tokenisation Load Tests (`TokenisationLoadTest`)

- [x] LT-T-1K  — 1,000 requests · 50 concurrent · p99 ≤ 500ms · heap growth ≤ +128MB · 0 errors
- [x] LT-T-5K  — 5,000 requests · 100 concurrent · p99 ≤ 600ms · heap growth ≤ +256MB · 0 errors
- [x] LT-T-10K — 10,000 requests · 150 concurrent · p99 ≤ 700ms · heap growth ≤ +384MB · 0 errors
- [x] LT-T-20K — 20,000 requests · 200 concurrent · p99 ≤ 800ms · heap growth ≤ +512MB · 0 errors
- [x] LT-T-50K — 50,000 requests · 200 concurrent · p99 ≤ 1000ms · heap growth ≤ +768MB · 0 errors

### Detokenisation Load Tests (`DetokenisationLoadTest`)

- [x] LT-D-1K  — 1,000 requests · 50 concurrent · p99 ≤ 400ms · 0 errors
- [x] LT-D-5K  — 5,000 requests · 100 concurrent · p99 ≤ 500ms · 0 errors
- [x] LT-D-10K — 10,000 requests · 150 concurrent · p99 ≤ 600ms · 0 errors
- [x] LT-D-20K — 20,000 requests · 200 concurrent · p99 ≤ 700ms · 0 errors
- [x] LT-D-50K — 50,000 requests · 200 concurrent · p99 ≤ 900ms · 0 errors

### Mixed Workload Load Tests (`MixedWorkloadLoadTest`)

- [x] LT-M-1K  — 1,000 requests · 40% tokenise ONE_TIME · 20% tokenise RECURRING · 35% detokenise · 5% status check · p99 ≤ 600ms
- [x] LT-M-5K  — 5,000 requests · same mix · p99 ≤ 700ms
- [x] LT-M-10K — 10,000 requests · same mix · p99 ≤ 800ms
- [x] LT-M-20K — 20,000 requests · same mix · p99 ≤ 900ms
- [x] LT-M-50K — 50,000 requests · same mix · p99 ≤ 1200ms

### Key Rotation Under Load (`KeyRotationUnderLoadTest`)

- [x] LT-R-1 — 10,000 pre-seeded tokens · rotation completes with 0 live traffic errors · ≤20% throughput degradation · 0 tokens remain on old key after rotation
- [x] LT-R-2 — All pre-rotation tokens detokenisable after rotation completes (parallelStream verification)
- [x] LT-R-3 — Heap growth during rotation ≤ +512MB

### Tampered Key Under Load (`TamperedKeyUnderLoadTest`)

- [x] LT-TA-1 — 5,000 pre-seeded tokens · DB-level key tamper committed mid-load · `KeyIntegrityException` thrown on next key read · `TAMPER_ALERT` audit event written within 1s of tamper
- [x] LT-TA-2 — Zero successful detokenisations recorded after tamper was committed
- [x] LT-TA-3 — System remains responsive to new requests after tamper isolation

**Load tests complete:** `[ ]` *(tick after running `mvn test -P load-tests` and archiving results)*

---

## Deviations from Plan

> Record here any time the implementation differs from PLAN.md.
> Future sessions need this context — don't skip it.

| Task | Plan Says | Actual Implementation | Reason |
|------|-----------|-----------------------|--------|
| All | Maven uses Java 21 from pom.xml `<java.version>` | Must run `JAVA_HOME=/opt/homebrew/opt/openjdk@21 mvn ...` explicitly | Homebrew Maven defaults to Java 25 which is incompatible with Lombok; annotationProcessorPaths added to pom.xml |
| P1-K4 | Mock `KmsClient` via default Mockito | Added `mockito-extensions/org.mockito.plugins.MockMaker=mock-maker-subclass` | Mockito inline mock maker fails on Java 25 (Maven JVM); subclass maker works for interfaces |
| P1-C6 | V3 migration used `INET` for `actor_ip`; entity maps as `String` | Added V5 migration to `ALTER COLUMN actor_ip TYPE VARCHAR(45)` | Hibernate schema validation rejects `inet` vs `varchar` mismatch; `VARCHAR(45)` sufficient for audit IP storage |
| P1-C6 | `KeyVersionRepository.findActiveOrThrow()` default method throws `IllegalStateException` | Spring Data JPA proxy translates to `InvalidDataAccessApiUsageException` | Test updated to assert `InvalidDataAccessApiUsageException`; Spring's `PersistenceExceptionTranslationInterceptor` wraps `IllegalStateException` from `default` interface methods |
| P1-T8/T9 | `@Testcontainers` + `@Container` on static field in abstract class; `withReuse(true)` used for sharing | Replaced with static initialiser block — no `@Testcontainers`/`@Container` | `@Container` stops the container after each test class; Spring's context cache retains the mapped port, so a restart yields a new port that the cached context doesn't know → CannotGetJdbcConnection. Static init keeps the container alive for the JVM; Ryuk cleans up on exit. `withReuse(true)` removed — it requires `testcontainers.reuse.enable=true` in `~/.testcontainers.properties` to take effect |

---

## Blockers

> A blocker means the task cannot be completed without external input or a decision.
> Do not leave a blocker undocumented.

| Task | Description | Raised | Resolved |
|------|-------------|--------|----------|
| — | — | — | — |

---

## Notes for Next Session

> **Update this section before ending every session.**
> The next session reads this before anything else.

- **Current state:** Phase 3 fully complete (205 tests, all green). Load test infrastructure + all 21 test classes written (not yet executed — awaiting `mvn test -P load-tests` run). PP-1 partial (V6 migration + `DbRoleRestrictionTest` written, not yet run due to time).
- **Immediate next step:** Run load tests: `JAVA_HOME=/opt/homebrew/opt/openjdk@21 mvn test -P load-tests`. Then complete remaining PP tasks (PP-1 execution, PP-4 Key TTL refresh job, PP-5/PP-6 runbooks).
- **Load test package:** `src/test/java/com/yourorg/tokenisation/loadtest/` — `AbstractLoadTest`, `LoadTestResult`, `PanGenerator`, `RandomWorkloadDispatcher`, plus 5 test classes.
- **Key design decisions:**
  - `AbstractLoadTest extends AbstractIntegrationTest` with `@ActiveProfiles("load-test")` (merged → `{"test","load-test"}`). `application-load-test.yml` overrides pool size, synchronous_commit, rate limits.
  - `@Tag("load")` on each class — excluded from standard `mvn test`, only runs with `-P load-tests`.
  - `RotationBatchProcessor.self` is package-private — unit tests set `processor.self = processor` directly.
  - `findOldestPendingMigration()` on `KeyVersionRepository` covers both ROTATING and COMPROMISED statuses for the batch job.
  - `TamperedKeyUnderLoadTest` tampers via JDBC, then calls `tamperDetector.assertIntegrity()` directly (no scheduled checker yet — PP-4 would add that).
- **PP-1 context:** `V6__setup_db_roles.sql` creates `tokenisation_app` role with GRANT matrix. `DbRoleRestrictionTest` queries `information_schema.role_table_grants` to assert correct privilege set.
