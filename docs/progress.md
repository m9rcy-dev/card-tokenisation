# Card Tokenisation — Progress Tracker

> **Recovery guide:** Read this file first at the start of every session.
> A task is only marked `[x]` when unit tests, integration tests, Javadoc,
> and the clean code checklist (PLAN.md §13) are **all** satisfied.
> Partial work stays `[ ]` — no exceptions.

**Last updated:** YYYY-MM-DD HH:MM NZST  
**Current phase:** Phase 1 — Tokenisation  
**Next task:** P1-F1 — Create project structure, pom.xml, application.yml skeleton

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
| — | — | — | — |

---

## Phase 1 — Tokenisation

### Foundation

- [ ] P1-F1 — Create project structure, pom.xml, application.yml skeleton
- [ ] P1-F2 — Flyway migrations V1–V4 (key_versions, token_vault, audit_log, indexes)
- [ ] P1-F3 — JPA entities: `TokenVault`, `KeyVersion`, `TokenAuditLog`
- [ ] P1-F4 — Repository interfaces: `TokenVaultRepository`, `KeyVersionRepository`, `AuditLogRepository`
- [ ] P1-F5 — `AbstractIntegrationTest` base class (Testcontainers PostgreSQL, `LocalDevKmsAdapter` wired)

### KMS Layer

- [ ] P1-K1 — `KmsProvider` interface + supporting types (`GeneratedDek`, `KeyMetadata`)
- [ ] P1-K2 — `LocalDevKmsAdapter` (no cloud dependency — used by all tests)
- [ ] P1-K3 — `AwsKmsAdapter` (`unwrapKek`, `generateDek`, `rewrapDek`, `describeKey`)
- [ ] P1-K4 — Unit tests: `LocalDevKmsAdapterTest`, `AwsKmsAdapterTest` (mocked KMS client)

### Crypto Layer

- [ ] P1-C1 — `AesGcmCipher` (`encrypt`, `decrypt`, `wrapDek`, `unwrapDek`) with DEK zeroing in try/finally
- [ ] P1-C2 — `PanHasher` (HMAC-SHA256 of PAN for deterministic de-dup)
- [ ] P1-C3 — `InMemoryKeyRing` (`load`, `promoteActive`, `getActive`, `getByVersion`, `retire`)
- [ ] P1-C4 — `KeyRingInitialiser` (`ApplicationRunner` — calls KMS once at startup)
- [ ] P1-C5 — Unit tests: `AesGcmCipherTest`, `PanHasherTest`, `InMemoryKeyRingTest`
- [ ] P1-C6 — Integration test: `KeyRingInitialiserIntegrationTest`

### Tokenisation Feature

- [ ] P1-T1 — Exception hierarchy (`TokenisationException` and all subtypes)
- [ ] P1-T2 — `TokeniseRequest` / `TokeniseResponse` DTOs with Bean Validation annotations
- [ ] P1-T3 — `TokenisationService` (`tokenise` — de-dup logic, envelope encryption, audit log)
- [ ] P1-T4 — `TokenController` (`POST /api/v1/tokens`)
- [ ] P1-T5 — PAN masking Logback `TurboFilter`
- [ ] P1-T6 — `AuditLogger` component (write audit events, never throws)
- [ ] P1-T7 — Unit tests: `TokenisationServiceTest` (happy path, de-dup, null PAN, invalid PAN, key ring empty)
- [ ] P1-T8 — Integration test: `TokenisationIntegrationTest` (HTTP → DB state → audit log record)
- [ ] P1-T9 — Log assertion test: `PanNeverInLogsTest` (ListAppender, tokenise + assert no PAN in captured logs)

**Phase 1 complete:** `[ ]` *(tick when all P1 tasks are `[x]` and delivery checklist passed)*

---

## Phase 2 — Detokenisation

- [ ] P2-D1 — `DetokeniseResponse` DTO
- [ ] P2-D2 — `DetokenisationService` (`detokenise` — merchant scope, GCM auth check, compromised key guard)
- [ ] P2-D3 — `TokenController` extension (`GET /api/v1/tokens/{token}`)
- [ ] P2-D4 — Rate limiter (per-merchant + per-service, configurable, Caffeine for single-node)
- [ ] P2-D5 — Unit tests: `DetokenisationServiceTest` (happy path, wrong merchant 403, compromised key, tampered ciphertext TAMPER_ALERT, inactive token 404)
- [ ] P2-D6 — Integration test: `DetokenisationIntegrationTest` (round-trip PAN recovery, cross-merchant 403, rate limit 429, inactive token 404)

**Phase 2 complete:** `[ ]` *(tick when all P2 tasks are `[x]` and delivery checklist passed)*

---

## Phase 3 — Key Rotation

- [ ] P3-R1 — `TamperDetector` (HMAC checksum compute + `assertIntegrity` on `key_versions` rows)
- [ ] P3-R2 — `KeyRotationService` (`initiateScheduledRotation`, `initiateEmergencyRotation`)
- [ ] P3-R3 — `RotationBatchProcessor` (re-encrypt single token, optimistic locking on `record_version`)
- [ ] P3-R4 — `RotationJob` (`@Scheduled` batch loop, completion check, cutover logic)
- [ ] P3-R5 — Admin endpoint: `POST /api/v1/admin/keys/rotate`
- [ ] P3-R6 — Security alert integration (configurable webhook/email on compromise event)
- [ ] P3-R7 — Unit tests: `TamperDetectorTest`, `KeyRotationServiceTest`, `RotationBatchProcessorTest`
- [ ] P3-R8 — Integration test: `ScheduledRotationIntegrationTest` (full batch → zero tokens on old key → detokenisable after)
- [ ] P3-R9 — Integration test: `EmergencyRotationIntegrationTest` (compromise → suspension → re-encryption → detokenisation restored)

**Phase 3 complete:** `[ ]` *(tick when all P3 tasks are `[x]` and delivery checklist passed)*

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

- [ ] LT-I-1 — `AbstractLoadTest` base class (`captureMetrics`, `SystemMetrics`, `awaitCompletion`, `buildVirtualThreadExecutor`)
- [ ] LT-I-2 — `LoadTestResult` record + `writeLoadTestResult()` JSON serialiser to `target/load-test-results/`
- [ ] LT-I-3 — `PanGenerator` utility (generates cryptographically random Luhn-valid PANs)
- [ ] LT-I-4 — `RandomWorkloadDispatcher` (weighted operation selector for mixed workload test)
- [ ] LT-I-5 — Maven `load-tests` profile configured in `pom.xml`
- [ ] LT-I-6 — `application-load-test.yml` with PostgreSQL tuning (`synchronous_commit=off`, larger pool)

### Tokenisation Load Tests (`TokenisationLoadTest`)

- [ ] LT-T-1K  — 1,000 requests · 50 concurrent · p99 ≤ 500ms · heap growth ≤ +128MB · 0 errors
- [ ] LT-T-5K  — 5,000 requests · 100 concurrent · p99 ≤ 600ms · heap growth ≤ +256MB · 0 errors
- [ ] LT-T-10K — 10,000 requests · 150 concurrent · p99 ≤ 700ms · heap growth ≤ +384MB · 0 errors
- [ ] LT-T-20K — 20,000 requests · 200 concurrent · p99 ≤ 800ms · heap growth ≤ +512MB · 0 errors
- [ ] LT-T-50K — 50,000 requests · 200 concurrent · p99 ≤ 1000ms · heap growth ≤ +768MB · 0 errors

### Detokenisation Load Tests (`DetokenisationLoadTest`)

- [ ] LT-D-1K  — 1,000 requests · 50 concurrent · p99 ≤ 400ms · 0 errors
- [ ] LT-D-5K  — 5,000 requests · 100 concurrent · p99 ≤ 500ms · 0 errors
- [ ] LT-D-10K — 10,000 requests · 150 concurrent · p99 ≤ 600ms · 0 errors
- [ ] LT-D-20K — 20,000 requests · 200 concurrent · p99 ≤ 700ms · 0 errors
- [ ] LT-D-50K — 50,000 requests · 200 concurrent · p99 ≤ 900ms · 0 errors

### Mixed Workload Load Tests (`MixedWorkloadLoadTest`)

- [ ] LT-M-1K  — 1,000 requests · 40% tokenise ONE_TIME · 20% tokenise RECURRING · 35% detokenise · 5% status check · p99 ≤ 600ms
- [ ] LT-M-5K  — 5,000 requests · same mix · p99 ≤ 700ms
- [ ] LT-M-10K — 10,000 requests · same mix · p99 ≤ 800ms
- [ ] LT-M-20K — 20,000 requests · same mix · p99 ≤ 900ms
- [ ] LT-M-50K — 50,000 requests · same mix · p99 ≤ 1200ms

### Key Rotation Under Load (`KeyRotationUnderLoadTest`)

- [ ] LT-R-1 — 10,000 pre-seeded tokens · rotation completes with 0 live traffic errors · ≤20% throughput degradation · 0 tokens remain on old key after rotation
- [ ] LT-R-2 — All pre-rotation tokens detokenisable after rotation completes (parallelStream verification)
- [ ] LT-R-3 — Heap growth during rotation ≤ +512MB

### Tampered Key Under Load (`TamperedKeyUnderLoadTest`)

- [ ] LT-TA-1 — 5,000 pre-seeded tokens · DB-level key tamper committed mid-load · `KeyIntegrityException` thrown on next key read · `TAMPER_ALERT` audit event written within 1s of tamper
- [ ] LT-TA-2 — Zero successful detokenisations recorded after tamper was committed
- [ ] LT-TA-3 — System remains responsive to new requests after tamper isolation

**Load tests complete:** `[ ]` *(tick when all LT tasks are `[x]` and load test results archived)*

---

## Deviations from Plan

> Record here any time the implementation differs from PLAN.md.
> Future sessions need this context — don't skip it.

| Task | Plan Says | Actual Implementation | Reason |
|------|-----------|-----------------------|--------|
| — | — | — | — |

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

- **Current state:** Not started
- **Immediate next step:** P1-F1 — create Maven project structure
- **Context:** Fresh start, no code written yet. Begin with pom.xml and project skeleton before any feature work.
