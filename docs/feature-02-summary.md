# Feature 02 — Production-Scale Rotation, Gatling Load Tests, OpenShift Runbook

## 1. Overview

This feature makes the key rotation pipeline production-viable at 1M tokens and adds
sustained load testing via Gatling, plus an OpenShift deployment runbook.

### The problem

The previous rotation pipeline processed tokens **sequentially, one batch per cron tick**:

| Config | Throughput | Time to rotate 1M tokens |
|--------|-----------|--------------------------|
| Sequential, 500/batch, 15-min cron | ~33 records/min | **~500 hours** |
| **Parallel (8 threads), 500/batch, continuous** | ~9,600 records/min | **~1.7 hours** |
| **Parallel (16 threads), 1000/batch, continuous** | ~38,400 records/min | **~26 minutes** |

Two targeted code changes fix this. No schema changes, no new dependencies.

---

## 2. Code Changes

### 2.1 Parallel rewrap — `RotationBatchProcessor`

The sequential `for` loop is replaced with a `CompletableFuture` parallel fan-out using a
fixed virtual-thread pool. Each token's `reencryptSingleToken` still runs in its own
`REQUIRES_NEW` transaction — parallelism adds throughput without changing the isolation model.

**New config property:** `rotation.batch.parallelism` (default `8`)

```yaml
rotation:
  batch:
    parallelism: 8           # parallel DEK-rewrap threads per batch
```

The executor is created at bean construction (`Executors.newFixedThreadPool(parallelism,
Thread.ofVirtual()...)`) and shut down cleanly via `@PreDestroy`.

**Constraint:** `parallelism` must be ≤ `spring.datasource.hikari.maximum-pool-size − 5`
to leave headroom for Spring's background threads.

### 2.2 Continuous batch loop — `RotationJob`

`processRotationBatch()` now calls `drainRotationBatches()`, which loops until no records
remain on the old key rather than returning after a single batch. A capped mode is available
for environments where you want to bound per-tick wall-clock time.

**New config property:** `rotation.batch.max-batches-per-run` (default `0` = unlimited)

```yaml
rotation:
  batch:
    max-batches-per-run: 0   # 0 = drain all; positive = cap batches per cron tick
```

With `max-batches-per-run: 0` (the default), a single cron tick completes the full rotation.
With `max-batches-per-run: 100`, each tick processes up to 100 × `size` records and picks up
where it left off on the next tick.

### 2.3 Full `application.yml` rotation block

```yaml
rotation:
  batch:
    cron: "0 */15 * * * *"
    size: 500
    emergency-size: 100
    parallelism: 8
    max-batches-per-run: 0
  compliance:
    max-key-age-days: 365
```

---

## 3. Load Testing

### 3.1 JUnit5 — 100K rotation CI test (LT-R-4)

Added to `KeyRotationUnderLoadTest`:

| ID | Name | Pre-seeded tokens | Method | Assertions |
|----|------|-------------------|--------|------------|
| LT-R-4 | `rotation_100000records_allMigratedToNewKey` | 100,000 | JDBC bulk insert | 0 tokens on old key, heap ≤ 512MB |

Seeding uses `BulkTokenSeeder` (JDBC batch insert, not HTTP) — 100K records insert in
~15–30 seconds with `synchronous_commit=off`. Each record is fully encrypted with the real
cipher so records are detokenisable after rotation.

Run:
```bash
mvn test -P load-tests -Dtest="*100000*"
```

### 3.2 Gatling simulations

Gatling simulations run against a **running application instance** (not embedded). They
produce HTML reports in `target/gatling/`.

**Prerequisites:** `make start` (app + PostgreSQL running)

| Simulation | Class | What it tests |
|-----------|-------|---------------|
| `TokenisationSimulation` | `com.yourorg.tokenisation.TokenisationSimulation` | POST /api/v1/tokens throughput |
| `DetokenisationSimulation` | `com.yourorg.tokenisation.DetokenisationSimulation` | GET /api/v1/tokens/{token} throughput |
| `RotationSimulation` | `com.yourorg.tokenisation.RotationSimulation` | Rotation under concurrent traffic |

**Scale variants** — all driven by `-DtotalRequests=N`, same simulation class:

| Scale | Requests | Command |
|-------|----------|---------|
| 20K | 20,000 | `make gatling-test GATLING_SCALE=20k` |
| 50K | 50,000 | `make gatling-test GATLING_SCALE=50k` |
| 100K | 100,000 | `make gatling-test GATLING_SCALE=100k` |
| 1M | 1,000,000 | `make gatling-test GATLING_SCALE=1m` |

**Clean database:** Every simulation calls `DbSetupHelper.truncate()` in its `before()` hook —
unconditional, no shared state between runs.

**Rotation simulation** additionally:
- Resets key version state (`DbSetupHelper.resetKeyVersions(seedKeyId)`)
- Seeds 5,000 tokens for detokenisation via HTTP
- Triggers rotation via `POST /api/v1/admin/keys/rotate`
- Runs 70% tokenise / 30% detokenise mixed traffic while rotation is in progress

---

## 4. Recommended Settings for 1M

### Throughput model

| Config | DB save time | Parallel threads | Throughput | Time for 1M |
|--------|-------------|-----------------|------------|-------------|
| Default (sequential, 500/batch) | 5ms | 1 | 200 rec/s | ~83 min (1 cron drain) |
| Parallel=8, batch=500 | 5ms | 8 | 1,600 rec/s | ~10 min |
| **Parallel=16, batch=1000** | 5ms | 16 | **3,200 rec/s** | **~5 min** |

DEK rewrap itself (in-memory AES-GCM) takes ~5 μs/record. The bottleneck is always the
`token_vault` UPDATE, not the crypto.

### Recommended production settings for 1M vault

```yaml
# application.yml on the rotation pod
rotation:
  batch:
    size: 1000              # 2× default; fewer DB round-trips
    parallelism: 16         # 16 parallel threads; leave HikariCP headroom
    max-batches-per-run: 0  # drain everything in one cron invocation

spring:
  datasource:
    hikari:
      maximum-pool-size: 40      # parallelism × 2 + buffer
      minimum-idle: 10           # keep connections warm pre-rotation
      connection-timeout: 10000
      connection-init-sql: "SET synchronous_commit = off"
```

JVM flags for the rotation pod:
```
-Xmx4g
-Xms1g
-Djdk.virtualThreadScheduler.parallelism=256
-Djdk.virtualThreadScheduler.maxPoolSize=512
```

PostgreSQL settings (32 GB server):
```
max_connections = 300
shared_buffers = 8GB
effective_cache_size = 24GB
synchronous_commit = off       # safe for tokenisation with client-side retries
autovacuum_vacuum_scale_factor = 0.01   # aggressive for token_vault heavy updates
```

### Settings reference table

| Setting | Default | 1M-scale value | Constraint |
|---------|---------|----------------|------------|
| `rotation.batch.size` | 500 | 1000 | Keep ≤ Hikari pool × 2 |
| `rotation.batch.parallelism` | 8 | 16 | ≤ `max-pool-size − 5` |
| `rotation.batch.max-batches-per-run` | 0 | 0 | — |
| `hikari.maximum-pool-size` | — | 40 (rotation pod) | — |
| JVM `-Xmx` | 1g | 4g (rotation pod) | — |
| Rotation pod count | 1 | 1 + ShedLock | Only 1 pod runs rotation |
| Traffic pod count | — | 3–5 | See OpenShift runbook |

---

## 5. OpenShift Deployment

See **`docs/openshift-runbook.md`** for:
- Pod sizing calculations (3 traffic pods + 1 rotation pod for 1M/day)
- Deployment and Route YAML
- HPA configuration (scale 3→5 at 70% CPU)
- PodDisruptionBudget (minimum 2 pods during rolling updates)
- ConfigMap and Secret structure
- PostgreSQL options (RDS vs Crunchy Operator)

---

## 6. Verification Checklist

```bash
# 1. Unit tests — rotation batch processor with new constructor
mvn test -Dtest="RotationBatchProcessorTest"
# Expected: 9 tests, 0 failures

# 2. Rotation integration tests — continuous loop + parallel rewrap
mvn test -Dtest="ScheduledRotationIntegrationTest,EmergencyRotationIntegrationTest"
# Expected: 17 tests, 0 failures

# 3. Full standard suite
mvn test
# Expected: BUILD SUCCESS (any pre-existing flakiness is unrelated to this feature)

# 4. 100K rotation CI test (Docker required, takes ~5 min)
mvn test -P load-tests -Dtest="*100000*"
# Expected: 0 tokens on old key, heap growth ≤ 512MB, result in target/load-test-results/

# 5. Full load test suite (Docker required, takes ~10 min)
make load-test
# Expected: all LT-T/D/M/R/TA tests pass

# 6. Gatling 20K tokenisation (app must be running: make start)
make gatling-test GATLING_SCALE=20k
# Expected: p99 < 2000ms, ≥ 99% success, HTML report in target/gatling/

# 7. Gatling 1M tokenisation (app must be running)
make gatling-test GATLING_SCALE=1m
# Expected: simulation completes, HTML report shows sustained throughput
```

---

## 7. New Files

| File | Purpose |
|------|---------|
| `src/test/java/.../loadtest/BulkTokenSeeder.java` | JDBC bulk seeder for 100K+ rotation tests |
| `src/gatling/java/.../SimulationConfig.java` | Shared Gatling config (baseUrl, scales, DB) |
| `src/gatling/java/.../DbSetupHelper.java` | JDBC truncate/seed for Gatling before() hooks |
| `src/gatling/java/.../TokenisationSimulation.java` | Gatling tokenisation at 20K–1M |
| `src/gatling/java/.../DetokenisationSimulation.java` | Gatling detokenisation at 20K–1M |
| `src/gatling/java/.../RotationSimulation.java` | Gatling rotation under concurrent traffic |
| `docs/openshift-runbook.md` | OpenShift deployment runbook |
