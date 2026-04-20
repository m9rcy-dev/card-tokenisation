# Feature 02 — Production-Scale Rotation, Gatling Load Tests, OpenShift Runbook

## Context

The existing rotation pipeline processes tokens **sequentially** (one at a time per cron tick).
At the default settings (batch=500, cron=15 min), rotating 1M tokens takes ~500 hours.
Two code changes fix this. Additionally, the test suite only covers up to 50K requests with
the custom JUnit5 framework; Gatling is added for sustained high-volume and 1M characterisation.
The deployment target is OpenShift, which needs a runbook. A progress tracker section is added
to avoid losing work across context resets.

---

## Part 1 — Code Changes

### 1.1 Add properties to `RotationProperties.Batch`

**File:** `src/main/java/com/yourorg/tokenisation/config/RotationProperties.java`

Add to the `Batch` inner class (after `emergencySize`):

```java
/** Number of parallel threads for DEK rewrap within a single batch. Default 8. */
private int parallelism = 8;

/** Max batches processed per cron invocation. 0 = unlimited (drain all). Default 0. */
private int maxBatchesPerRun = 0;
```

With the standard getter/setter pair for each field.

**application.yml** — add under `rotation.batch`:
```yaml
rotation:
  batch:
    cron: "0 */15 * * * *"
    size: 500
    emergency-size: 100
    parallelism: 8
    max-batches-per-run: 0
```

---

### 1.2 Parallel rewrap in `RotationBatchProcessor`

**File:** `src/main/java/com/yourorg/tokenisation/rotation/RotationBatchProcessor.java`

**Why:** The inner `for` loop processes one token at a time. Each `reencryptSingleToken` is
a `REQUIRES_NEW` transaction — they are independent and can run in parallel.

**Changes:**

1. **Add constructor parameter** `RotationProperties rotationProperties` (inject after `AuditLogger`).
2. **Add field** `private final ExecutorService rewrapExecutor;`
3. **In constructor** create the executor:
   ```java
   this.rewrapExecutor = Executors.newFixedThreadPool(
       rotationProperties.getBatch().getParallelism(),
       Thread.ofVirtual().name("rotation-rewrap-", 0).factory());
   ```
   Use virtual threads — they park on DB I/O, ideal here.
4. **Add `@PreDestroy`**:
   ```java
   @PreDestroy
   void shutdownExecutor() {
       rewrapExecutor.shutdown();
   }
   ```
5. **Replace the sequential `for` loop** in `processBatch()`:

```java
// Replace:
int processed = 0, failed = 0;
for (TokenVault vault : batch) {
    try {
        self.reencryptSingleToken(vault, ...);
        processed++;
    } catch (Exception e) { failed++; ... }
}

// With:
AtomicInteger processed = new AtomicInteger();
AtomicInteger failed    = new AtomicInteger();

List<CompletableFuture<Void>> futures = batch.stream()
    .map(vault -> CompletableFuture.runAsync(() -> {
        try {
            self.reencryptSingleToken(vault, oldKeyVersionId, newKeyVersionId, newKeyVersion);
            processed.incrementAndGet();
        } catch (Exception e) {
            failed.incrementAndGet();
            log.error("Re-encryption failed for token [{}]: {}",
                    vault.getTokenId(), e.getMessage(), e);
            auditLogger.logFailure(
                    AuditEventType.RE_ENCRYPTION_FAILURE,
                    vault.getTokenId(), null, null, null,
                    "Re-encryption failed: " + e.getClass().getSimpleName() + " — " + e.getMessage(),
                    null);
        }
    }, rewrapExecutor))
    .toList();

CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
```

Return `new BatchResult(processed.get(), failed.get(), batch.size())`.

**Note on proxy:** `self.reencryptSingleToken(...)` still goes through the Spring AOP proxy
even when called from a thread pool thread — the proxy is a field reference, not `this`.
Each parallel call gets its own `REQUIRES_NEW` transaction. This is correct.

**Note on `RotationBatchProcessor` constructor change:** The test
`RotationBatchProcessorTest` needs a new `RotationProperties` stub added:
```java
@Mock private RotationProperties rotationProperties;
// in setUp():
RotationProperties.Batch batchProps = new RotationProperties.Batch();
batchProps.setParallelism(1); // single-threaded in unit tests for determinism
when(rotationProperties.getBatch()).thenReturn(batchProps);
processor = new RotationBatchProcessor(
    tokenVaultRepository, keyVersionRepository, cipher, keyRing, auditLogger, rotationProperties);
```

---

### 1.3 Continuous batch loop in `RotationJob`

**File:** `src/main/java/com/yourorg/tokenisation/rotation/RotationJob.java`

**Why:** Currently `processRotationBatch()` calls `processBatch()` **once** then returns.
With 1M tokens and batch=500, this requires 2000 cron ticks = 500 hours.

**Change:** Replace the single `processBatch()` call with a loop. Extract to a private helper
`drainRotationBatches()` called from `processRotationBatch()`:

```java
private void drainRotationBatches(UUID oldKeyVersionId, UUID newKeyVersionId, int batchSize) {
    int maxBatches = rotationProperties.getBatch().getMaxBatchesPerRun();
    int batchNum = 0;
    while (true) {
        if (Thread.currentThread().isInterrupted()) {
            log.warn("Rotation drain interrupted after {} batch(es) on key [{}]",
                    batchNum, oldKeyVersionId);
            return;
        }
        RotationBatchProcessor.BatchResult result =
                batchProcessor.processBatch(oldKeyVersionId, newKeyVersionId, batchSize);
        batchNum++;
        log.info("Rotation batch {}: processed={}, failed={}, fetched={}",
                batchNum, result.processedCount(), result.failedCount(), result.totalFetched());

        if (result.totalFetched() == 0) break;   // nothing left to fetch
        if (maxBatches > 0 && batchNum >= maxBatches) {
            log.info("maxBatchesPerRun ({}) reached — will resume on next cron tick", maxBatches);
            break;
        }
    }
}
```

In `processRotationBatch()`, replace the single call:
```java
// Before:
RotationBatchProcessor.BatchResult result = batchProcessor.processBatch(...);
log.info("Rotation batch result: ...", result...);

// After:
drainRotationBatches(oldKeyVersionId, newKeyVersionId, batchSize);
```

Then the remaining count check and `completeRotation()` call stays unchanged:
```java
long remaining = tokenVaultRepository.countActiveByKeyVersionId(oldKeyVersionId);
if (remaining == 0) {
    completeRotation(rotatingKey);
} else {
    log.info("Rotation in progress: {} token(s) remaining on old key [{}]", remaining, oldKeyVersionId);
}
```

**Existing test impact:** `KeyRotationUnderLoadTest` already calls `processRotationBatch()`
in a manual loop (`while (count > 0) { rotationJob.processRotationBatch(); }`). With
`maxBatchesPerRun=0` (default), `processRotationBatch()` now drains everything in one call,
so that while-loop only iterates once. The assertions still pass — update `SEED_TOKEN_COUNT`
and loops in the test accordingly.

---

## Part 2 — New Test Infrastructure

### 2.1 `BulkTokenSeeder` — JDBC bulk insert for 100K+ rotation tests

**File:** `src/test/java/com/yourorg/tokenisation/loadtest/BulkTokenSeeder.java`

A Spring `@Component` (test-scope) that inserts valid encrypted `token_vault` rows via batched
JDBC — bypassing the HTTP API to handle 100K–1M records in seconds, not minutes.

```java
@Component
public class BulkTokenSeeder {

    private final JdbcTemplate jdbc;
    private final AesGcmCipher cipher;
    private final InMemoryKeyRing keyRing;
    private final PanHasher panHasher;

    // Constructor injection

    /**
     * Seeds count tokens under the current active key via JDBC batch insert.
     * Uses real AES-GCM encryption so records are detokenisable via the actual service.
     * @param count     number of token_vault rows to insert
     * @param chunkSize JDBC batch size (1000 is a good default)
     * @return array of token strings for verification
     */
    public String[] seedTokens(int count, String merchantId, int chunkSize) {
        KeyMaterial active = keyRing.getActive();
        byte[] kek = active.copyKek();
        String[] tokens = new String[count];
        try {
            List<Object[]> batch = new ArrayList<>(chunkSize);
            for (int i = 0; i < count; i++) {
                // Generate encrypted record
                String pan = PanGenerator.generateVisa16();
                byte[] dek = generateDek(); // SecureRandom 32 bytes
                byte[] wrappedDek = cipher.wrapDek(dek, kek);
                EncryptResult enc = cipher.encrypt(pan.getBytes(StandardCharsets.UTF_8), dek);
                Arrays.fill(dek, (byte) 0);
                String panHash = panHasher.hash(pan);
                String token = "tok-" + UUID.randomUUID();
                tokens[i] = token;
                batch.add(new Object[]{ UUID.randomUUID(), token, enc.ciphertext(),
                        enc.iv(), enc.authTag(), wrappedDek, active.keyVersionId(),
                        panHash, merchantId, "ONE_TIME", "VISA",
                        pan.substring(pan.length() - 4), 12, 2027,
                        Instant.now(), Instant.now().plusSeconds(5 * 365 * 86400L), true, 0 });
                if (batch.size() == chunkSize) {
                    jdbcBatchInsert(batch);
                    batch.clear();
                }
            }
            if (!batch.isEmpty()) jdbcBatchInsert(batch);
        } finally {
            Arrays.fill(kek, (byte) 0);
        }
        return tokens;
    }

    private void jdbcBatchInsert(List<Object[]> rows) {
        jdbc.batchUpdate("""
            INSERT INTO token_vault (token_id, token, encrypted_pan, iv, auth_tag,
                encrypted_dek, key_version_id, pan_hash, merchant_id, token_type,
                card_scheme, last_four, expiry_month, expiry_year,
                created_at, expires_at, is_active, record_version)
            VALUES (?,?,?,?,?,?,?::uuid,?,?,?,?,?,?,?,?,?,?,?)
            """, rows);
    }
}
```

---

### 2.2 `KeyRotationUnderLoadTest` — add 100K rotation scenario (LT-R-4)

**File:** `src/test/java/com/yourorg/tokenisation/loadtest/KeyRotationUnderLoadTest.java`

Add `@Autowired BulkTokenSeeder bulkSeeder;` field.

Add new test method:

```java
/**
 * LT-R-4: 100,000 pre-seeded tokens — full rotation completes.
 * Seeds via JDBC bulk insert (not HTTP). Asserts 0 tokens on old key after rotation.
 * Heap growth ≤ 512MB. Only runs with -Pscale=100k.
 */
@Test
void rotation_100k_tokens_allMigratedToNewKey() {
    String[] tokens = bulkSeeder.seedTokens(100_000, MERCHANT, 1000);
    long heapBefore = captureHeapMb();
    UUID oldKeyId = UUID.fromString(SEED_KEY_VERSION_ID);

    keyRotationService.initiateScheduledRotation("load-test-key-v2", RotationReason.SCHEDULED);
    long start = System.currentTimeMillis();
    rotationJob.processRotationBatch(); // drains all batches in one call with continuous loop
    long durationMs = System.currentTimeMillis() - start;

    long remaining = tokenVaultRepository.countActiveByKeyVersionId(oldKeyId);
    long heapGrowth = captureHeapMb() - heapBefore;

    new LoadTestResult("LT-R-4", 100_000, rotationProperties.getBatch().getParallelism(),
            durationMs, 0, 0, 0, 0, 0L, heapGrowth, Instant.now()).writeToFile();

    assertThat(remaining).as("LT-R-4: 0 tokens remain on old key").isZero();
    assertThat(heapGrowth).as("LT-R-4: heap growth ≤ 512MB").isLessThanOrEqualTo(512L);
}
```

Add scale filter to Maven/Gradle so `SCALE=100k` triggers this test.
In `pom.xml` load-tests profile, add:
```xml
<groups>load</groups>
```
(unchanged — the filter is method-name based via `-Dtest=*100k*`).

In `build.gradle.kts` loadTest task, the `-Pscale=100k` filter already works via:
```kotlin
filter { includeTestsMatching("*LoadTest.*100000requests*") }
```
Rename the method to `rotation_100000records_allMigratedToNewKey()` for filter consistency.

---

## Part 3 — Gatling Load Tests

### 3.1 Dependencies and plugin

**File:** `pom.xml` — add a new `gatling-tests` Maven profile:

```xml
<profile>
  <id>gatling-tests</id>
  <dependencies>
    <dependency>
      <groupId>io.gatling.highcharts</groupId>
      <artifactId>gatling-charts-highcharts</artifactId>
      <version>3.10.5</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
  <build>
    <plugins>
      <plugin>
        <groupId>io.gatling</groupId>
        <artifactId>gatling-maven-plugin</artifactId>
        <version>4.9.6</version>
        <configuration>
          <simulationsFolder>src/gatling/java</simulationsFolder>
          <resultsFolder>target/gatling</resultsFolder>
        </configuration>
        <executions>
          <execution>
            <goals><goal>test</goal></goals>
          </execution>
        </executions>
      </plugin>
    </plugins>
  </build>
</profile>
```

**build.gradle.kts** — add Gatling task alongside existing `loadTest`:
```kotlin
tasks.register<JavaExec>("gatlingTest") {
    description = "Run Gatling simulations. Use -PsimClass=... -PbaseUrl=... -Pusers=... -PtotalRequests=..."
    group = "verification"
    // Gatling main class drives simulation execution
    mainClass.set("io.gatling.app.Gatling")
    classpath = sourceSets["test"].runtimeClasspath
    jvmArgs("-Xmx2g")
    args = listOf(
        "-s", project.findProperty("simClass")?.toString() ?: "com.yourorg.tokenisation.TokenisationSimulation",
        "-rd", "target/gatling"
    )
}
```

**Makefile** — add:
```makefile
GATLING_BASE_URL ?= http://localhost:8080
GATLING_SIM     ?= com.yourorg.tokenisation.TokenisationSimulation
GATLING_SCALE   ?= 20k

## gatling-test [GATLING_SCALE=20k|50k|100k|1m] [GATLING_SIM=...]: run Gatling simulation against running app
gatling-test: ## requires: make start (app must be running)
	$(MVN) gatling:test -P gatling-tests \
	  -DbaseUrl=$(GATLING_BASE_URL) \
	  -DtotalRequests=$(subst k,000,$(GATLING_SCALE)) \
	  -DsimulationClass=$(GATLING_SIM)
```

---

### 3.2 Simulation structure

**Directory:** `src/gatling/java/com/yourorg/tokenisation/`

**Files to create:**

| File | Purpose |
|------|---------|
| `TokenisationSimulation.java` | POST /api/v1/tokens at scale |
| `DetokenisationSimulation.java` | GET /api/v1/tokens/{token} at scale |
| `RotationSimulation.java` | Rotation under concurrent tokenisation |
| `SimulationConfig.java` | Shared config (baseUrl, auth, scales) |
| `DbSetupHelper.java` | JDBC truncate/seed for before() hooks |

**TokenisationSimulation.java** scaffold:
```java
public class TokenisationSimulation extends Simulation {
    private final String baseUrl = System.getProperty("baseUrl", "http://localhost:8080");
    private final int totalRequests = Integer.parseInt(System.getProperty("totalRequests", "20000"));
    private final int rampSeconds = 30;
    private final int sustainSeconds = 60;
    private final int maxUsers = 20;

    private final HttpProtocolBuilder protocol = http
        .baseUrl(baseUrl)
        .acceptHeader("application/json")
        .contentTypeHeader("application/json");

    private final ScenarioBuilder tokenise = scenario("Tokenise")
        .exec(http("POST /api/v1/tokens")
            .post("/api/v1/tokens")
            .body(StringBody(session -> buildPanRequestJson()))
            .check(status().is(201))
            .check(jsonPath("$.token").saveAs("token")));

    { setUp(
        tokenise.injectOpen(
            rampUsers(maxUsers).during(rampSeconds),
            constantUsersPerSec((double) maxUsers / 2).during(sustainSeconds)
        ).throttle(reachRps(totalRequests / sustainSeconds).in(rampSeconds),
                   holdFor(sustainSeconds))
      ).protocols(protocol);
    }

    @Override
    public void before() {
        DbSetupHelper.truncate(); // JDBC clean slate
    }
}
```

Scales 20k / 50k / 100k / 1M are all driven by `-DtotalRequests=N` — same simulation class.

**RotationSimulation.java** scaffold:
- `before()`: seeds N tokens via `DbSetupHelper.seedTokens(N)` (direct JDBC + cipher calls)
- Concurrent scenario: 15 workers tokenise, 5 workers detokenise
- `setUp()`: halfway through, trigger rotation via `POST /api/v1/admin/keys/rotate`
- Assert: zero 5xx during rotation window

**DbSetupHelper.java** (standalone, no Spring context):
```java
public class DbSetupHelper {
    private static final String DB_URL  = System.getProperty("dbUrl",  "jdbc:postgresql://localhost:5432/tokenisation");
    private static final String DB_USER = System.getProperty("dbUser", "tokenisation_app");
    private static final String DB_PASS = System.getProperty("dbPass", "change_me");

    public static void truncate() {
        try (Connection c = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
             Statement s = c.createStatement()) {
            s.execute("DELETE FROM token_vault");
            s.execute("DELETE FROM token_audit_log");
        } catch (SQLException e) { throw new RuntimeException(e); }
    }
    // seedTokens() for rotation simulation — generates raw encrypted rows via direct crypto
}
```

---

### 3.3 Clean-database guarantee for all Gatling simulations

Every simulation class calls `DbSetupHelper.truncate()` in `before()`.
This is explicit and unconditional — no shared state between simulation runs.

---

## Part 4 — Recommended Settings for 1M

Document in `docs/feature-02.md` §4 (Settings Reference table):

### Throughput maths

With `parallelism=16`, `batchSize=1000`:
- DEK rewrap (pure in-memory AES-GCM): ~5 μs/record
- DB save (token_vault UPDATE + audit INSERT, async commit): ~5 ms/record
- Parallel throughput: 16 / 5ms = **3,200 records/second**
- 1M records: **~5 minutes**

Compare to original sequential 500-batch/15-min cron: **~500 hours**.

### Recommended production settings

| Property | Default | 1M-scale value | Notes |
|----------|---------|----------------|-------|
| `rotation.batch.size` | 500 | 1000 | Fewer round-trips; keep ≤ Hikari pool size × 2 |
| `rotation.batch.parallelism` | 8 | 16 | Must be ≤ `hikari.maximum-pool-size − 5` |
| `rotation.batch.max-batches-per-run` | 0 | 0 | Drain everything in one run |
| `spring.datasource.hikari.maximum-pool-size` | (not set) | 40 | Per pod; parallelism + buffer |
| `spring.datasource.hikari.minimum-idle` | (not set) | 10 | Warm connections pre-rotation |
| JVM `-Xmx` | 1g (test) | 4g (rotation pod) | Holds 1k-record batch in memory |
| `jdk.virtualThreadScheduler.parallelism` | default | 256 | JVM arg for rotation pod |
| PostgreSQL `synchronous_commit` | on | off (load only) | Safe with retries; skip for compliance |
| PostgreSQL `max_connections` | 100 | 300 | Matches multi-pod Hikari pools |
| Rotation pod count | 1 | 1 (+ ShedLock) | Only 1 pod should run rotation at a time |
| Traffic pod count | — | 3–5 | See OpenShift runbook |

---

## Part 5 — OpenShift Deployment Runbook

**File to create:** `docs/openshift-runbook.md`

### Sections outline

**§1 Capacity model**
- 1M requests/day = 11.6 TPS average; assume 20× peak = 232 TPS
- Per-pod throughput at p50=50ms, 20 concurrent = 400 TPS theoretical; realistic 150–200 TPS
- Pod count: **3 pods** baseline for HA; **5 pods** at peak with HPA

**§2 Deployment YAML**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: card-tokenisation
  namespace: payments
spec:
  replicas: 3
  selector:
    matchLabels:
      app: card-tokenisation
  template:
    spec:
      containers:
      - name: app
        image: registry.internal/card-tokenisation:latest
        ports:
        - containerPort: 8080
        resources:
          requests: { cpu: "500m", memory: "1Gi" }
          limits:   { cpu: "2000m", memory: "2Gi" }
        readinessProbe:
          httpGet: { path: /actuator/health/readiness, port: 8080 }
          initialDelaySeconds: 30
          periodSeconds: 10
          failureThreshold: 3
        livenessProbe:
          httpGet: { path: /actuator/health/liveness, port: 8080 }
          initialDelaySeconds: 60
          periodSeconds: 30
        env:
        - name: JAVA_TOOL_OPTIONS
          value: "-Xmx1536m -Djdk.virtualThreadScheduler.parallelism=256"
        envFrom:
        - secretRef:  { name: card-tokenisation-secrets }
        - configMapRef: { name: card-tokenisation-config }
```

**§3 Rotation pod (separate Deployment)**
- Label: `role: rotation-worker`; `replicas: 1`
- Larger memory: limit 4Gi
- ShedLock configured (via DB or Redis) to ensure only 1 pod runs rotation
- Rotation cron still fires on all pods but only 1 holds the lock
- JVM args: `-Xmx3g -Djdk.virtualThreadScheduler.parallelism=256 -Djdk.virtualThreadScheduler.maxPoolSize=512`

**§4 OpenShift Route (HAProxy)**
```yaml
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  name: card-tokenisation
  annotations:
    haproxy.router.openshift.io/timeout: 60s
    haproxy.router.openshift.io/balance: leastconn
    haproxy.router.openshift.io/disable_cookies: "true"
spec:
  to:
    kind: Service
    name: card-tokenisation
  port:
    targetPort: 8080
  tls:
    termination: edge             # or passthrough for mTLS
    insecureEdgeTerminationPolicy: Redirect
```

HAProxy ingress settings:
- `timeout`: 60s (covers long rotation requests on admin endpoint)
- `balance: leastconn`: routes to least-loaded pod (better than round-robin for variable latency)
- `disable_cookies`: prevents session affinity (stateless app, cookies add overhead)

**§5 HorizontalPodAutoscaler**
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: card-tokenisation
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: card-tokenisation
  minReplicas: 3
  maxReplicas: 5
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

**§6 PodDisruptionBudget**
```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
spec:
  minAvailable: 2          # never take cluster below 2 pods during rolling update
  selector:
    matchLabels:
      app: card-tokenisation
```

**§7 ConfigMap and Secrets**
- ConfigMap: non-sensitive config (`rotation.batch.*`, `detokenisation.rate-limit.*`)
- Secret: `DATASOURCE_PASSWORD`, `KMS_LOCAL_DEV_KEK_HEX`, `PAN_HASH_SECRET`, `TAMPER_DETECTION_SECRET`

**§8 PostgreSQL options**
- Option A: External AWS RDS PostgreSQL (preferred — managed, Multi-AZ)
- Option B: Crunchy Postgres Operator for OpenShift
- Either way: `max_connections=300`, `synchronous_commit=off` for rotation, autovacuum tuned

**§9 Pod sizing cheat-sheet**

| Scenario | Pods | CPU req | Mem req | Notes |
|----------|------|---------|---------|-------|
| Dev/staging | 1 | 250m | 512Mi | |
| Production baseline | 3 | 500m | 1Gi | HA + failover |
| 1M rotation window | 3 traffic + 1 rotation | 500m / 2 | 1Gi / 4Gi | Rotation pod separate |
| Peak 1M req/day | 5 | 500m | 1Gi | HPA triggered |

---

## Part 6 — progress.md Update

**File:** `docs/progress.md`

Append a new `## Feature 02` section at the end tracking all tasks from this feature.
Tasks format matching existing style. Each task is `[ ]` until code + tests + docs complete.

Tasks to track:
- F2-1: RotationProperties — add `parallelism` + `maxBatchesPerRun`
- F2-2: RotationBatchProcessor — parallel rewrap (ExecutorService)
- F2-3: RotationJob — continuous batch loop (drainRotationBatches)
- F2-4: RotationBatchProcessorTest — update for new constructor
- F2-5: BulkTokenSeeder — JDBC bulk seeder utility
- F2-6: KeyRotationUnderLoadTest LT-R-4 — 100K rotation scenario
- F2-7: Gatling deps + plugin in pom.xml (gatling-tests profile)
- F2-8: Gatling Makefile target
- F2-9: TokenisationSimulation.java
- F2-10: DetokenisationSimulation.java
- F2-11: RotationSimulation.java
- F2-12: DbSetupHelper.java
- F2-13: docs/feature-02.md — full feature doc
- F2-14: docs/openshift-runbook.md
- F2-15: docs/progress.md updated

---

## Part 7 — docs/feature-02-summary.md Content

The actual `docs/feature-02-summary.md` feature document to create. Sections:

1. **Overview** — what this feature does and why (rotation capacity, 1M scale, OpenShift)
2. **Code changes** — RotationBatchProcessor + RotationJob summary with config knobs
3. **Load testing** — JUnit5 100K rotation test (LT-R-4), Gatling simulations table
4. **Recommended settings for 1M** — the table from Part 4 above
5. **OpenShift deployment** — summary + link to `docs/openshift-runbook.md`
6. **Verification checklist** — how to run all pieces end-to-end

---

## Critical Files to Modify

| File | Change type |
|------|-------------|
| `src/main/java/.../config/RotationProperties.java` | Add `parallelism`, `maxBatchesPerRun` to `Batch` |
| `src/main/resources/application.yml` | Add `parallelism: 8`, `max-batches-per-run: 0` |
| `src/main/java/.../rotation/RotationBatchProcessor.java` | Add executor, parallel loop, `@PreDestroy` |
| `src/main/java/.../rotation/RotationJob.java` | Add `drainRotationBatches()`, loop replaces single call |
| `src/test/java/.../rotation/RotationBatchProcessorTest.java` | Add `RotationProperties` mock to constructor |
| `pom.xml` | Add `gatling-tests` profile with Gatling plugin + dependency |
| `build.gradle.kts` | Add `gatlingTest` task |
| `Makefile` | Add `gatling-test` target |

## New Files to Create

| File | Purpose |
|------|---------|
| `src/test/java/.../loadtest/BulkTokenSeeder.java` | JDBC bulk seeder for 100K+ tests |
| `src/gatling/java/.../TokenisationSimulation.java` | Gatling tokenisation at scale |
| `src/gatling/java/.../DetokenisationSimulation.java` | Gatling detokenisation at scale |
| `src/gatling/java/.../RotationSimulation.java` | Gatling rotation under load |
| `src/gatling/java/.../DbSetupHelper.java` | JDBC truncate/seed for Gatling before() |
| `src/gatling/java/.../SimulationConfig.java` | Shared Gatling config (baseUrl, credentials) |
| `docs/feature-02.md` | Full feature specification and settings reference |
| `docs/openshift-runbook.md` | OpenShift deployment runbook |

---

## Verification Steps

1. **Unit test:** `mvn test -Dtest="RotationBatchProcessorTest"` — all 9 tests pass with new constructor
2. **Compile check:** `mvn compile -q` + `mvn test-compile -q` — no errors
3. **Rotation integration test:** `mvn test -Dtest="ScheduledRotationIntegrationTest"` — still passes
4. **100K rotation CI test:** `mvn test -P load-tests -Dtest="*100000*"` — completes, 0 tokens on old key
5. **Gatling tokenisation 20K:** `make start && make gatling-test GATLING_SCALE=20k` — Gatling report in `target/gatling/`
6. **Gatling 1M (local):** `make start && make gatling-test GATLING_SCALE=1m GATLING_SIM=...TokenisationSimulation`
7. **Full load test suite:** `make load-test` — all existing LT-T/D/M/R/TA tests pass
8. **Full standard suite:** `mvn test` — zero failures

---

## Implementation Order

1. RotationProperties (F2-1) — no deps
2. RotationBatchProcessor parallel (F2-2) — depends on F2-1
3. RotationJob continuous loop (F2-3) — depends on RotationBatchProcessor compiling
4. RotationBatchProcessorTest update (F2-4) — depends on F2-2
5. BulkTokenSeeder (F2-5) — independent
6. KeyRotationUnderLoadTest LT-R-4 (F2-6) — depends on F2-3 + F2-5
7. Gatling infra (F2-7 to F2-12) — independent of code changes
8. Documentation (F2-13 to F2-15) — last, once code is verified
