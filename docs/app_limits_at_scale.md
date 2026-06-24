# Application Limits at Scale

This document covers memory, CPU, and rotation performance characteristics for the
card tokenisation system at 5–10 million `token_vault` rows, with sizing guidance for
a 3-pod OpenShift deployment.

---

## 1. What a TokenVault entity costs in heap

Every batch fetch during rotation materialises `batchSize` JPA entities into the JVM heap.
Each `TokenVault` entity carries:

| Field | Approximate heap size |
|---|---|
| `encryptedPan` (byte[]) | ~32 bytes + array header |
| `iv` (byte[12]) | 28 bytes |
| `authTag` (byte[16]) | 32 bytes |
| `encryptedDek` (byte[], DEK + IV + overhead) | ~64 bytes |
| `token` (String, UUID 36 chars) | ~92 bytes |
| `panHash` (String, 64 chars) | ~128 bytes |
| JPA object header + field references | ~136 bytes |
| Remaining fields (dates, lastFour, scheme, etc.) | ~100 bytes |
| **Total per entity** | **~700–1,000 bytes ≈ 1 KB** |

With the recommended production batch size of `rotation.batch.size=2000`:

- Batch list in heap: **~2 MB**
- 32 concurrent rotation threads (each holding a Hibernate session context + 3×32-byte
  key copies): **~3 MB additional**
- HMAC rotation (16 threads, with a momentary plaintext PAN copy of ~20 bytes): **no
  material difference**

The rotation batch window at any moment occupies **5–10 MB** of heap.  
This is not the memory driver — JVM non-heap overhead is.

---

## 2. JVM process memory (heap + non-heap)

The container RSS in production is `Xmx + ~500–600 MB` for non-heap components that live
outside the garbage-collected heap:

| Non-heap component | Approximate size |
|---|---|
| Spring Boot context (beans, proxies, reflection cache) | ~150 MB |
| HikariCP: 80 connections × ~300 KB native socket buffers | ~24 MB |
| Metaspace (JIT-compiled Spring / Hibernate class metadata) | ~120 MB |
| JIT code cache | ~80 MB |
| G1GC bookkeeping (card tables, remembered sets) | ~80 MB |
| NIO / native buffers | ~50 MB |
| **Non-heap total** | **~500 MB** |

With `-Xmx1g`, expect an RSS of approximately **1.4–1.6 GB** under rotation load.

OpenShift's OOMKiller fires when the container RSS exceeds the memory **limit**, not the heap.
The limit must cover the full RSS, not just `-Xmx`.

---

## 3. GC pressure during rotation

Rotation allocates and discards a fresh 2 MB batch every few seconds. G1GC handles this
well — the short-lived entities die in the young generation without triggering full GC.
However, the concurrent young-gen collections consume **15–20% of a CPU core** continuously
for the full duration of the rotation run.

Pause targets: `-XX:MaxGCPauseMillis=200` keeps individual GC pauses below 200 ms, which
is acceptable for background rotation. Live tokenisation/detokenisation latency is unaffected
because those requests run in Tomcat threads that are not involved in the rotation batch.

---

## 4. Rotation throughput at 5–10 million rows

### 4.1 KEK rotation (`RotationBatchProcessor`)

Per record: 2 in-memory AES-256-GCM operations (DEK unwrap + rewrap), 1 UPDATE to
`token_vault`, 1 INSERT to `token_audit_log`, 1 transaction commit. No KMS calls.

The bottleneck is **Postgres round-trip latency**, not crypto. AES-NI makes the cipher
operations negligible (~1–5 µs each).

| Config | Throughput | 5 M rows | 10 M rows |
|---|---|---|---|
| Default: size=500, parallelism=8 | ~800 rows/sec | ~1.7 hours | ~3.5 hours |
| Recommended: size=2000, parallelism=32 | ~3,200 rows/sec | ~26 min | ~52 min |

### 4.2 HMAC rotation (`PanHashBatchProcessor`)

Per record: AES-GCM DEK unwrap + AES-GCM PAN decrypt + HMAC-SHA256 compute + 1 UPDATE +
1 INSERT + commit. This is heavier than KEK rotation because the plaintext PAN must be
recovered to recompute the hash.

| Config | Throughput | 5 M rows | 10 M rows |
|---|---|---|---|
| Default: size=100, parallelism=4 | ~200 rows/sec | ~7 hours | ~14 hours |
| Recommended: size=500, parallelism=16 | ~800 rows/sec | ~1.7 hours | ~3.5 hours |

With default config, HMAC rotation of a 10 M-row vault at 02:00 would still be running
at 16:00 the next day — well past the daily cron window. Use the recommended values.

### 4.3 Recommended `application.yml` for production at this scale

```yaml
rotation:
  batch:
    size: 2000
    parallelism: 32
    max-batches-per-run: 0
  hmac-batch:
    size: 500
    parallelism: 16
    max-batches-per-run: 0

spring:
  datasource:
    hikari:
      maximum-pool-size: 80   # must exceed parallelism (32 or 16) + live-traffic headroom
```

---

## 5. Virtual thread pinning — critical flag for OpenShift

The PostgreSQL JDBC driver uses `synchronized` blocks for socket I/O. Virtual threads
entering a `synchronized` block are **pinned** to a carrier OS thread and cannot yield.
The ForkJoinPool backing virtual threads defaults to `availableProcessors()` carrier threads.

On a 2-core pod with `parallelism=32`:
- 32 virtual threads hit JDBC simultaneously and pin to carrier threads
- The pool has only 2 carrier threads
- At most 2 JDBC operations make progress at a time — effectively serialising the batch
  despite 32 declared parallel threads

**Set the following in `JAVA_OPTS`:**

```
-Djdk.virtualThreadScheduler.parallelism=64
-Djdk.virtualThreadScheduler.maxPoolSize=256
```

`parallelism=64` gives the scheduler enough carrier threads to run all 32 rotation threads
and ~32 concurrent Tomcat request threads simultaneously when they are pinned in JDBC.

This concern is documented in the Maven `pom.xml` (`load-tests` profile) where
`parallelism=256` is used for the highest-concurrency load test scenarios.

---

## 6. Per-pod OpenShift resource sizing

### JVM flags (`JAVA_OPTS` in Deployment env)

```
-Xms512m
-Xmx1g
-XX:+UseG1GC
-XX:MaxGCPauseMillis=200
-XX:+UseContainerSupport
-Djdk.virtualThreadScheduler.parallelism=64
-Djdk.virtualThreadScheduler.maxPoolSize=256
```

`-XX:+UseContainerSupport` is the default in JDK 17+ but should be explicit. It reads
cgroup memory limits from the container, preventing the JVM from treating the host's full
RAM as available.

### Resource block

```yaml
resources:
  requests:
    memory: "1Gi"    # guaranteed allocation — minimum for scheduling
    cpu: "500m"       # sufficient for steady-state live traffic
  limits:
    memory: "1750Mi" # Xmx=1g + ~750 MB JVM non-heap — prevents OOMKill under rotation
    cpu: "2000m"      # burst headroom for rotation GC and batch processing
```

---

## 7. What each pod does in a 3-pod deployment

ShedLock (V13 migration, `SchedulingConfig`) ensures exactly one pod runs the rotation
batch at a time. The other two pods serve live traffic and run `KeyRingRefreshJob` every
60 seconds.

| Pod | Role at rotation time | Memory (steady) | Memory (peak) | CPU |
|---|---|---|---|---|
| A — ShedLock winner | Live traffic + rotation batch | ~800 MB RSS | ~1.4 GB RSS | 0.8–1.5 cores |
| B, C — live only | Tokenise/detokenise + ring refresh | ~700 MB RSS | ~800 MB RSS | 0.25–0.5 cores |

Pods B and C are unaffected by rotation in terms of memory: `KeyRingRefreshJob` issues
2 DB reads per 60-second tick and performs at most 1–2 KMS calls if a new key was rotated
since the last tick.

### 3-pod cluster totals

| Resource | Per pod | 3 pods total |
|---|---|---|
| Memory limit | 1750 Mi | **5.25 Gi** |
| Memory request | 1 Gi | **3 Gi** |
| CPU limit | 2000 m | **6 cores** |
| CPU request | 500 m | **1.5 cores** |

---

## 8. Audit log write amplification

`RotationBatchProcessor.reencryptSingleToken()` writes one `TOKEN_REENCRYPTED` audit event
per migrated record. At 10 M rows this produces **10 M INSERTs into `token_audit_log`** per
KEK rotation cycle — approximately 3,200 inserts/sec for 52 minutes concurrent with vault
updates.

With annual rotation and a 7-year PCI DSS retention period, rotation alone contributes
**70 M rows** to the audit table. Combined with live-traffic audit events, the audit table
becomes the dominant source of Postgres storage consumption and vacuum overhead at this scale.

**Recommended fix:** remove the per-record `TOKEN_REENCRYPTED` event from
`RotationBatchProcessor.reencryptSingleToken()` and replace it with a migrated-record count
appended to the `KEY_ROTATION_COMPLETED` event in `RotationJob.completeRotation()`. The
`KEY_ROTATION_STARTED` and `KEY_ROTATION_COMPLETED` pair with a total count satisfies PCI
DSS audit trail requirements; individual DEK re-wraps do not require separate audit rows.

---

## 9. What the system is bounded by

| Bottleneck | Bound by | Not bound by |
|---|---|---|
| Rotation throughput | Postgres JDBC round-trip latency | AES-NI crypto (µs range) |
| Rotation memory | JVM non-heap (Metaspace, GC, buffers) | Batch size (5–10 MB window) |
| Rotation CPU | G1GC young-gen collections (~15–20% of a core) | AES-GCM or HMAC-SHA256 compute |
| Live tokenisation latency | Postgres write + HMAC compute | Key ring lookups (pure in-memory) |
| Live detokenisation latency | Postgres read | AES-GCM decrypt (µs), key ring (ns) |
| KMS calls | Startup only (1–2 per pod) | Per-request (0 KMS calls in hot paths) |

The 3-layer key hierarchy (`CMK → KEK → DEK`) is the reason KMS calls are absent from all
hot paths. Both rotation and detokenisation work entirely with in-memory key material after
startup.
