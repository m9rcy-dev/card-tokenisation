# OpenShift Deployment Runbook — Card Tokenisation System

This runbook covers deploying the card tokenisation system to OpenShift at 1M tokens/day
scale: capacity modelling, Deployment YAMLs, Route configuration, autoscaling, pod
disruption budgets, ConfigMap/Secret layout, and PostgreSQL options.

---

## Table of Contents

1. [Capacity Model](#1-capacity-model)
2. [Architecture Overview](#2-architecture-overview)
3. [Traffic Pod Deployment](#3-traffic-pod-deployment)
4. [Rotation Pod Deployment](#4-rotation-pod-deployment)
5. [OpenShift Route (HAProxy Ingress)](#5-openshift-route-haproxy-ingress)
6. [HorizontalPodAutoscaler](#6-horizontalpodautoscaler)
7. [PodDisruptionBudget](#7-poddisruptionbudget)
8. [ConfigMap and Secret Layout](#8-configmap-and-secret-layout)
9. [PostgreSQL Options](#9-postgresql-options)
10. [Pod Sizing Cheat-Sheet](#10-pod-sizing-cheat-sheet)
11. [Deployment Checklist](#11-deployment-checklist)
12. [Rollback Procedure](#12-rollback-procedure)

---

## 1. Capacity Model

### 1.1 Traffic baseline

| Metric | Value | Derivation |
|--------|-------|-----------|
| Daily volume | 1,000,000 requests | requirement |
| Average TPS | 11.6 | 1M / 86,400s |
| Peak multiplier | 20× | typical payment peak |
| Peak TPS | 232 | 11.6 × 20 |
| Per-pod throughput (realistic) | 150–200 TPS | p50=50ms, 20 workers, ~70% efficiency |
| Pods required at peak | 3 | ceil(232 / 180) = 2 → 3 for HA |
| HPA scale-out ceiling | 5 | covers 5× normal peak |

### 1.2 Rotation window

| Config | Throughput | Time for 1M |
|--------|-----------|-------------|
| Sequential 500/batch, 1 cron tick | 200 rec/s | ~83 min |
| **Parallel=16, batch=1000** | **3,200 rec/s** | **~5 min** |

A single dedicated rotation pod with `parallelism=16` completes a full 1M re-encryption in
~5 minutes. The rotation pod runs independently — traffic pods are unaffected.

### 1.3 Database connection budget

| Component | Hikari pool | Peak connections |
|-----------|-------------|-----------------|
| Traffic pod (×3) | 20 | 60 |
| Traffic pod HPA (×5) | 20 | 100 |
| Rotation pod (×1) | 40 | 40 |
| Spring background threads | 5 per pod | 30 (5 pods) |
| **Total worst case** | | **170** |
| PostgreSQL `max_connections` | 300 | safe headroom ✓ |

---

## 2. Architecture Overview

```
                    ┌─────────────────────────────────────┐
                    │          OpenShift Router             │
                    │   (HAProxy, Route: card-tokenisation) │
                    └──────────────┬──────────────────────┘
                                   │ HTTPS (edge TLS termination)
                    ┌──────────────▼──────────────────────┐
                    │        card-tokenisation Service      │
                    │           (ClusterIP :8080)           │
                    └────┬──────────┬──────────┬───────────┘
                         │          │          │
               ┌─────────▼──┐  ┌───▼────┐  ┌─▼────────┐
               │ traffic-pod │  │traffic │  │ traffic  │
               │   replica 1 │  │replica │  │ replica  │
               │    (1Gi)    │  │  (1Gi) │  │  (1Gi)   │
               └─────────────┘  └────────┘  └──────────┘
                                                  ▲
               ┌────────────────────┐             │ HPA: scale 3→5
               │  rotation-worker   │             │ at 70% CPU
               │  (1 replica, 4Gi) │
               │  ShedLock on DB   │
               └─────────┬──────────┘
                          │
               ┌──────────▼──────────────────────────────┐
               │              PostgreSQL                   │
               │  (RDS Multi-AZ or Crunchy Operator)       │
               │  max_connections=300, synchronous_commit  │
               │  =off during rotation window              │
               └──────────────────────────────────────────┘
```

---

## 3. Traffic Pod Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: card-tokenisation
  namespace: payments
  labels:
    app: card-tokenisation
    role: traffic-worker
spec:
  replicas: 3
  selector:
    matchLabels:
      app: card-tokenisation
      role: traffic-worker
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0        # never drop below 3 during rollout
  template:
    metadata:
      labels:
        app: card-tokenisation
        role: traffic-worker
    spec:
      terminationGracePeriodSeconds: 60
      containers:
        - name: app
          image: registry.internal/card-tokenisation:latest
          imagePullPolicy: Always
          ports:
            - containerPort: 8080
              name: http
          resources:
            requests:
              cpu: "500m"
              memory: "1Gi"
            limits:
              cpu: "2000m"
              memory: "2Gi"
          env:
            - name: JAVA_TOOL_OPTIONS
              value: >-
                -Xmx1536m
                -Xms512m
                -Djdk.virtualThreadScheduler.parallelism=256
                -Djdk.virtualThreadScheduler.maxPoolSize=512
                -XX:+UseZGC
          envFrom:
            - secretRef:
                name: card-tokenisation-secrets
            - configMapRef:
                name: card-tokenisation-config
          readinessProbe:
            httpGet:
              path: /actuator/health/readiness
              port: 8080
            initialDelaySeconds: 30
            periodSeconds: 10
            failureThreshold: 3
            successThreshold: 1
          livenessProbe:
            httpGet:
              path: /actuator/health/liveness
              port: 8080
            initialDelaySeconds: 60
            periodSeconds: 30
            failureThreshold: 3
          lifecycle:
            preStop:
              exec:
                # Give HAProxy time to drain in-flight connections before the
                # container exits. HAProxy removes the pod from rotation
                # ~2s after the endpoint is removed; 10s is safe.
                command: ["sh", "-c", "sleep 10"]
```

**Service:**

```yaml
apiVersion: v1
kind: Service
metadata:
  name: card-tokenisation
  namespace: payments
spec:
  selector:
    app: card-tokenisation
    role: traffic-worker
  ports:
    - port: 80
      targetPort: 8080
      name: http
  type: ClusterIP
```

---

## 4. Rotation Pod Deployment

The rotation pod is a **separate Deployment** with one replica. It uses the same application
image but with rotation-tuned JVM and Hikari settings. ShedLock (via the shared PostgreSQL
database) ensures only one pod holds the rotation lock — if you ever scale rotation replicas to
2 for redundancy, only one will actually process batches at a time.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: card-tokenisation-rotation
  namespace: payments
  labels:
    app: card-tokenisation
    role: rotation-worker
spec:
  replicas: 1
  selector:
    matchLabels:
      app: card-tokenisation
      role: rotation-worker
  template:
    metadata:
      labels:
        app: card-tokenisation
        role: rotation-worker
    spec:
      terminationGracePeriodSeconds: 120   # give the rotation loop time to finish a batch
      containers:
        - name: app
          image: registry.internal/card-tokenisation:latest
          imagePullPolicy: Always
          ports:
            - containerPort: 8080
              name: http
          resources:
            requests:
              cpu: "1000m"
              memory: "2Gi"
            limits:
              cpu: "4000m"
              memory: "4Gi"
          env:
            - name: JAVA_TOOL_OPTIONS
              value: >-
                -Xmx3g
                -Xms1g
                -Djdk.virtualThreadScheduler.parallelism=256
                -Djdk.virtualThreadScheduler.maxPoolSize=512
                -XX:+UseZGC
            # Override rotation settings for this pod via env (Spring property binding)
            - name: ROTATION_BATCH_PARALLELISM
              value: "16"
            - name: ROTATION_BATCH_SIZE
              value: "1000"
            - name: SPRING_DATASOURCE_HIKARI_MAXIMUM_POOL_SIZE
              value: "40"
            - name: SPRING_DATASOURCE_HIKARI_MINIMUM_IDLE
              value: "10"
            - name: SPRING_DATASOURCE_HIKARI_CONNECTION_INIT_SQL
              value: "SET synchronous_commit = off"
          envFrom:
            - secretRef:
                name: card-tokenisation-secrets
            - configMapRef:
                name: card-tokenisation-config
          readinessProbe:
            httpGet:
              path: /actuator/health/readiness
              port: 8080
            initialDelaySeconds: 30
            periodSeconds: 10
            failureThreshold: 3
          livenessProbe:
            httpGet:
              path: /actuator/health/liveness
              port: 8080
            initialDelaySeconds: 60
            periodSeconds: 30
```

### 4.1 ShedLock configuration

ShedLock prevents two pods from running the rotation job simultaneously. Add to your
`application.yml` (or ConfigMap):

```yaml
shedlock:
  defaults:
    lock-at-most-for: PT30M    # release lock after 30 min even if pod dies mid-rotation
    lock-at-least-for: PT1M    # prevent immediate re-entry after fast completion
```

The rotation job annotation:

```java
@Scheduled(cron = "${rotation.batch.cron}")
@SchedulerLock(name = "RotationJob_processRotationBatch",
               lockAtMostFor = "${shedlock.defaults.lock-at-most-for}",
               lockAtLeastFor = "${shedlock.defaults.lock-at-least-for}")
public void processRotationBatch() { ... }
```

ShedLock requires a `shedlock` table — add a Flyway migration:

```sql
-- V10__add_shedlock.sql
CREATE TABLE IF NOT EXISTS shedlock (
    name        VARCHAR(64)  NOT NULL,
    lock_until  TIMESTAMP    NOT NULL,
    locked_at   TIMESTAMP    NOT NULL,
    locked_by   VARCHAR(255) NOT NULL,
    PRIMARY KEY (name)
);
```

---

## 5. OpenShift Route (HAProxy Ingress)

OpenShift Routes are served by the built-in HAProxy router. The annotations below tune it
for the tokenisation service's latency profile.

```yaml
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  name: card-tokenisation
  namespace: payments
  annotations:
    # Allow up to 60s for long rotation admin requests and slow-start traffic pods
    haproxy.router.openshift.io/timeout: 60s

    # leastconn spreads load to the least-busy pod.
    # Round-robin (the default) sends bursts to whichever pod is "next" even if it's
    # already saturated. leastconn is strictly better for variable-latency crypto workloads.
    haproxy.router.openshift.io/balance: leastconn

    # Disable cookie-based session affinity. The app is fully stateless — sticky sessions
    # add latency overhead with no benefit and skew load distribution.
    haproxy.router.openshift.io/disable_cookies: "true"

    # Keep 100 concurrent connections per HAProxy thread to the backend pool.
    # Default is 10000 which is too high for a 3–5 pod cluster; 200 prevents HAProxy
    # from queueing thousands of requests when all pods are briefly slow.
    haproxy.router.openshift.io/rate-limit-connections: "true"
    haproxy.router.openshift.io/rate-limit-connections.concurrent-tcp: "200"

    # Protect against slow clients consuming connection slots
    haproxy.router.openshift.io/timeout-tunnel: "60s"
spec:
  host: card-tokenisation.apps.your-cluster.example.com
  to:
    kind: Service
    name: card-tokenisation
    weight: 100
  port:
    targetPort: http
  tls:
    termination: edge                     # HAProxy terminates TLS; app sees plain HTTP
    insecureEdgeTerminationPolicy: Redirect
  wildcardPolicy: None
```

### 5.1 mTLS variant

If merchants are required to present client certificates (see `docs/ops-runbook.md §2`),
use `termination: reencrypt` instead of `edge`:

```yaml
  tls:
    termination: reencrypt
    # HAProxy re-encrypts to the pod — app receives TLS with the client cert forwarded
    # in the X-Forwarded-Client-Cert header (configure Spring Security to validate it)
    destinationCACertificate: |
      -----BEGIN CERTIFICATE-----
      <your internal CA cert>
      -----END CERTIFICATE-----
```

### 5.2 HAProxy tuning reference

| Annotation | Value | Reason |
|-----------|-------|--------|
| `timeout` | `60s` | Admin rotation endpoints can be slow; prevents 504 during long batches |
| `balance` | `leastconn` | Routes to least-loaded pod; better than round-robin for crypto |
| `disable_cookies` | `true` | Stateless app; cookies add overhead and skew load |
| `rate-limit-connections.concurrent-tcp` | `200` | Caps HAProxy→pod queue depth |
| `timeout-tunnel` | `60s` | Closes zombie connections from slow clients |

---

## 6. HorizontalPodAutoscaler

Scale from 3 to 5 pods at 70% average CPU. This gives burst headroom without over-provisioning
during normal operation.

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: card-tokenisation
  namespace: payments
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
  behavior:
    scaleUp:
      # Scale up quickly when under load — add 1 pod at a time, stabilise for 30s before
      # adding another to avoid thrashing.
      stabilizationWindowSeconds: 30
      policies:
        - type: Pods
          value: 1
          periodSeconds: 30
    scaleDown:
      # Scale down slowly — wait 5 minutes of below-threshold CPU before removing a pod.
      # Prevents premature scale-down during payment peaks that follow lunch/dinner patterns.
      stabilizationWindowSeconds: 300
      policies:
        - type: Pods
          value: 1
          periodSeconds: 120
```

> **Note:** Do not attach an HPA to the rotation pod (`card-tokenisation-rotation`). The
> rotation job is DB-bound, not CPU-bound; scaling it horizontally without ShedLock would
> double-process batches. Keep `replicas: 1` and rely on the continuous loop for throughput.

---

## 7. PodDisruptionBudget

Ensures at least 2 traffic pods remain available during node drain, cluster upgrade, or
rolling deployment. Without this, a 3-pod cluster drained to 0 pods would cause an outage.

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: card-tokenisation-pdb
  namespace: payments
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: card-tokenisation
      role: traffic-worker
```

**Rotation pod PDB** — not strictly needed (rotation is background work, not customer-facing),
but add one if you need to guarantee the rotation job isn't interrupted mid-batch during
a node drain:

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: card-tokenisation-rotation-pdb
  namespace: payments
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app: card-tokenisation
      role: rotation-worker
```

---

## 8. ConfigMap and Secret Layout

### 8.1 ConfigMap — non-sensitive configuration

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: card-tokenisation-config
  namespace: payments
data:
  # Rotation tuning (traffic pod defaults — rotation pod overrides via env)
  ROTATION_BATCH_CRON: "0 */15 * * * *"
  ROTATION_BATCH_SIZE: "500"
  ROTATION_BATCH_PARALLELISM: "8"
  ROTATION_BATCH_MAX_BATCHES_PER_RUN: "0"
  ROTATION_COMPLIANCE_MAX_KEY_AGE_DAYS: "365"

  # Detokenisation rate limiting
  DETOKENISATION_RATE_LIMIT_PER_MERCHANT_PER_SECOND: "100"
  DETOKENISATION_RATE_LIMIT_GLOBAL_PER_SECOND: "1000"

  # Hikari pool (traffic pod defaults)
  SPRING_DATASOURCE_HIKARI_MAXIMUM_POOL_SIZE: "20"
  SPRING_DATASOURCE_HIKARI_MINIMUM_IDLE: "5"
  SPRING_DATASOURCE_HIKARI_CONNECTION_TIMEOUT: "10000"

  # Actuator
  MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE: "health,info,metrics,prometheus"
  MANAGEMENT_ENDPOINT_HEALTH_SHOW_DETAILS: "when_authorized"

  # KMS provider — set to "aws" in production
  KMS_PROVIDER: "aws"
  KMS_AWS_REGION: "ap-southeast-2"
  KMS_AWS_KEY_ARN: "arn:aws:kms:ap-southeast-2:123456789012:key/your-key-id"
```

### 8.2 Secret — sensitive values

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: card-tokenisation-secrets
  namespace: payments
type: Opaque
stringData:
  DATASOURCE_URL: "jdbc:postgresql://your-rds-endpoint.rds.amazonaws.com:5432/tokenisation"
  DATASOURCE_USER: "tokenisation_app"
  DATASOURCE_PASSWORD: "<strong-random-password>"
  PAN_HASH_SECRET: "<32-byte-random-hex>"
  TAMPER_DETECTION_SECRET: "<32-byte-random-hex>"
  # Only needed when KMS_PROVIDER=local-dev (never in production)
  # KMS_LOCAL_DEV_KEK_HEX: "not-set-in-production"
```

> **Security note:** Never commit Secrets to source control. Use Sealed Secrets, Vault Agent
> Injector, or the OpenShift Secrets Store CSI driver to inject them from an external vault.
> The `stringData` block above is for documentation only — provision these through your
> secrets management pipeline.

### 8.3 Secrets management options

| Option | Complexity | Recommended for |
|--------|-----------|----------------|
| OpenShift Secrets (base64 in etcd) | Low | Dev/staging only |
| Sealed Secrets (Bitnami) | Low | GitOps workflows |
| HashiCorp Vault + Agent Injector | Medium | Production, multi-cluster |
| AWS Secrets Manager + CSI driver | Medium | AWS-hosted OpenShift (ROSA) |
| OpenShift Secrets Store CSI | Medium | Any external vault |

---

## 9. PostgreSQL Options

### 9.1 Option A — AWS RDS PostgreSQL (recommended for ROSA/AWS)

Managed, Multi-AZ, automated backups, no operator needed.

**Recommended instance:** `db.r6g.xlarge` (4 vCPU, 32 GB RAM) for 1M tokens/day workload.

```
# RDS parameter group settings
max_connections = 300
shared_buffers = 8GB                    # ~25% of RAM
effective_cache_size = 24GB             # ~75% of RAM
synchronous_commit = on                 # default; rotation pod overrides per connection
autovacuum_vacuum_scale_factor = 0.01   # aggressive for token_vault heavy updates
autovacuum_analyze_scale_factor = 0.005
wal_compression = on
```

**Connection string format:**
```
jdbc:postgresql://your-rds-endpoint.ap-southeast-2.rds.amazonaws.com:5432/tokenisation
  ?ssl=true
  &sslmode=require
  &connectTimeout=10
  &socketTimeout=60
```

**IAM authentication (instead of password):** Enable `rds.iam_authentication=1` on the
parameter group and configure the application's datasource to use an IAM token as the
password (refreshed every 15 minutes).

### 9.2 Option B — Crunchy Postgres Operator (on-cluster)

For on-premises OpenShift where RDS is not available.

```yaml
apiVersion: postgres-operator.crunchydata.com/v1beta1
kind: PostgresCluster
metadata:
  name: tokenisation-db
  namespace: payments
spec:
  image: registry.developers.crunchydata.com/crunchydata/crunchy-postgres:ubi8-15.6-0
  postgresVersion: 15
  instances:
    - name: pgha1
      replicas: 2                         # primary + 1 standby
      dataVolumeClaimSpec:
        accessModes: ["ReadWriteOnce"]
        resources:
          requests:
            storage: 100Gi
      resources:
        requests:
          cpu: "2"
          memory: "8Gi"
        limits:
          cpu: "4"
          memory: "16Gi"
  patroni:
    dynamicConfiguration:
      postgresql:
        parameters:
          max_connections: "300"
          shared_buffers: "2GB"
          autovacuum_vacuum_scale_factor: "0.01"
          synchronous_commit: "on"
  backups:
    pgbackrest:
      repos:
        - name: repo1
          volume:
            volumeClaimSpec:
              accessModes: ["ReadWriteOnce"]
              resources:
                requests:
                  storage: 200Gi
```

### 9.3 Rotation window database tuning

During a scheduled rotation run (~5 minutes), temporarily relax durability on the rotation
connection to maximise throughput. The rotation pod sets this per-connection via HikariCP:

```yaml
# application.yml on rotation pod (or override via env SPRING_DATASOURCE_HIKARI_CONNECTION_INIT_SQL)
spring:
  datasource:
    hikari:
      connection-init-sql: "SET synchronous_commit = off"
```

`synchronous_commit = off` does **not** risk data loss for tokenisation: DEKs are still
committed before the client receives a response — the relaxation only means the WAL flush
may lag by up to `wal_writer_delay` (200ms default). In the event of a PostgreSQL crash
mid-rotation, incomplete rewraps are detected at next startup (tokens still on old key)
and re-processed. Client-side retry handles this transparently.

---

## 10. Pod Sizing Cheat-Sheet

| Scenario | Pod role | Replicas | CPU req/limit | Mem req/limit | Notes |
|----------|----------|----------|---------------|---------------|-------|
| Dev / local | traffic | 1 | 250m / 1000m | 512Mi / 1Gi | `make start` |
| Staging | traffic | 1 | 500m / 2000m | 1Gi / 2Gi | Full image, no HPA |
| Production baseline | traffic | 3 | 500m / 2000m | 1Gi / 2Gi | HA + failover |
| Production rotation | rotation | 1 | 1000m / 4000m | 2Gi / 4Gi | ShedLock, no HPA |
| Production peak (HPA) | traffic | up to 5 | 500m / 2000m | 1Gi / 2Gi | CPU 70% trigger |
| Emergency rotation | rotation | 1 | 2000m / 4000m | 3Gi / 4Gi | `ROTATION_BATCH_PARALLELISM=32` |

### JVM flags by role

| Role | `-Xmx` | `-Xms` | Virtual thread parallelism |
|------|--------|--------|--------------------------|
| Traffic pod | 1536m | 512m | 256 |
| Rotation pod | 3g | 1g | 256 |
| Load test (local) | 2g | 512m | 256 |

---

## 11. Deployment Checklist

Run through this checklist for every production deployment:

**Before deploy:**
- [ ] Image tagged with git SHA (not `latest`) in production — update `image:` fields
- [ ] Secrets provisioned in the cluster (not committed to source control)
- [ ] `KMS_PROVIDER=aws` in ConfigMap (not `local-dev`)
- [ ] `KMS_AWS_KEY_ARN` points to the production KMS key
- [ ] `DATASOURCE_URL` points to production RDS endpoint
- [ ] Database migrations run: `make db-migrate` or Flyway init container
- [ ] PodDisruptionBudget applied (`kubectl apply -f pdb.yaml`)
- [ ] HPA applied (`kubectl apply -f hpa.yaml`)
- [ ] Rotation pod is separate from traffic pods (different Deployment, different labels)

**During rolling deploy:**
- [ ] Watch `oc rollout status deployment/card-tokenisation` — should see pods replaced 1-at-a-time
- [ ] Watch readiness probe: `oc get pods -w` — all pods should reach `Running 1/1`
- [ ] Monitor error rate on Route: `oc get route card-tokenisation` → hit the health endpoint
- [ ] Confirm no `5xx` spike in application logs: `oc logs -l app=card-tokenisation --tail=100`

**After deploy:**
- [ ] Smoke test: POST a tokenise request, GET detokenise, verify round-trip
- [ ] Verify rotation cron is firing: check logs on rotation pod
- [ ] Confirm HPA is active: `oc get hpa card-tokenisation`
- [ ] Archive the deploy timestamp + image SHA in the incident log

---

## 12. Rollback Procedure

### 12.1 Rolling rollback (image only)

```bash
# Revert to the previous image
oc rollout undo deployment/card-tokenisation
oc rollout undo deployment/card-tokenisation-rotation

# Monitor rollback
oc rollout status deployment/card-tokenisation
```

### 12.2 Schema rollback (Flyway)

Flyway does not support automatic rollback. If a migration caused the incident:

1. Identify the bad migration: `oc exec <pod> -- flyway info`
2. Write a compensating migration `Vnext__rollback_bad_migration.sql`
3. Apply via `make db-migrate`
4. Redeploy the previous application image

> **Irreversible migrations:** Dropping columns or tables cannot be undone. Always take a
> database snapshot before deploying a migration that removes schema objects.

### 12.3 Key rotation rollback

If a rotation was initiated but not completed (e.g., rotation pod OOM-killed mid-batch):

1. The `key_versions` table has the rotation in `ROTATING` state
2. Remaining tokens still on the old key are detected by `countActiveByKeyVersionId`
3. Restarting the rotation pod resumes automatically — the cron job picks up where it left off
4. If the new key was compromised: trigger emergency rotation via
   `POST /api/v1/admin/keys/rotate` with `reason: EMERGENCY`
