# Operations Runbook — Card Tokenisation System

This runbook covers deployment hardening, mTLS configuration, database high-throughput tuning,
monitoring setup, and day-2 operational procedures.

---

## Table of Contents

1. [Pre-Deployment Security Hardening](#1-pre-deployment-security-hardening)
2. [mTLS Configuration](#2-mtls-configuration)
3. [Database High-Throughput Configuration](#3-database-high-throughput-configuration)
4. [Monitoring and Observability](#4-monitoring-and-observability)
5. [JWT Authentication Setup (Phase 2)](#5-jwt-authentication-setup-phase-2)
6. [Distributed Rate Limiting (Multi-Node)](#6-distributed-rate-limiting-multi-node)
7. [Incident Response Procedures](#7-incident-response-procedures)
8. [Production Environment Variables Reference](#8-production-environment-variables-reference)

---

## 1. Pre-Deployment Security Hardening

### 1.1 Remove Development Defaults

Before any production deployment, verify these are all absent from the running configuration:

| Item | Risk | Action |
|------|------|--------|
| `KMS_PROVIDER=local-dev` | Plaintext KEK in environment | Set `KMS_PROVIDER=aws` |
| `KMS_LOCAL_DEV_KEK_HEX` set | Known KEK in env | Remove entirely |
| Swagger UI reachable | Exposes API schema | Disable or firewall |
| `anyRequest().permitAll()` in `SecurityConfig` | Zero auth | See §5 before deploying |
| Default DB superuser as app user | Overprivileged | Use `tokenisation_app` role |

### 1.2 Set the Database Role Password

The `V6__setup_db_roles.sql` migration creates the `tokenisation_app` role without a password
(to avoid committing credentials to source control). After the first migration run, set the
password out-of-band:

```sql
ALTER ROLE tokenisation_app PASSWORD '<strong-random-password-from-secrets-manager>';
```

Then configure the application datasource:
```
DATASOURCE_USER=tokenisation_app
DATASOURCE_PASSWORD=<same-strong-password>
```

### 1.3 Disable Swagger UI in Production

Add to your production `application-production.yml`:

```yaml
springdoc:
  api-docs:
    enabled: false
  swagger-ui:
    enabled: false
```

Or restrict it to internal networks only at the load-balancer / WAF level.

### 1.4 Secrets Management

All secrets must come from a secrets manager, not environment variables directly where possible:

| Secret | Recommended Source |
|--------|--------------------|
| `DATASOURCE_PASSWORD` | AWS Secrets Manager / Vault |
| `PAN_HASH_SECRET` | AWS Secrets Manager / Vault |
| `TAMPER_DETECTION_SECRET` | AWS Secrets Manager / Vault |
| `AWS_KMS_KEY_ARN` | AWS Parameter Store |
| SSL keystore password | AWS Secrets Manager |

Use Spring Cloud AWS or a sidecar to inject these at pod startup.

---

## 2. mTLS Configuration

Mutual TLS (mTLS) ensures that both the server and the calling client authenticate with
certificates. For a PCI-DSS tokenisation vault this is the primary access control at the
network layer — **all** merchant integrations must present a valid client certificate.

### 2.1 Recommended Architecture: Terminate at the Ingress

Apply mTLS **at the ingress layer**, not in the Spring Boot application. This separates
certificate management from application code and is easier to rotate and revoke.

```
Merchant → [mTLS] → ALB / Nginx / Istio → [plain TLS or HTTP] → Spring Boot (internal network)
```

#### AWS Application Load Balancer (mTLS)

```bash
# 1. Create a trust store with your merchant CA certificates
aws elbv2 create-trust-store \
  --name card-tokenisation-trust \
  --ca-certificates-bundle-s3-bucket my-ca-bundle-bucket \
  --ca-certificates-bundle-s3-key ca-bundle.pem

# 2. Enable mutual TLS on the HTTPS listener
aws elbv2 modify-listener \
  --listener-arn <your-listener-arn> \
  --mutual-authentication Mode=verify,TrustStoreArn=<trust-store-arn>
```

The ALB will reject any request without a valid client certificate before it reaches the
Spring Boot application.

#### Kubernetes with Istio

```yaml
# Enforce STRICT mTLS for the tokenisation namespace
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: card-tokenisation-mtls
  namespace: tokenisation
spec:
  mtls:
    mode: STRICT
---
# Require a specific SPIFFE identity for callers
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: card-tokenisation-callers
  namespace: tokenisation
spec:
  rules:
  - from:
    - source:
        principals:
        - "cluster.local/ns/merchant-gateway/sa/gateway-sa"
```

#### Nginx Ingress

```nginx
server {
    listen 443 ssl;
    ssl_certificate     /etc/ssl/certs/server.crt;
    ssl_certificate_key /etc/ssl/private/server.key;

    # Require client certificate
    ssl_client_certificate /etc/ssl/certs/merchant-ca.crt;
    ssl_verify_client on;
    ssl_verify_depth 2;

    location /api/v1/ {
        # Forward verified client CN to application for merchant ID extraction
        proxy_set_header X-Client-CN $ssl_client_s_dn_cn;
        proxy_pass http://card-tokenisation-service:8080;
    }
}
```

### 2.2 Spring Boot Application-Layer mTLS (Fallback)

Use this approach only when you cannot apply mTLS at the infrastructure layer (no ALB, no
Ingress controller, direct-to-JVM traffic). The certificate setup, trust exchange, and
handshake mechanics described below also apply when you operate your own CA regardless of
where TLS is terminated.

---

#### How mTLS Works

Standard TLS authenticates only the **server** to the client (the client checks the server's
certificate against a trusted CA). mTLS adds a second leg: the **server also demands a
certificate from the client** and refuses the connection if the client certificate is absent,
expired, or signed by an untrusted CA.

```
  Client (Merchant)                        Server (Tokenisation Vault)
  ─────────────────                        ───────────────────────────
  1. ClientHello ─────────────────────────►
  2.                         ServerHello ◄─────────────────────────────
                        Server Certificate  (server proves its identity)
                    CertificateRequest ◄─────── server demands client cert
  3. Client Certificate ───────────────────►  (client proves its identity)
     CertificateVerify ──────────────────────►
  4. Both sides derive session keys from the handshake — Finished
  ─────────────────────────────────────────────────────────────────────
  5. Application data (HTTP/JSON) flows over the encrypted tunnel
```

Both sides verify:
- The certificate was signed by a trusted CA (trust anchor)
- The certificate has not expired
- The certificate has not been revoked (CRL / OCSP)

The **Common Name (CN)** or **Subject Alternative Name (SAN)** in the client certificate
identifies which merchant is calling. The application extracts this and uses it as the
authoritative merchant ID — the caller cannot spoof a different merchant ID because the
certificate is bound to their private key, which only they hold.

---

#### Certificate Roles and What Each Party Holds

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Certificate Authority (CA)                      │
│   You operate this.  Issues and signs all certificates.             │
│   Private key is the most sensitive asset — keep it offline/HSM.   │
└──────────────────┬──────────────────────┬───────────────────────────┘
                   │ signs                │ signs
        ┌──────────▼──────────┐  ┌────────▼────────────────┐
        │  Server Certificate │  │  Client Certificate     │
        │  (Tokenisation Vault)│  │  (Merchant A, B, C ...) │
        │                     │  │                         │
        │  Subject: CN=card-  │  │  Subject: CN=merchant-a │
        │    tokenisation.int │  │  Issuer: Your CA        │
        │  Issuer: Your CA    │  │  Private key: held by   │
        │  Private key: held  │  │    the merchant         │
        │    by your servers  │  └─────────────────────────┘
        └─────────────────────┘
```

| Party | What they hold | What they receive from you |
|-------|---------------|---------------------------|
| **You (vault operator)** | CA private key + CA cert, server private key + server cert | — |
| **Merchant (client)** | Their own private key + their client cert (signed by your CA) | Your CA certificate (to verify the server cert) |
| **You trust from merchant** | — | Their client certificate (signed by your CA, or their CSR for you to sign) |

---

#### Step 1 — Create Your Certificate Authority

Do this **once**. The CA private key must never leave a secure environment (HSM or encrypted offline storage).

```bash
# Create the CA private key (4096-bit RSA; ECDSA P-384 is also acceptable)
openssl genrsa -aes256 -out ca.key 4096

# Self-sign the CA certificate (valid 10 years — CAs are long-lived)
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
  -subj "/C=AU/O=YourOrg/CN=Card Tokenisation Vault CA" \
  -out ca.crt

# Verify
openssl x509 -in ca.crt -text -noout | grep -A2 "Subject:\|Validity"
```

`ca.crt` is your **trust anchor**. You distribute this to every merchant so they can verify
the server certificate. Your server's trust store also loads it to verify client certificates.

---

#### Step 2 — Issue the Server Certificate

```bash
# Server private key
openssl genrsa -out server.key 4096

# Certificate Signing Request (CSR)
# CN and SAN must match the hostname clients will connect to
openssl req -new -key server.key \
  -subj "/C=AU/O=YourOrg/CN=card-tokenisation.internal" \
  -out server.csr

# Sign with your CA; include SAN extension
cat > server-ext.cnf <<EOF
[req]
req_extensions = v3_req
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = card-tokenisation.internal
DNS.2 = tokenisation-api.yourorg.com
IP.1  = 10.0.1.50
EOF

openssl x509 -req -in server.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 365 -sha256 \
  -extfile server-ext.cnf -extensions v3_req \
  -out server.crt

# Bundle into PKCS12 for the Java keystore
openssl pkcs12 -export \
  -in server.crt -inkey server.key -certfile ca.crt \
  -name card-tokenisation \
  -out server.p12 \
  -passout pass:${SERVER_KEYSTORE_PASSWORD}
```

Place `server.p12` at `${SSL_KEYSTORE_PATH}`.

---

#### Step 3 — Create the Server's Trust Store

The trust store tells the server which CA certificates it accepts for verifying client
certificates. Load your CA cert (and any intermediate CAs) into it:

```bash
# Create trust store from the CA certificate
keytool -importcert \
  -alias tokenisation-ca \
  -file ca.crt \
  -keystore truststore.p12 \
  -storetype PKCS12 \
  -storepass ${TRUSTSTORE_PASSWORD} \
  -noprompt

# Verify
keytool -list -keystore truststore.p12 -storepass ${TRUSTSTORE_PASSWORD}
```

Place `truststore.p12` at `${SSL_TRUSTSTORE_PATH}`.

---

#### Step 4 — Issue a Client Certificate for Each Merchant

You have two options:

**Option A — You generate the key pair and deliver the PKCS12 bundle to the merchant (simpler)**

```bash
MERCHANT_ID="merchant-a"

# Generate client private key
openssl genrsa -out ${MERCHANT_ID}.key 4096

# CSR — CN becomes the merchant ID the application extracts
openssl req -new -key ${MERCHANT_ID}.key \
  -subj "/C=AU/O=YourOrg/CN=${MERCHANT_ID}" \
  -out ${MERCHANT_ID}.csr

# Sign with your CA
openssl x509 -req -in ${MERCHANT_ID}.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 365 -sha256 \
  -out ${MERCHANT_ID}.crt

# Pack into PKCS12 to hand to the merchant
# The merchant imports this into their HTTP client / keystore
openssl pkcs12 -export \
  -in ${MERCHANT_ID}.crt \
  -inkey ${MERCHANT_ID}.key \
  -certfile ca.crt \
  -name ${MERCHANT_ID} \
  -out ${MERCHANT_ID}.p12 \
  -passout pass:${CLIENT_BUNDLE_PASSWORD}
```

Deliver `${MERCHANT_ID}.p12` and `${CLIENT_BUNDLE_PASSWORD}` to the merchant **via separate
secure channels** (e.g. the bundle via encrypted email, the password via SMS or phone).

**Option B — Merchant generates their own key pair and sends you a CSR (more secure)**

```bash
# Merchant runs on their side:
openssl genrsa -out merchant-a.key 4096
openssl req -new -key merchant-a.key \
  -subj "/C=AU/O=MerchantA/CN=merchant-a" \
  -out merchant-a.csr
# Merchant sends you merchant-a.csr via secure channel

# You sign it:
openssl x509 -req -in merchant-a.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 365 -sha256 \
  -out merchant-a.crt
# You send merchant-a.crt back to the merchant
```

The merchant's private key never leaves their environment. This is the more secure option
and should be preferred for production.

---

#### What You Send to Each Merchant

| Artefact | Format | Purpose |
|----------|--------|---------|
| `ca.crt` | PEM | Trust anchor — merchant imports this so their HTTP client trusts your server certificate |
| `merchant-a.p12` (Option A) or `merchant-a.crt` (Option B) | PKCS12 / PEM | Client certificate — merchant presents this on every request |
| `CLIENT_BUNDLE_PASSWORD` (Option A only) | Out-of-band | Password to open the PKCS12 bundle |
| API base URL + port | Documentation | `https://card-tokenisation.internal:8443/api/v1` |

**Never send the CA private key to anyone.**

---

#### What You Receive from Each Merchant

| Artefact | When | Purpose |
|----------|------|---------|
| `merchant-a.csr` | Option B only — at onboarding | You sign it to produce their client certificate |
| Signed `merchant-a.crt` (if they use their own CA) | If you accept external CA certs | Import their CA into your trust store |

For most deployments, **Option A or B with your own CA** is correct. Accepting merchant-operated
CAs adds complexity and requires strict vetting.

---

#### Step 5 — Spring Boot Configuration

```yaml
# application-production.yml
server:
  port: 8443
  ssl:
    enabled: true
    # Server identity (Step 2)
    key-store: ${SSL_KEYSTORE_PATH}            # path to server.p12
    key-store-password: ${SSL_KEYSTORE_PASSWORD}
    key-store-type: PKCS12
    key-alias: card-tokenisation
    # Client certificate verification (Step 3)
    client-auth: need                          # reject connections without a client cert
    trust-store: ${SSL_TRUSTSTORE_PATH}        # path to truststore.p12
    trust-store-password: ${SSL_TRUSTSTORE_PASSWORD}
    trust-store-type: PKCS12
    # Protocol hardening
    protocol: TLS
    enabled-protocols: TLSv1.3               # drop to TLSv1.2,TLSv1.3 for legacy clients
    ciphers: >
      TLS_AES_256_GCM_SHA384,
      TLS_AES_128_GCM_SHA256,
      TLS_CHACHA20_POLY1305_SHA256
```

---

#### Step 6 — Extract Merchant ID from the Client Certificate

Add a utility method and update `TokenController` to read the verified CN rather than trusting
the request body:

```java
// In TokenController.java

@PostMapping
public TokeniseResponse tokenise(
        @Valid @RequestBody TokeniseRequest request,
        HttpServletRequest httpRequest) {
    request.setMerchantId(extractVerifiedMerchantId(httpRequest));
    return tokenisationService.tokenise(request);
}

@GetMapping("/{token}")
public DetokeniseResponse detokenise(
        @PathVariable String token,
        HttpServletRequest httpRequest) {
    String merchantId = extractVerifiedMerchantId(httpRequest);
    return detokenisationService.detokenise(token, merchantId);
}

private String extractVerifiedMerchantId(HttpServletRequest request) {
    X509Certificate[] certs = (X509Certificate[])
        request.getAttribute("jakarta.servlet.request.X509Certificate");
    if (certs == null || certs.length == 0) {
        throw new AccessDeniedException("Client certificate required");
    }
    // Extract CN from Subject DN, e.g. "CN=merchant-a, O=YourOrg, C=AU" → "merchant-a"
    String dn = certs[0].getSubjectX500Principal().getName(X500Principal.RFC2253);
    return Arrays.stream(dn.split(","))
        .map(String::trim)
        .filter(part -> part.startsWith("CN="))
        .findFirst()
        .map(cn -> cn.substring(3))
        .orElseThrow(() -> new AccessDeniedException("Client certificate has no CN"));
}
```

The merchant cannot fake a different `CN` — the certificate is signed by your CA and
the private key is known only to that merchant.

---

#### Step 7 — Test the mTLS Handshake

```bash
# Test that the server rejects a request with no client cert
curl -v --cacert ca.crt https://card-tokenisation.internal:8443/api/v1/health
# Expected: TLS handshake failure (SSL alert: certificate required)

# Test with a valid client cert
curl -v \
  --cacert ca.crt \
  --cert merchant-a.crt \
  --key merchant-a.key \
  https://card-tokenisation.internal:8443/api/v1/health
# Expected: HTTP 200 {"status":"UP"}

# Test with a cert signed by a different (untrusted) CA
# Expected: TLS handshake failure (SSL alert: unknown CA)

# Test certificate details visible during handshake
openssl s_client \
  -connect card-tokenisation.internal:8443 \
  -cert merchant-a.crt \
  -key merchant-a.key \
  -CAfile ca.crt \
  -state -debug 2>&1 | grep -E "SSL_connect|subject|issuer|Verify"
```

---

#### Merchant Integration Checklist

Share this checklist with each merchant when onboarding:

```
mTLS Onboarding Checklist — Card Tokenisation Vault
────────────────────────────────────────────────────
You will receive from us:
  [ ] ca.crt          — Import as a trusted CA in your HTTP client
  [ ] merchant-X.p12  — Your client certificate bundle (Option A)
      OR
  [ ] merchant-X.crt  — Your signed client certificate (Option B, after you send us a CSR)
  [ ] API base URL    — https://card-tokenisation.internal:8443/api/v1

You must send us (Option B only):
  [ ] merchant-X.csr  — Your Certificate Signing Request

HTTP client configuration:
  [ ] Load ca.crt as the trusted CA (do not use the system trust store for this endpoint)
  [ ] Load your client certificate and private key
  [ ] Set TLS minimum version to TLSv1.2 (TLSv1.3 preferred)
  [ ] Verify the server hostname matches the CN / SAN in the server certificate
  [ ] Do NOT disable certificate verification (no --insecure / verify=False in production)

Test your integration:
  [ ] curl --cacert ca.crt --cert merchant-X.crt --key merchant-X.key \
           https://card-tokenisation.internal:8443/api/v1/health
      → Expected: {"status":"UP"}
```

### 2.3 Certificate Lifecycle

| Task | Frequency | Procedure |
|------|-----------|-----------|
| Rotate server certificate | 90 days or before expiry | Zero-downtime: load new cert alongside old, swap, remove old |
| Rotate merchant client cert | On merchant request / 1 year | Issue new cert, merchant tests, revoke old |
| Revoke compromised cert | Immediately on compromise | Update CRL / OCSP stapling on load balancer |
| Audit client cert usage | Monthly | Check ALB access logs for CN patterns |

---

## 3. Database High-Throughput Configuration

### 3.1 HikariCP Connection Pool Sizing

**Rule: `pool-size ≥ 2 × max-concurrency`**

The Spring Boot application and its test suite share the same HikariCP pool. The pool must
have headroom for background threads (HikariCP housekeeper, Hibernate entity manager, Flyway
migration runner) beyond the application's maximum concurrency.

```yaml
# application-production.yml
spring:
  datasource:
    hikari:
      # Production: 50 app threads × 2 = 100, plus 20 buffer
      maximum-pool-size: 120
      minimum-idle: 10
      connection-timeout: 5000        # Fail fast — 5 seconds
      idle-timeout: 600000            # 10 minutes
      max-lifetime: 1800000           # 30 minutes — shorter than PostgreSQL's tcp_keepalives_idle
      keepalive-time: 60000           # 1 minute — prevents idle connection drops at firewalls
      connection-init-sql: "SET synchronous_commit = off"  # async WAL write — see §3.3
```

### 3.2 PostgreSQL Configuration for High Throughput

Edit `postgresql.conf` (or use an RDS parameter group):

```ini
# Connection headroom
max_connections = 300        # HikariCP manages actual usage; this is the hard cap

# Memory — tune to available RAM (example: 32 GB server)
shared_buffers = 8GB         # 25% of RAM
effective_cache_size = 24GB  # 75% of RAM — hint to planner, not actual allocation
work_mem = 64MB              # Per sort/hash operation; multiply by max_connections for total
maintenance_work_mem = 2GB   # For VACUUM, CREATE INDEX

# Write performance
synchronous_commit = off      # Async WAL write — safe for tokenisation (idempotent retries)
                              # NEVER turn off for audit_log table in strict compliance environments
wal_buffers = 64MB
checkpoint_completion_target = 0.9
max_wal_size = 4GB

# Parallel query (for rotation batch SELECT)
max_parallel_workers_per_gather = 4
max_parallel_workers = 8

# Autovacuum — critical for token_vault as rows are updated (DEK re-encryption)
autovacuum_vacuum_cost_delay = 2ms
autovacuum_vacuum_scale_factor = 0.01  # Vacuum after 1% of table changes (default: 20%)
autovacuum_analyze_scale_factor = 0.005
```

### 3.3 `synchronous_commit = off` Trade-off

With `synchronous_commit = off`, a committed transaction may not have been flushed to disk if
the server crashes within ~200ms. For the tokenisation vault:

- **token_vault writes**: Acceptable — the PAN is not lost (client retries tokenisation).
- **token_audit_log writes**: Use `synchronous_commit = on` for the audit writer connection if
  PCI-DSS compliance requires guaranteed audit persistence. Override per transaction:
  ```sql
  SET LOCAL synchronous_commit = on;
  INSERT INTO token_audit_log ...;
  ```

### 3.4 Index Strategy

The existing indexes in `V4__create_indexes.sql` cover the hot paths. Key additions for production:

```sql
-- Partial index: only ACTIVE tokens — dramatically smaller index for recurring dedup lookup
CREATE UNIQUE INDEX CONCURRENTLY idx_tv_active_recurring_pan_merchant
    ON token_vault (pan_hash, merchant_id)
    WHERE is_active = true AND token_type = 'RECURRING';

-- Partial index: only tokens still on old key version — used by rotation batch SELECT
-- (already covered by idx_tv_key_version_id, but a partial on is_active=true is faster)
CREATE INDEX CONCURRENTLY idx_tv_active_by_key_version
    ON token_vault (key_version_id)
    WHERE is_active = true;

-- Covering index for audit log time-range queries (compliance reporting)
CREATE INDEX CONCURRENTLY idx_tal_created_at_event_type
    ON token_audit_log (created_at DESC, event_type);
```

> **Important:** The unique partial index on `(pan_hash, merchant_id) WHERE is_active AND RECURRING`
> is also the database-level guard against the RECURRING duplicate race condition. Without it, a
> concurrent race between two identical tokenisation requests can produce two RECURRING tokens and
> cause `NonUniqueResultException` on the next lookup. With the unique index, one of the two inserts
> will fail with a unique violation — the application must handle this by retrying the lookup.

### 3.5 PgBouncer (Connection Pooling Proxy)

For deployments with many application instances (e.g. Kubernetes horizontal scaling), each
instance brings its own HikariCP pool. With 10 pods × 120 connections = 1,200 connections
against PostgreSQL, you quickly exhaust `max_connections`.

Deploy PgBouncer in transaction pooling mode in front of PostgreSQL:

```ini
# pgbouncer.ini
[databases]
tokenisation = host=postgres-primary port=5432 dbname=tokenisation

[pgbouncer]
pool_mode = transaction
max_client_conn = 2000          # Total connections from all Spring Boot pods
default_pool_size = 100         # Connections PgBouncer maintains to PostgreSQL
reserve_pool_size = 20          # Emergency reserve
reserve_pool_timeout = 3
server_lifetime = 3600
server_idle_timeout = 600
```

With PgBouncer, Spring Boot's HikariCP talks to PgBouncer (not PostgreSQL directly), so
`max_connections` in PostgreSQL can stay at 150 even with many pods.

> **Caveat:** Transaction pooling mode is incompatible with `SET LOCAL` (session-level settings
> are reset between transactions). Ensure no `SET LOCAL synchronous_commit = on` is used per §3.3
> when PgBouncer is in the path.

### 3.6 Read Replicas

For compliance reporting and audit log queries that do not need to be real-time:

1. Create a PostgreSQL streaming replica (RDS read replica or pg_basebackup).
2. Configure a second `DataSource` bean pointing to the replica.
3. Annotate read-only services with `@Transactional(readOnly = true)` and route them to the
   replica datasource via Spring's `AbstractRoutingDataSource`.

```java
@Service
@Transactional(readOnly = true)
public class AuditReportingService {
    // Queries here run on the replica
}
```

### 3.7 Table Partitioning (Long-Term)

Once `token_audit_log` grows beyond ~100 million rows, range partition by `created_at`:

```sql
-- Convert to partitioned table (requires downtime or online migration tool like pg_partman)
CREATE TABLE token_audit_log_new (
    LIKE token_audit_log INCLUDING ALL
) PARTITION BY RANGE (created_at);

CREATE TABLE token_audit_log_2024
    PARTITION OF token_audit_log_new
    FOR VALUES FROM ('2024-01-01') TO ('2025-01-01');

CREATE TABLE token_audit_log_2025
    PARTITION OF token_audit_log_new
    FOR VALUES FROM ('2025-01-01') TO ('2026-01-01');
```

Old partitions can be archived (e.g., to S3 via `COPY TO`) after the 7-year retention window.

---

## 4. Monitoring and Observability

### 4.1 Key Metrics to Alert On

| Metric | Alert Threshold | Severity | Notes |
|--------|----------------|----------|-------|
| Tokenisation error rate | > 1% over 5 min | HIGH | Signals crypto or DB failure |
| Detokenisation 5xx rate | > 0.5% | HIGH | Merchant impact |
| HikariCP active connections | > 90% of pool | WARN | Pool exhaustion approaching |
| HikariCP pending threads | > 0 sustained 1 min | HIGH | Pool exhausted |
| Key rotation lag | tokens on old key > 0 for > 2 hours | WARN | Rotation batch stalled |
| Audit write failures | any | HIGH | Compliance log gap |
| Health endpoint status | not UP for > 30s | HIGH | Service unavailable |
| Tamper alert events in audit log | any | CRITICAL | Immediate investigation |
| p99 tokenisation latency | > 500ms | WARN | DB or crypto slowdown |

### 4.2 Spring Boot Actuator

Enable the actuator health and metrics endpoints (internal network only):

```yaml
management:
  endpoints:
    web:
      exposure:
        include: health, metrics, prometheus
      base-path: /actuator
  endpoint:
    health:
      show-details: when-authorized
  metrics:
    export:
      prometheus:
        enabled: true
```

Expose on a separate internal port:
```yaml
management:
  server:
    port: 8081
```

### 4.3 Custom Metrics

Add Micrometer counters to the tokenisation and detokenisation services:

```java
@Autowired MeterRegistry meterRegistry;

// In TokenisationService.tokenise():
meterRegistry.counter("tokenisation.requests", "outcome", "success").increment();

// On failure:
meterRegistry.counter("tokenisation.requests", "outcome", "failure",
                      "reason", exception.getClass().getSimpleName()).increment();

// Gauge for pool saturation:
meterRegistry.gauge("hikaricp.pending_threads",
    hikariDataSource, ds -> ds.getHikariPoolMXBean().getThreadsAwaitingConnection());
```

### 4.4 Structured Logging

The application uses Logback with PAN masking (`PanMaskingTurboFilter`). For production,
output JSON logs for ingestion by CloudWatch Logs / ELK / Datadog:

```xml
<!-- logback-spring.xml -->
<springProfile name="production">
  <appender name="JSON" class="ch.qos.logback.core.ConsoleAppender">
    <encoder class="net.logstash.logback.encoder.LogstashEncoder"/>
  </appender>
  <root level="WARN">
    <appender-ref ref="JSON"/>
  </root>
</springProfile>
```

Add dependency:
```xml
<dependency>
  <groupId>net.logstash.logback</groupId>
  <artifactId>logstash-logback-encoder</artifactId>
  <version>7.4</version>
</dependency>
```

### 4.5 Audit Log Alerting

Query the `token_audit_log` table periodically for tamper events:

```sql
-- Run as a CloudWatch metric filter or scheduled job
SELECT COUNT(*) FROM token_audit_log
WHERE event_type = 'TAMPER_ALERT'
  AND created_at > NOW() - INTERVAL '1 hour';
```

Alert if count > 0 with severity CRITICAL.

---

## 5. JWT Authentication Setup (Phase 2)

The current `SecurityConfig` allows all requests without authentication (`anyRequest().permitAll()`).
Before production deployment, implement JWT validation.

### 5.1 Dependencies

```xml
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>
```

### 5.2 SecurityConfig Changes

```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .csrf(AbstractHttpConfigurer::disable)
        .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
            .requestMatchers("/actuator/health").permitAll()
            .requestMatchers("/actuator/**").hasRole("OPS")
            .anyRequest().authenticated()
        )
        .oauth2ResourceServer(oauth2 -> oauth2
            .jwt(jwt -> jwt.decoder(jwtDecoder()))
        );
    return http.build();
}

@Bean
public JwtDecoder jwtDecoder() {
    return NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
}
```

### 5.3 Extract Merchant ID from JWT

Override any client-supplied `merchantId` with the value from the JWT claim:

```java
@PostMapping
public TokeniseResponse tokenise(
        @Valid @RequestBody TokeniseRequest request,
        @AuthenticationPrincipal Jwt jwt) {
    request.setMerchantId(jwt.getClaimAsString("merchant_id")); // Trust only the JWT
    return tokenisationService.tokenise(request);
}
```

### 5.4 Token Scopes

| Endpoint | Required Scope/Role |
|----------|---------------------|
| `POST /api/v1/tokens` | `tokenise` scope |
| `GET /api/v1/tokens/{token}` | `detokenise` scope |
| `POST /api/v1/admin/keys/rotate` | `ADMIN` role + mTLS |
| `GET /api/v1/health` | none (public) |
| `GET /actuator/**` | `OPS` role, internal network only |

---

## 6. Distributed Rate Limiting (Multi-Node)

The current Caffeine-backed rate limiter is in-memory and single-node. For multi-node
deployments, use Redis-backed counters.

### 6.1 Redis Sliding-Window Rate Limiter

```java
@Component
public class RedisRateLimiter {

    private final StringRedisTemplate redis;

    public boolean isAllowed(String merchantId, int limitPerMinute) {
        String key = "rate:" + merchantId;
        long now = System.currentTimeMillis();
        long windowStart = now - 60_000;

        // Lua script for atomic sliding-window check
        String script = """
            redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[1])
            local count = redis.call('ZCARD', KEYS[1])
            if count < tonumber(ARGV[2]) then
                redis.call('ZADD', KEYS[1], ARGV[3], ARGV[3])
                redis.call('EXPIRE', KEYS[1], 61)
                return 1
            end
            return 0
            """;

        Long result = redis.execute(
            RedisScript.of(script, Long.class),
            List.of(key),
            String.valueOf(windowStart),
            String.valueOf(limitPerMinute),
            String.valueOf(now)
        );
        return Long.valueOf(1).equals(result);
    }
}
```

### 6.2 Resilience4j Alternative

```xml
<dependency>
  <groupId>io.github.resilience4j</groupId>
  <artifactId>resilience4j-spring-boot3</artifactId>
</dependency>
```

```yaml
resilience4j.ratelimiter:
  instances:
    detokenise:
      limitForPeriod: 1000
      limitRefreshPeriod: 1m
      timeoutDuration: 0
```

```java
@RateLimiter(name = "detokenise", fallbackMethod = "rateLimitFallback")
public DetokeniseResponse detokenise(String token, String merchantId) { ... }
```

---

## 7. Incident Response Procedures

### 7.1 Key Compromise

1. Identify the compromised key version UUID from the audit log or security alert.
2. Call the emergency rotation endpoint:
   ```bash
   curl -X POST https://internal-host/api/v1/admin/keys/rotate \
     -H "Content-Type: application/json" \
     -d '{"reason":"COMPROMISE","compromisedKeyVersionId":"<UUID>","newKeyAlias":"emergency-2025-Q1"}'
   ```
3. Verify the old key is immediately marked `COMPROMISED` in `key_versions`.
4. Monitor rotation batch progress:
   ```sql
   SELECT COUNT(*) FROM token_vault WHERE key_version_id = '<old-UUID>' AND is_active = true;
   ```
   This should decrease toward zero as the batch job runs.
5. After rotation completes, verify zero tokens remain on the old key.
6. Notify affected merchants if any detokenisation requests returned errors during the window.
7. File a PCI-DSS incident report if cardholder data exposure cannot be ruled out.

### 7.2 Database Connection Pool Exhaustion

**Symptoms:** HTTP 500 with `HikariPool-1 - Connection is not available, request timed out`

**Immediate steps:**
1. Check HikariCP metrics: `GET /actuator/metrics/hikaricp.connections.active`
2. Check for long-running queries: `SELECT pid, query, query_start FROM pg_stat_activity WHERE state = 'active' ORDER BY query_start;`
3. Kill blocking queries if safe: `SELECT pg_terminate_backend(<pid>);`
4. If the pool is fully saturated, temporarily reduce traffic at the load balancer.

**Root causes:**
- Concurrency exceeds pool size: increase `maximum-pool-size`
- Long-running transactions holding connections: check for missing `@Transactional` boundaries
- Rotation batch overwhelming the pool: reduce `rotation.batch.size`

### 7.3 Health Endpoint Returns DEGRADED

The `/api/v1/health` endpoint returns `DEGRADED` with one or more checks DOWN.

| Check | Cause | Fix |
|-------|-------|-----|
| `database: DOWN` | PostgreSQL unreachable | Check DB host, credentials, firewall |
| `keyRing: DOWN` | No ACTIVE key in DB | Check key_versions table; re-run initialiser |
| `keyRing: DOWN` | Key ring not loaded in memory | Check startup logs for KMS errors; restart |

### 7.4 Tamper Alert in Audit Log

If `event_type = 'TAMPER_ALERT'` appears in `token_audit_log`:

1. **Do not restart the application** — preserve the in-memory state for forensics.
2. Identify which `key_version_id` was flagged.
3. Query `key_versions` to inspect `checksum` and `updated_at`.
4. Compare checksum against a fresh HMAC-SHA256 computation from known-good key fields.
5. If tampering is confirmed:
   - Mark the key `COMPROMISED` via the emergency rotation endpoint.
   - Escalate to the security team and PCI-DSS QSA.
   - Initiate a full audit log review for the affected time window.

---

## 8. Production Environment Variables Reference

| Variable | Required | Description |
|----------|----------|-------------|
| `DATASOURCE_URL` | Yes | `jdbc:postgresql://<host>:<port>/<db>` |
| `DATASOURCE_USER` | Yes | `tokenisation_app` |
| `DATASOURCE_PASSWORD` | Yes | From secrets manager |
| `PAN_HASH_SECRET` | Yes | 32+ byte random string; never reuse across environments |
| `TAMPER_DETECTION_SECRET` | Yes | 32+ byte random string; different from PAN hash secret |
| `KMS_PROVIDER` | Yes | `aws` in production |
| `AWS_REGION` | Yes (if aws) | e.g. `ap-southeast-2` |
| `AWS_KMS_KEY_ARN` | Yes (if aws) | Full ARN of the CMK |
| `KMS_LOCAL_DEV_KEK_HEX` | No | Local dev only; must not be set in production |
| `SSL_KEYSTORE_PATH` | If mTLS at app layer | Path to PKCS12 keystore |
| `SSL_KEYSTORE_PASSWORD` | If mTLS at app layer | From secrets manager |
| `SSL_TRUSTSTORE_PATH` | If mTLS at app layer | Path to PKCS12 truststore |
| `SSL_TRUSTSTORE_PASSWORD` | If mTLS at app layer | From secrets manager |

### Startup Validation

The application will **fail to start** (intentionally) if any of these are missing or invalid:

- `DATASOURCE_URL`, `DATASOURCE_USER`, `DATASOURCE_PASSWORD` — Flyway and HikariCP will throw
- `PAN_HASH_SECRET` — Spring will throw on unresolved property placeholder
- `TAMPER_DETECTION_SECRET` — Same as above
- `KMS_LOCAL_DEV_KEK_HEX` when `KMS_PROVIDER=local-dev` — No fallback (removed in §1.1)
- KMS unreachable at startup — `KeyRingInitialiser` throws and stops context load
- No `ACTIVE` key version in `key_versions` — `KeyRingInitialiser` throws

This fail-fast behaviour is intentional. A partially initialised tokenisation service that
accepts requests but cannot encrypt or decrypt is more dangerous than one that refuses to start.
