# Pre-Production Hardening Checklist

This document covers each task in the **Pre-Production Hardening** phase (PP-1 through PP-6) — what it requires, why it matters, and how to verify it.

---

## PP-1 — Database Role Restrictions

**Status:** Migration written (`V6__setup_db_roles.sql`). Integration test written (`DbRoleRestrictionTest`).

### What was done

`V6__setup_db_roles.sql` creates the `tokenisation_app` role and grants it the minimum necessary privileges on each table:

| Table               | SELECT | INSERT | UPDATE | DELETE |
|---------------------|--------|--------|--------|--------|
| `key_versions`      | ✅     | ✅     | ✅     | ❌     |
| `token_vault`       | ✅     | ✅     | ✅     | ✅     |
| `token_audit_log`   | ✅     | ✅     | ❌     | ❌     |

The audit log is **append-only at the database level** — the application role can never UPDATE or DELETE a written record. This provides an independent integrity guarantee beyond the application layer.

### How to verify

```bash
# Run the privilege assertion test
JAVA_HOME=/opt/homebrew/opt/openjdk@21 mvn test -pl . -Dtest=DbRoleRestrictionTest
```

### Production steps

1. The migration runs automatically via Flyway on startup.
2. In production, the connection user must be `tokenisation_app` (not the migration superuser).
3. Set `DATASOURCE_USER=tokenisation_app` in your deployment secrets.
4. **Never** use the superuser for the application datasource in production.

---

## PP-2 — AWS KMS IAM Role Verification

**Status:** Not yet verified. Requires AWS sandbox access.

### What to do

1. Create an IAM role `tokenisation-app-role` with the following policy:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": ["kms:GenerateDataKey", "kms:Decrypt", "kms:DescribeKey"],
         "Resource": "arn:aws:kms:<region>:<account>:key/<key-id>"
       }
     ]
   }
   ```

2. Attach the role to your EC2 instance / ECS task / Lambda. **Do not use access keys.**

3. Set environment variables:
   ```
   KMS_PROVIDER=aws
   AWS_REGION=ap-southeast-2
   AWS_KMS_KEY_ARN=arn:aws:kms:...
   ```

4. Start the application and verify it reaches `KeyRingInitialiser.run()` without error in the logs.

5. Perform a single tokenise request and verify the token is stored in the DB.

### Why IAM roles, not access keys

Access keys are long-lived credentials that can be leaked. IAM roles are granted to the compute resource itself — they cannot be extracted from the environment and used elsewhere. This is required for PCI-DSS compliance.

---

## PP-3 — mTLS Configuration

**Status:** Application-layer security is configured (Spring Security). mTLS is an infrastructure concern.

### What to configure

mTLS (mutual TLS) means the server verifies the client certificate as well as the client verifying the server. For a PCI-DSS tokenisation vault, this prevents:
- Rogue services calling the tokenisation API without a certificate
- Token interception by a man-in-the-middle

### Recommended approach (AWS / Kubernetes)

Apply mTLS at the ingress/load-balancer layer, not in the Spring Boot application:

1. **AWS ALB** — Enable mutual TLS authentication on the listener:
   ```
   aws elbv2 create-listener --mutual-authentication Mode=verify,TrustStoreArn=<arn>
   ```

2. **Kubernetes / Istio** — Add a `PeerAuthentication` policy:
   ```yaml
   apiVersion: security.istio.io/v1beta1
   kind: PeerAuthentication
   metadata:
     name: card-tokenisation-mtls
   spec:
     mtls:
       mode: STRICT
   ```

3. **Client certificates** — Each merchant integration must present a valid certificate signed by your CA. Revoke on compromise.

### Spring Boot (if enforcing at app layer)

If you must enforce mTLS in Spring Boot (without an infrastructure layer):

```yaml
server:
  ssl:
    enabled: true
    key-store: classpath:keystore.p12
    key-store-password: ${SSL_KEYSTORE_PASSWORD}
    key-store-type: PKCS12
    client-auth: need
    trust-store: classpath:truststore.p12
    trust-store-password: ${SSL_TRUSTSTORE_PASSWORD}
```

---

## PP-4 — Key TTL Refresh Job

**Status:** Configurable TTL field exists (`kms.key-ring.ttl-hours`). The refresh job is not yet implemented.

### What to implement

Add an `@Scheduled` job that re-fetches the KEK from KMS after the configured TTL expires. This limits the window in which a stolen in-memory KEK can be used after the corresponding KMS key is disabled.

```java
@Scheduled(fixedDelayString = "${kms.key-ring.ttl-refresh-delay-ms:3600000}")
public void refreshExpiredKeys() {
    keyVersionRepository.findByStatusIn(List.of(KeyStatus.ACTIVE, KeyStatus.ROTATING))
        .stream()
        .filter(kv -> keyRing.getByVersion(kv.getId().toString()).isExpired())
        .forEach(kv -> {
            byte[] freshKek = kmsProvider.unwrapKek(kv.getEncryptedKekBlob());
            try {
                keyRing.load(kv.getId().toString(), freshKek, kv.getRotateBy());
            } finally {
                Arrays.fill(freshKek, (byte) 0);
            }
        });
}
```

Add `isExpired()` to `KeyMaterial`:
```java
public boolean isExpired() {
    return Instant.now().isAfter(expiresAt);
}
```

### Testing

Write a unit test that mocks `KmsProvider` and verifies the job calls `unwrapKek()` only for expired entries.

---

## PP-5 — Runbook: Emergency Rotation Procedure

See [`key-rotation-runbook.md`](./key-rotation-runbook.md) for the full procedure.

**Quick reference:**

1. Identify the compromised key version UUID from the audit log or monitoring alert.
2. Call `POST /api/v1/admin/keys/rotate` with `reason=COMPROMISE` and the UUID.
3. Verify HTTP 202 is returned.
4. Monitor batch progress via `GET /api/v1/metrics` (tokenise/detokenise counts stabilize when re-encryption completes).
5. Verify the old key is RETIRED in `key_versions` and zero tokens remain on it.
6. Notify affected merchants if token access was disrupted during re-encryption.

---

## PP-6 — Runbook: Startup Failure When KMS Unreachable

### Symptoms

```
ERROR KeyRingInitialiser - KMS is unreachable at startup. Cannot load KEK.
Application context failed to start.
```

### Cause

`KeyRingInitialiser.run()` calls `kmsProvider.unwrapKek()` which makes a network call to AWS KMS (or the configured provider). If the call fails (network partition, IAM permission revoked, KMS endpoint down), the `ApplicationRunner` throws and Spring shuts down the context.

This is intentional — the application **must not start** if it cannot load the KEK, because it would be unable to decrypt any token DEK.

### Diagnosis steps

1. **Check IAM role** — Verify the EC2/ECS role has `kms:Decrypt` permission on the CMK ARN.
   ```bash
   aws sts get-caller-identity
   aws kms describe-key --key-id <ARN>
   ```

2. **Check network** — Verify the compute node can reach the KMS VPC endpoint or public endpoint.
   ```bash
   curl https://kms.ap-southeast-2.amazonaws.com
   ```

3. **Check CMK status** — Ensure the CMK is enabled (not pending deletion or disabled).
   ```bash
   aws kms get-key-rotation-status --key-id <ARN>
   ```

4. **Check encrypted KEK blob** — Verify the `encrypted_kek_blob` in `key_versions` is intact (matches the expected ciphertext format).

### Recovery

Once the KMS issue is resolved, restart the application. The `KeyRingInitialiser` will retry on the next startup.

If the CMK was rotated outside of the application's key rotation process, you will need to re-wrap the DEKs:
1. Decrypt all `encrypted_kek_blob` values using the old CMK.
2. Re-encrypt them with the new CMK.
3. Update `key_versions` rows.
4. Restart the application.

### Prevention

- Enable `kms.key-ring.ttl-hours` (PP-4) to re-fetch the KEK periodically rather than only at startup.
- Configure CloudWatch alarms on CMK usage anomalies.
- Use AWS KMS multi-region keys to survive regional outages.
