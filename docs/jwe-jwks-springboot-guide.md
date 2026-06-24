# JWE/JWKS Encryption Guide for Spring Boot

This guide explains how to generate an RSA key pair, publish the public key as JWKS through `serviceCommon`, and use the private key in `serviceB` to decrypt encrypted data sent by `serviceA`.

## 1. Architecture Overview

```text
serviceB
  Owns the RSA private key
  Uses the private key to decrypt messages

serviceCommon
  Publishes the public key as JWKS
  Does not expose the private key

serviceA
  Calls serviceCommon JWKS endpoint
  Uses serviceB's public key to encrypt sensitive data
  Sends encrypted payload to serviceB over HTTPS
```

Important rule:

```text
Only serviceB should have the private key.
serviceCommon should expose only the public key.
serviceA should only use the public JWKS.
```

HTTPS still protects the transport layer. JWE protects the sensitive field or message itself, even if logs, traces, proxies, or queues accidentally capture the payload.

---

## 2. Generate RSA Key Pair

Use OpenSSL.

### Option A: Generate PKCS#8 Private Key Directly

This format works well with Java.

```bash
openssl genpkey \
  -algorithm RSA \
  -out serviceb-private.pem \
  -pkeyopt rsa_keygen_bits:4096
```

This creates:

```text
serviceb-private.pem
```

Example header:

```text
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
```

This is the private key. Keep it secret.

---

## 3. Extract Public Key from Private Key

```bash
openssl rsa \
  -in serviceb-private.pem \
  -pubout \
  -out serviceb-public.pem
```

This creates:

```text
serviceb-public.pem
```

Example header:

```text
-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----
```

This public key can be shared with `serviceCommon`.

---

## 4. Verify the Key Pair

Check the private key:

```bash
openssl rsa \
  -in serviceb-private.pem \
  -check \
  -noout
```

Check the public key:

```bash
openssl rsa \
  -pubin \
  -in serviceb-public.pem \
  -text \
  -noout
```

---

## 5. Convert Public Key to JWKS

Install `node-jose-tools`:

```bash
npm install -g node-jose-tools
```

Convert the public PEM to JWK:

```bash
jose jwk:from-pem serviceb-public.pem \
  --kid serviceb-key-2026-06 \
  --use enc \
  --alg RSA-OAEP-256
```

This outputs a JWK similar to this:

```json
{
  "kty": "RSA",
  "kid": "serviceb-key-2026-06",
  "use": "enc",
  "alg": "RSA-OAEP-256",
  "n": "...",
  "e": "AQAB"
}
```

Wrap it inside a JWKS document:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "serviceb-key-2026-06",
      "use": "enc",
      "alg": "RSA-OAEP-256",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

`serviceCommon` should expose this at an endpoint like:

```text
GET https://service-common/.well-known/jwks.json
```

Never include the private key in JWKS.

---

## 6. Where to Put the Private Key in Spring Boot

Do not put this into an SSL bundle.

SSL bundles are for TLS/mTLS certificates:

```text
HTTPS certificates
mTLS keystore
mTLS truststore
```

JWE keys are application-level encryption keys:

```text
JWKS
JWE
RSA key pair
payload encryption/decryption
```

Recommended places for `serviceb-private.pem`:

```text
HashiCorp Vault
AWS Secrets Manager
Kubernetes Secret
OpenShift Secret
Mounted secret file
```

For local development, you can use:

```text
src/main/resources/keys/serviceb-private.pem
```

For production, prefer a mounted file such as:

```text
/opt/secrets/serviceb-private.pem
```

---

## 7. Maven Dependency

Use Nimbus JOSE + JWT:

```xml
<dependency>
    <groupId>com.nimbusds</groupId>
    <artifactId>nimbus-jose-jwt</artifactId>
    <version>10.5</version>
</dependency>
```

---

## 8. Spring Boot Configuration

`application.yml`:

```yaml
crypto:
  private-key-location: /opt/secrets/serviceb-private.pem
  jwks-url: https://service-common/.well-known/jwks.json
  encryption-kid: serviceb-key-2026-06
```

For local development:

```yaml
crypto:
  private-key-location: src/main/resources/keys/serviceb-private.pem
  jwks-url: http://localhost:8081/.well-known/jwks.json
  encryption-kid: serviceb-key-2026-06
```

---

## 9. Configuration Properties

```java
package com.example.crypto;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "crypto")
public record CryptoProperties(
    String privateKeyLocation,
    String jwksUrl,
    String encryptionKid
) {
}
```

Enable it:

```java
package com.example.crypto;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(CryptoProperties.class)
public class CryptoPropertiesConfiguration {
}
```

---

## 10. Load Private Key in ServiceB

```java
package com.example.crypto;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class PrivateKeyConfiguration {

    @Bean
    public RSAPrivateKey rsaPrivateKey(CryptoProperties properties) throws Exception {
        String pem = Files.readString(Path.of(properties.privateKeyLocation()));

        String privateKeyContent = pem
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replaceAll("\\s+", "");

        byte[] decoded = Base64.getDecoder().decode(privateKeyContent);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }
}
```

Note: this expects a PKCS#8 private key with this header:

```text
-----BEGIN PRIVATE KEY-----
```

If your key has this header:

```text
-----BEGIN RSA PRIVATE KEY-----
```

convert it to PKCS#8:

```bash
openssl pkcs8 \
  -topk8 \
  -inform PEM \
  -outform PEM \
  -nocrypt \
  -in serviceb-rsa-private.pem \
  -out serviceb-private.pem
```

---

## 11. ServiceB: Decrypt a JWE String

```java
package com.example.crypto;

import java.security.interfaces.RSAPrivateKey;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;
import org.springframework.stereotype.Service;

@Service
public class JweDecryptionService {

    private final RSAPrivateKey privateKey;

    public JweDecryptionService(RSAPrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public String decrypt(String jweString) {
        try {
            JWEObject jweObject = JWEObject.parse(jweString);
            jweObject.decrypt(new RSADecrypter(privateKey));
            return jweObject.getPayload().toString();
        } catch (Exception ex) {
            throw new IllegalArgumentException("Failed to decrypt JWE payload", ex);
        }
    }
}
```

---

## 12. ServiceCommon: Sample JWKS Controller

If `serviceCommon` is responsible for exposing the JWKS, it can serve the public JWKS like this.

```java
package com.example.servicecommon;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwksController {

    @GetMapping(
        value = "/.well-known/jwks.json",
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public String jwks() {
        return """
            {
              "keys": [
                {
                  "kty": "RSA",
                  "kid": "serviceb-key-2026-06",
                  "use": "enc",
                  "alg": "RSA-OAEP-256",
                  "n": "PUT_PUBLIC_MODULUS_HERE",
                  "e": "AQAB"
                }
              ]
            }
            """;
    }
}
```

In a real service, load this from configuration, database, or a secure key metadata store.

Again: this endpoint should expose public keys only.

---

## 13. ServiceA: Fetch Public JWKS from ServiceCommon

This service fetches the public key from `serviceCommon`, selects the key by `kid`, and encrypts a string into JWE.

```java
package com.example.crypto;

import java.net.URL;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.stereotype.Component;

@Component
public class JwksClient {

    private final CryptoProperties properties;

    public JwksClient(CryptoProperties properties) {
        this.properties = properties;
    }

    public RSAKey getEncryptionKey() {
        try {
            JWKSet jwkSet = JWKSet.load(new URL(properties.jwksUrl()));

            JWK jwk = jwkSet.getKeyByKeyId(properties.encryptionKid());
            if (jwk == null) {
                throw new IllegalStateException(
                    "No JWKS key found for kid: " + properties.encryptionKid()
                );
            }

            if (!(jwk instanceof RSAKey rsaKey)) {
                throw new IllegalStateException("JWKS key is not an RSA key");
            }

            if (!JWEAlgorithm.RSA_OAEP_256.equals(rsaKey.getAlgorithm())) {
                // Optional strict check. You may relax this if serviceCommon does not populate alg.
                throw new IllegalStateException("JWKS key alg must be RSA-OAEP-256");
            }

            return rsaKey;
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to load JWKS from serviceCommon", ex);
        }
    }
}
```

For production, cache the JWKS result instead of calling `serviceCommon` for every request.

---

## 14. ServiceA: Encrypt a String Using Public JWKS

```java
package com.example.crypto;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.stereotype.Service;

@Service
public class JweEncryptionService {

    private final JwksClient jwksClient;
    private final CryptoProperties properties;

    public JweEncryptionService(
        JwksClient jwksClient,
        CryptoProperties properties
    ) {
        this.jwksClient = jwksClient;
        this.properties = properties;
    }

    public String encrypt(String plaintext) {
        try {
            RSAKey rsaPublicKey = jwksClient.getEncryptionKey();

            JWEHeader header = new JWEHeader.Builder(
                JWEAlgorithm.RSA_OAEP_256,
                EncryptionMethod.A256GCM
            )
                .keyID(properties.encryptionKid())
                .contentType("text/plain")
                .build();

            JWEObject jweObject = new JWEObject(
                header,
                new Payload(plaintext)
            );

            jweObject.encrypt(new RSAEncrypter(rsaPublicKey));

            return jweObject.serialize();
        } catch (Exception ex) {
            throw new IllegalArgumentException("Failed to encrypt payload as JWE", ex);
        }
    }
}
```

The result is a compact JWE string, similar to:

```text
eyJraWQiOiJzZXJ2aWNlYi1rZXktMjAyNi0wNiIsImFsZyI6IlJTQS1PQUVQLTI1NiIsImVuYyI6IkEyNTZHQ00ifQ...
```

---

## 15. Request and Controller Example

### Encrypted Request DTO

```java
package com.example.api;

public record EncryptedRequest(
    String encryptedPayload
) {
}
```

### ServiceB Controller That Decrypts

```java
package com.example.api;

import com.example.crypto.JweDecryptionService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SensitiveDataController {

    private final JweDecryptionService decryptionService;

    public SensitiveDataController(JweDecryptionService decryptionService) {
        this.decryptionService = decryptionService;
    }

    @PostMapping("/sensitive-data")
    public ResponseEntity<Void> receive(@RequestBody EncryptedRequest request) {
        String plaintext = decryptionService.decrypt(request.encryptedPayload());

        // Use the plaintext securely.
        // Avoid logging sensitive plaintext.

        return ResponseEntity.ok().build();
    }
}
```

### ServiceA Example That Encrypts Before Sending

```java
package com.example.client;

import com.example.crypto.JweEncryptionService;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

@Service
public class ServiceAClient {

    private final JweEncryptionService encryptionService;
    private final RestClient restClient;

    public ServiceAClient(JweEncryptionService encryptionService, RestClient.Builder builder) {
        this.encryptionService = encryptionService;
        this.restClient = builder
            .baseUrl("https://service-b")
            .build();
    }

    public void sendSensitiveValue(String sensitiveValue) {
        String encryptedPayload = encryptionService.encrypt(sensitiveValue);

        EncryptedRequest request = new EncryptedRequest(encryptedPayload);

        restClient.post()
            .uri("/sensitive-data")
            .body(request)
            .retrieve()
            .toBodilessEntity();
    }

    public record EncryptedRequest(String encryptedPayload) {
    }
}
```

---

## 16. Key Rotation Approach

During rotation, `serviceCommon` can publish multiple public keys:

```json
{
  "keys": [
    {
      "kid": "serviceb-key-2026-06",
      "use": "enc",
      "alg": "RSA-OAEP-256"
    },
    {
      "kid": "serviceb-key-2026-09",
      "use": "enc",
      "alg": "RSA-OAEP-256"
    }
  ]
}
```

Recommended approach:

```text
1. Generate new key pair.
2. Add new public key to serviceCommon JWKS.
3. Deploy serviceB with both old and new private keys.
4. Configure serviceA to encrypt with the new kid.
5. Keep old private key until old messages no longer exist.
6. Remove old public key from JWKS.
7. Remove old private key from serviceB.
```

For multiple private keys, use a key registry:

```java
Map<String, RSAPrivateKey> privateKeysByKid;
```

Then choose the key based on the JWE header:

```java
String kid = jweObject.getHeader().getKeyID();
RSAPrivateKey privateKey = privateKeysByKid.get(kid);
```

---

## 17. Decryption Service with Key Rotation Support

```java
package com.example.crypto;

import java.security.interfaces.RSAPrivateKey;
import java.util.Map;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;
import org.springframework.stereotype.Service;

@Service
public class RotatingJweDecryptionService {

    private final Map<String, RSAPrivateKey> privateKeysByKid;

    public RotatingJweDecryptionService(Map<String, RSAPrivateKey> privateKeysByKid) {
        this.privateKeysByKid = privateKeysByKid;
    }

    public String decrypt(String jweString) {
        try {
            JWEObject jweObject = JWEObject.parse(jweString);
            String kid = jweObject.getHeader().getKeyID();

            RSAPrivateKey privateKey = privateKeysByKid.get(kid);
            if (privateKey == null) {
                throw new IllegalStateException("No private key found for kid: " + kid);
            }

            jweObject.decrypt(new RSADecrypter(privateKey));
            return jweObject.getPayload().toString();
        } catch (Exception ex) {
            throw new IllegalArgumentException("Failed to decrypt JWE payload", ex);
        }
    }
}
```

---

## 18. Important Security Notes

Do not log plaintext sensitive values.

Do not log the private key.

Do not expose the private key from `serviceCommon`.

Do not put JWE private keys into SSL bundles. SSL bundles are for TLS/mTLS, not application payload encryption.

Use JWE rather than custom RSA encryption.

Prefer:

```text
RSA-OAEP-256 + A256GCM
```

Do not use:

```text
RSA1_5
```

Cache JWKS in `serviceA`, but respect rotation.

Keep old private keys in `serviceB` until all messages encrypted with old public keys are gone.

---

## 19. Summary

The clean enterprise setup is:

```text
serviceB
  Owns private key
  Decrypts JWE payload

serviceCommon
  Exposes public JWKS only

serviceA
  Fetches public JWKS
  Encrypts sensitive data as JWE
  Sends encrypted data to serviceB over HTTPS
```

Use:

```text
OpenSSL for key generation
JWKS for public key publishing
Nimbus JOSE + JWT for Java JWE encryption/decryption
Vault/OpenShift Secret/AWS Secrets Manager for private key storage
```
