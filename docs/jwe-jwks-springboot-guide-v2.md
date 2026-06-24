# JWE, JWKS, PEM, PKCS12 and Spring Boot Guide (v2)

## Architecture

```text
ServiceA
  |
  |-- GET JWKS --> ServiceCommon
  |
  |-- Encrypt using ServiceB public key
  |
  +-- HTTPS + JWE ---> ServiceB

ServiceB
  |
  +-- Decrypt using private key
```

HTTPS protects transport.

JWE protects the payload itself.

---

# Key Concepts

## Key Pair

OpenSSL generates:

- Private Key
- Public Key

It does NOT generate:

- kid
- jwk
- jwks
- jwe

Example kid values:

```text
service-b-v1
service-b-v2
service-b-v3
```

---

# Option 1 - PEM

Files:

```text
private.pem
public.pem
```

Pros:

- Simple
- Easy with Vault
- Common for JWKS/JWE

Cons:

- Application must parse PEM

## Generate RSA Key Pair

```bash
openssl genrsa -out private.pem 4096
```

Extract public key:

```bash
openssl rsa \
  -in private.pem \
  -pubout \
  -out public.pem
```

Inspect:

```bash
openssl rsa \
  -in private.pem \
  -text \
  -noout
```

---

# Option 2 - PKCS12 (Recommended for Java)

Files:

```text
service-b.p12
```

Contains:

- Private Key
- Public Key
- Certificate

Pros:

- Native Java support
- Password protected
- Easy with Spring Boot

Cons:

- Slightly more setup

## Create Self-Signed Certificate

```bash
openssl req \
  -new \
  -x509 \
  -key private.pem \
  -out certificate.crt \
  -days 3650
```

## Create PKCS12

```bash
openssl pkcs12 \
  -export \
  -inkey private.pem \
  -in certificate.crt \
  -out service-b.p12 \
  -name service-b
```

Inspect contents:

```bash
openssl pkcs12 \
  -info \
  -in service-b.p12
```

Extract public key:

```bash
openssl pkcs12 \
  -in service-b.p12 \
  -clcerts \
  -nokeys \
  -out public.crt
```

```bash
openssl x509 \
  -pubkey \
  -noout \
  -in public.crt \
  > public.pem
```

Extract private key:

```bash
openssl pkcs12 \
  -in service-b.p12 \
  -nocerts \
  -nodes \
  -out private.pem
```

---

# Publishing JWKS

ServiceCommon exposes:

```text
GET /.well-known/jwks.json
```

Example:

```json
{
  "keys": [
    {
      "kid": "service-b-v1",
      "kty": "RSA",
      "alg": "RSA-OAEP-256",
      "use": "enc",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

Only public keys are published.

Never publish private keys.

---

# Maven Dependency

```xml
<dependency>
    <groupId>com.nimbusds</groupId>
    <artifactId>nimbus-jose-jwt</artifactId>
    <version>10.5</version>
</dependency>
```

---

# ServiceA - Encrypt Using JWKS

```java
JWKSet jwkSet = JWKSet.load(
    URI.create("https://service-common/.well-known/jwks.json").toURL());

RSAKey rsaKey =
    (RSAKey) jwkSet.getKeyByKeyId("service-b-v1");

RSAEncrypter encrypter =
    new RSAEncrypter(rsaKey.toRSAPublicKey());

JWEObject jweObject =
    new JWEObject(
        new JWEHeader.Builder(
            JWEAlgorithm.RSA_OAEP_256,
            EncryptionMethod.A256GCM)
            .keyID(rsaKey.getKeyID())
            .build(),
        new Payload("Sensitive Value"));

jweObject.encrypt(encrypter);

String encryptedPayload =
    jweObject.serialize();
```

---

# ServiceB - Decrypt Using PEM

```java
JWEObject jweObject =
    JWEObject.parse(encryptedPayload);

RSADecrypter decrypter =
    new RSADecrypter(privateKey);

jweObject.decrypt(decrypter);

String plaintext =
    jweObject.getPayload().toString();
```

---

# Load Private Key From PEM

```java
String pem = Files.readString(path);

pem = pem
    .replace("-----BEGIN PRIVATE KEY-----", "")
    .replace("-----END PRIVATE KEY-----", "")
    .replaceAll("\\\\s+", "");

byte[] decoded =
    Base64.getDecoder().decode(pem);

PKCS8EncodedKeySpec spec =
    new PKCS8EncodedKeySpec(decoded);

KeyFactory factory =
    KeyFactory.getInstance("RSA");

RSAPrivateKey privateKey =
    (RSAPrivateKey) factory.generatePrivate(spec);
```

---

# Load Private Key From PKCS12

```java
KeyStore keyStore =
    KeyStore.getInstance("PKCS12");

keyStore.load(
    inputStream,
    password.toCharArray());

RSAPrivateKey privateKey =
    (RSAPrivateKey) keyStore.getKey(
        "service-b",
        password.toCharArray());
```

---

# Key Rotation

Current:

```text
service-b-v1
```

New key:

```text
service-b-v2
```

JWKS can expose both:

```json
{
  "keys": [
    { "kid": "service-b-v1" },
    { "kid": "service-b-v2" }
  ]
}
```

ServiceA starts encrypting with v2.

ServiceB keeps both private keys until old messages expire.

---

# OpenShift

Store:

```text
service-b.p12
```

or

```text
private.pem
```

as Kubernetes Secret.

Mount into:

```text
/opt/secrets
```

Load at application startup.

---

# Vault

Recommended:

```text
Vault
  |
  +-- service-b.p12
```

or

```text
Vault
  |
  +-- private.pem
```

Never commit keys into source control.

---

# Recommended Enterprise Setup

```text
ServiceB
  Private Key -> PKCS12
  Stored in Vault
  Mounted to OpenShift

ServiceCommon
  Publishes JWKS

ServiceA
  Fetches JWKS
  Caches keys
  Encrypts using JWE

ServiceB
  Decrypts using private key
```

Algorithms:

```text
RSA-OAEP-256
A256GCM
```

This is a common enterprise-grade design for sensitive data protection between internal services.
