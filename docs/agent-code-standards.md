# Code Standards — Read When Writing Any Production Class

---

## Naming

- Classes — nouns (`AesGcmCipher`, not `AesGcmEncryptorHelper`)
- Methods — verbs (`tokenise`, `unwrapDek`, `assertIntegrity`)
- Variables — full words, no abbreviations (`encryptedDataKey` not `encDek`)
- Booleans — `isActive`, `hasExpired`, `canDetokenise`
- Constants — `UPPER_SNAKE_CASE` as `static final`; never inline literals

## Methods

- One level of abstraction — orchestrates OR does detail work, never both
- Max 20 lines; if longer, extract and add an inline comment explaining why
- Max 3 parameters; beyond that, introduce a parameter object
- No boolean flag parameters — split into two methods or use an enum
- Guard clauses at the top; happy path last

```java
// Wrong — nested, happy path buried
public TokeniseResponse tokenise(TokeniseRequest request) {
    if (request != null) {
        if (request.getPan() != null) { /* happy path */ }
    }
    return null;
}

// Correct — guards first
public TokeniseResponse tokenise(TokeniseRequest request) {
    requireNonNull(request, "TokeniseRequest must not be null");
    validateLuhn(request.getPan());   // throws PanValidationException if invalid
    return doTokenise(request);
}
```

## Classes

- Single responsibility — if the name needs "And", "Or", or "Manager" it does too much
- Constructor injection only — all injected fields are `private final`
- No static mutable state
- Max 7 injected dependencies — more means it's orchestrating too much

## Immutability

- Domain objects (`TokenVault`, `KeyVersion`) are immutable after construction — use `@Value` or `record`
- Collections returned from methods are unmodifiable (`List.copyOf`)
- `KeyMaterial.getKek()` returns a copy, never the original array

## Error Handling

- Use the domain exception hierarchy (`docs/card-tokenisation-plan.md §13.3`) — never throw raw `RuntimeException`
- Never catch and swallow — every `catch` either rethrows, wraps, or has an explicit comment
- Never include PAN in exception messages — use token IDs or redacted hints only
- Log-then-throw or throw — not both; duplicate stack traces waste log space

## Resource Management

- All `byte[]` holding key or PAN bytes are zeroed in `finally`: `Arrays.fill(secret, (byte) 0)`
- All `Cipher`/`SecretKey`/`KeySpec` objects are local to the method — never stored as fields
- All closeables in try-with-resources

---

## Anti-Slop Rules — Banned Patterns

These are the patterns AI most commonly produces. Every one of them is a defect.

### No filler code

```java
// Banned — pointless null check
if (result != null) { return result; }
return null;

// Banned — rethrow adds nothing
catch (SomeException e) { throw new SomeException(e.getMessage()); }

// Banned — log AND throw (duplicate stack trace)
log.error("Error: {}", e.getMessage());
throw e;

// Banned — comment restates the code
// Get the token from the repository
TokenVault token = tokenVaultRepository.findByToken(tokenValue);

// Banned — empty catch
catch (Exception e) { /* ignore */ }
```

### No speculative code

```java
// Banned — abstract base for a hierarchy of one
public abstract class AbstractTokenisationStrategy { }

// Banned — factory for a single implementation
public class TokenisationServiceFactory {
    public TokenisationService create(String type) { return new TokenisationServiceImpl(); }
}

// Banned — unused parameter "just in case"
public EncryptResult encrypt(byte[] plaintext, byte[] kek, Map<String, String> futureContext) { }
```

Write the abstraction only if `docs/card-tokenisation-plan.md` anticipates it (e.g. `KmsProvider`). Otherwise don't.

### No fake robustness

```java
// Banned — null return on failure
public TokenVault findToken(String token) {
    try { return tokenVaultRepository.findByToken(token); }
    catch (Exception e) { return null; }  // caller gets NPE elsewhere
}

// Banned — swallowed exception returned as empty Optional
catch (KeyVersionNotFoundException e) {
    log.warn("Key not found, returning empty");
    return Optional.empty();
}
```

### No generic variable names

```java
// Banned
String result = service.tokenise(request);
byte[] data = cipher.encrypt(pan, kek);
List<TokenVault> list = repo.findAll();

// Required
String surrogateToken = service.tokenise(request);
byte[] encryptedPan = cipher.encrypt(panBytes, keyEncryptionKey);
List<TokenVault> expiredTokens = repo.findAllExpiredBefore(cutoff);
```

### No meaningless comments

```java
// Banned — restates code
// Encrypt the PAN
byte[] encryptedPan = cipher.encrypt(panBytes, kek);

// Required — explains a decision
// A fresh DEK per tokenisation ensures compromise of one token's DEK does not affect others.
byte[] dek = generateFreshDek();

// Required — explains a constraint
// GCM tag verification happens implicitly in doFinal(). Do NOT catch AEADBadTagException generically.
byte[] plaintext = cipher.doFinal(ciphertext);
```

---

## Javadoc — Required on Every Public Class and Method

```java
/**
 * Encrypts a PAN using AES-256-GCM with a freshly generated Data Encryption Key (DEK).
 *
 * <p>A new random 96-bit IV is generated per invocation. The DEK is zeroed immediately
 * after use in a {@code finally} block regardless of outcome.
 *
 * @param pan  the raw PAN bytes; must not be null or empty
 * @param kek  the Key Encryption Key; must be exactly 32 bytes (AES-256)
 * @return     {@link EncryptResult} containing ciphertext, IV, auth tag, and wrapped DEK —
 *             all fields are safe to persist
 * @throws IllegalArgumentException  if {@code pan} is null/empty or {@code kek} is not 32 bytes
 * @throws EncryptionException       if the JCE operation fails
 */
public EncryptResult encrypt(byte[] pan, byte[] kek) { ... }
```

Javadoc answers: **what** it does, **why** any non-obvious decision was made, and documents every parameter, return value, and thrown exception.

---

## Self-Check Before Submitting Code

```
[ ] Every public class and method has Javadoc
[ ] No method exceeds 20 lines (or has an explanatory comment)
[ ] No more than 3 parameters (or uses a parameter object)
[ ] All variables are intention-revealing — no abbreviations
[ ] No inline magic strings or numbers
[ ] Constructor injection used — no @Autowired on fields
[ ] Guard clauses at top, happy path last
[ ] No banned anti-slop patterns present (check each category above)
[ ] No PAN in any log statement
[ ] DEK byte arrays zeroed in finally blocks
[ ] No key material in exception messages
[ ] IVs generated fresh per encryption operation
```
