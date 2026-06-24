# Feature 03 — Vault Simplification & Token Lifecycle

## Context

Through design review, two concepts in the original implementation were identified as
over-engineered for the actual use case:

**`token_type` (ONE_TIME / RECURRING):** The vault's purpose is to store a PAN and return
a stable, opaque token. Every caller wants the same thing — a consistent handle for a card.
The RECURRING de-dup behaviour is correct and should always apply. ONE_TIME served no purpose
in a single-tenant internal vault; it inflated the vault with duplicate PAN entries and the
name implied single-use enforcement that was never implemented.

**`merchant_id`:** Merchant scoping was designed for a multi-tenant vault shared by multiple
independent merchants. This bank has one operator, one Mastercard integration, and no need for
cross-tenant isolation. The field added dead weight to every API call, every DB row, and every test.

Additionally, two correctness gaps were identified:
- `expires_at` was stored on every token but never checked during detokenisation — expired
  tokens remained usable indefinitely.
- No revocation endpoint existed — a card reported lost or stolen could not be invalidated
  via the API.

**Intended outcome:** A simpler, more honest API surface. One PAN always maps to one active
token. No tenant scoping. Token lifecycle (expiry + revocation) is actually enforced. Card
scheme input is validated against a configurable allowlist.

---

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| Remove `token_type` entirely | Vault always de-duplicates — one PAN → one active token |
| Remove `merchant_id` entirely | Single-tenant vault; no cross-tenant isolation needed |
| Keep `card_scheme`, add allowlist validation | Display metadata is useful; free-text acceptance is not |
| Enforce `expires_at` on detokenise | Stored but ignored — needs to actually gate access |
| Add `DELETE /api/v1/tokens/{token}` | Card-loss/fraud revocation is an operational necessity |
| Add `TOKEN_REVOKED` audit event | Every lifecycle change must be in the audit trail |
| Unique partial index on `pan_hash` WHERE `is_active = TRUE` | DB-level guarantee: one active token per PAN |

---

## New Flyway Migration — V5

`src/main/resources/db/migration/V7__simplify_token_vault.sql`

Drops `token_type` and `merchant_id` from `token_vault`, drops `merchant_id` from
`token_audit_log`, removes the old partial index on RECURRING tokens, and adds a unique
partial index enforcing one active token per PAN.

---

## API Surface After Feature 03

```
POST   /api/v1/tokens
{
  "pan": "5123456789012346",
  "cardScheme": "MC",
  "expiryMonth": 12,
  "expiryYear": 2027
}
→ 201 { "token": "uuid", "lastFour": "2346", "cardScheme": "MC", "createdAt": "..." }

GET    /api/v1/tokens/{token}
→ 200 { "pan": "5123456789012346", "expiryMonth": 12, "expiryYear": 2027, "cardScheme": "MC", "lastFour": "2346" }

DELETE /api/v1/tokens/{token}
→ 204 (token deactivated — subsequent GET returns 404)
```

Removed from POST request: `tokenType`, `merchantId`.
Removed from GET request: `X-Merchant-ID` header.
Removed from all responses: `tokenType` field.

---

## Card Scheme Validation

Card scheme is validated against a configurable allowlist in `application.yml`:

```yaml
tokenisation:
  allowed-card-schemes:
    - MC
```

Callers sending an unlisted scheme (e.g. `BANANA`, `VISA`) receive HTTP 400.
Adding a new scheme in future requires only a config change — no code change.

New classes: `TokenisationProperties`, `ValidCardScheme` (annotation), `CardSchemeValidator`.

---

## Token Expiry Enforcement

`DetokenisationService` now checks `expires_at` after the `isActive` check:

```java
if (vault.getExpiresAt() != null && Instant.now().isAfter(vault.getExpiresAt())) {
    throw new TokenNotFoundException(token);
}
```

Expired tokens return HTTP 404 — same response as inactive tokens (no information leakage).

---

## Token Revocation

`TokenisationService.revokeToken(String token)`:
1. Look up vault by token value — throws `TokenNotFoundException` if absent or already inactive
2. Call `vault.deactivate()` (sets `is_active = false`)
3. Save
4. Write `TOKEN_REVOKED` success audit record

`TokenController` exposes `DELETE /api/v1/tokens/{token}` returning HTTP 204.

---

## Files Deleted

| File | Reason |
|------|--------|
| `domain/TokenType.java` | Enum no longer needed |
| `exception/MerchantScopeException.java` | No merchant scope check |
| `bruno/.../tokenise-one-time.bru` | ONE_TIME type removed |
| `bruno/.../detokenise-wrong-merchant.bru` | Merchant concept removed |
| `bruno/.../detokenise-missing-merchant-header.bru` | Merchant concept removed |
| `bruno/.../tokenise-validation-missing-merchant.bru` | Merchant concept removed |

---

## Verification

```bash
# 1. Full unit + integration suite
mvn test
# Expected: BUILD SUCCESS — key tests:
#   TokenisationServiceTest     — de-dup, revocation
#   DetokenisationServiceTest   — expiry enforcement
#   TokenisationIntegrationTest — invalid scheme 400, revocation 204→404
#   DetokenisationIntegrationTest — expired token 404
#   RotationBatchProcessorTest  — no regressions

# 2. Compile gate — confirm no lingering TokenType/merchantId/MerchantScopeException references
mvn compile

# 3. Load test regression
mvn test -P load-tests -Dtest="KeyRotationUnderLoadTest"

# 4. Manual API smoke (Bruno or curl)
# POST /api/v1/tokens  (no tokenType, no merchantId)  → 201
# GET  /api/v1/tokens/{token}                          → 200 with PAN
# DELETE /api/v1/tokens/{token}                        → 204
# GET  /api/v1/tokens/{token}  (after delete)          → 404
# POST with cardScheme: "BANANA"                       → 400
```
