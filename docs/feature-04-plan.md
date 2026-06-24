# Feature 04 — Card Replacement (Token Re-binding)

## Context

When a customer's card is replaced — due to loss, theft, renewal, or upgrade — the replacement card carries a different PAN. Downstream systems (core banking, mobile app, billing) hold the **old token** as the stable reference for that customer's payment instrument.

Two approaches are possible:

| Approach | Token fate | Downstream impact |
|----------|-----------|-------------------|
| Revoke + re-tokenise | New token issued | Every system must be updated |
| **Token re-binding** | **Token value unchanged** | **Zero downstream changes** |

Token re-binding is the correct approach for a bank vault. The token is the stable identifier for the customer's payment instrument — when the physical card changes, the logical reference must remain stable. This mirrors card-on-file update services (Visa Account Updater, Mastercard MATCH).

**Intended outcome:** `PATCH /api/v1/tokens/{token}` replaces all PAN-related fields in the vault record while keeping the token value, token ID, and creation timestamp unchanged.

---

## API

```
PATCH /api/v1/tokens/{token}
Content-Type: application/json

{
  "pan": "5105105105105100",
  "cardScheme": "MC",
  "expiryMonth": 6,
  "expiryYear": 2029
}

→ 200 { "token": "uuid", "lastFour": "5100", "cardScheme": "MC", "createdAt": "..." }
→ 404  token not found or inactive
→ 409  new PAN already has a different active token in the vault
→ 400  invalid PAN (Luhn failure, format, unsupported scheme)
```

---

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| New DEK via `cipher.encrypt()` | Fresh DEK + fresh IV per replacement — reusing the same DEK across different PAN data is a security anti-pattern |
| Update `keyVersion` to active key | Card replacement migrates the token to the current key version as a side effect |
| 409 if new PAN has a different active token | Enforces one-PAN-one-token invariant |
| Allow same-PAN replacement | Re-encrypting the same PAN is harmless; supports operational re-keying |
| Update `expiresAt` to `now + defaultTokenTtlDays` | New card = fresh TTL |
| `CARD_REPLACED` audit event | Every PAN change is traceable in the audit log |

---

## No Database Migration Required

The DB schema columns (`pan_hash`, `last_four`, `card_scheme`, `expiry_month`, `expiry_year`) carry no update-blocking constraints at the PostgreSQL level. The `updatable = false` constraint exists only in JPA. Removing it from the entity is sufficient.

---

## Files Changed

### New
- `api/request/CardReplacementRequest.java` — PATCH body DTO
- `exception/CardAlreadyTokenisedException.java` — thrown on 409 conflict

### Modified
- `domain/TokenVault.java` — remove `updatable=false` from PAN metadata fields; add `replacePanFields()` mutator
- `audit/AuditEventType.java` — add `CARD_REPLACED`
- `service/TokenisationService.java` — add `replaceCard()` method
- `api/TokenController.java` — add `PATCH /{token}` endpoint
- `api/GlobalExceptionHandler.java` — handle `CardAlreadyTokenisedException` → 409

### Bruno
- Remove stale `merchantId` from `environments/local.bru`
- Add `tokens/token-revoke.bru` and `tokens/token-revoke-not-found.bru` (Feature 03 gap)
- Add `tokens/token-replace-card.bru`, `tokens/token-replace-card-conflict.bru`, `tokens/token-replace-card-not-found.bru`

---

## Verification

```bash
# Unit tests
JAVA_HOME=/opt/homebrew/opt/openjdk@21 mvn test -Dtest="TokenisationServiceTest"

# Full suite
JAVA_HOME=/opt/homebrew/opt/openjdk@21 mvn test

# Manual smoke (requires: make start)
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/tokens \
  -H "Content-Type: application/json" \
  -d '{"pan":"5500005555555559","cardScheme":"MC","expiryMonth":12,"expiryYear":2027}' \
  | jq -r '.token')

# Replace card
curl -X PATCH http://localhost:8080/api/v1/tokens/$TOKEN \
  -H "Content-Type: application/json" \
  -d '{"pan":"5105105105105100","cardScheme":"MC","expiryMonth":6,"expiryYear":2029}'
# → 200, lastFour=5100

# Detokenise — returns new PAN
curl http://localhost:8080/api/v1/tokens/$TOKEN
# → pan=5105105105105100

# Conflict — original PAN now has its own token; can't rebind to it
curl -X PATCH http://localhost:8080/api/v1/tokens/$TOKEN \
  -H "Content-Type: application/json" \
  -d '{"pan":"5500005555555559","cardScheme":"MC","expiryMonth":12,"expiryYear":2027}'
# → 409
```
