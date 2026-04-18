# Test Standards — Read When Writing Any Test

---

## Core Rules

- Testing is part of implementation — not after. Code without tests is not finished.
- For service/business logic: write the test first, confirm it fails, then implement.
- For infrastructure (adapters, filters): tests written alongside.
- One test class per production class — named `<ClassName>Test` (unit) or `<Feature>IntegrationTest` (integration).

---

## Unit Tests

- `@ExtendWith(MockitoExtension.class)` — no Spring context, no DB
- Mock all collaborators with `@Mock` — never use real implementations except pure value objects
- Every public method needs tests for: happy path, every documented `@throws`, null inputs, boundary values
- Naming: `methodName_condition_expectedBehaviour`
- No `if`, `for`, `while`, `switch` inside test methods — one scenario per test
- Use `@ParameterizedTest` for input variation
- Use AssertJ (`assertThat`) — not JUnit `assertEquals`

```java
// Correct naming and assertion
@Test
void tokenise_recurringPan_returnsSameTokenOnSubsequentCall() {
    TokeniseResponse first = service.tokenise(recurringRequest);
    TokeniseResponse second = service.tokenise(recurringRequest);

    assertThat(first.getToken()).isEqualTo(second.getToken());
    assertThat(tokenVaultRepository.countByPanHash(panHash)).isEqualTo(1);
}

// Banned — no meaningful assertion
@Test
void tokenise_returnsResponse() {
    TokeniseResponse response = service.tokenise(validRequest);
    assertNotNull(response);  // proves nothing
}

// Banned — no assertion at all
@Test
void encrypt_doesNotThrow() {
    assertDoesNotThrow(() -> cipher.encrypt(panBytes, kek));
}

// Required — assert the actual output
@Test
void encrypt_producesUniqueCiphertextOnRepeatedCalls() {
    byte[] first = cipher.encrypt(panBytes, kek).ciphertext();
    byte[] second = cipher.encrypt(panBytes, kek).ciphertext();
    assertThat(first).isNotEqualTo(second);
}
```

---

## Integration Tests

- Extend `AbstractIntegrationTest` — real PostgreSQL via Testcontainers, `LocalDevKmsAdapter`
- Test the full stack: HTTP request → service → DB → response
- Assert DB state directly after operations — use `JdbcTemplate` or the repository
- Assert audit log records were written with correct event type and outcome
- Never mock the database or crypto layer in integration tests

```java
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
public abstract class AbstractIntegrationTest {

    @Container
    static final PostgreSQLContainer<?> postgres =
        new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("tokenisation_test")
            .withUsername("test").withPassword("test")
            .withReuse(true);

    @DynamicPropertySource
    static void overrideProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("kms.provider", () -> "local-dev");
    }
}
```

---

## Mandatory Security Tests

These three tests must exist before any phase closes. They are not optional.

```java
// 1. PAN never in logs
// Attach ListAppender to root Logback logger; tokenise + detokenise; assert no event contains PAN
@Test void panNeverAppearsInAnyLogOutput() { ... }

// 2. GCM tamper detection
// Tokenise; corrupt one byte of encrypted_pan in DB via JdbcTemplate;
// detokenise; assert HTTP 500 and TAMPER_ALERT in audit_log
@Test void detokenise_tamperedCiphertext_triggersTamperAlert() { ... }

// 3. Cross-merchant isolation
// Tokenise under MERCHANT_A; detokenise with MERCHANT_B;
// assert 403 and MERCHANT_SCOPE_VIOLATION in audit_log
@Test void detokenise_wrongMerchant_returns403AndAudits() { ... }
```

---

## Coverage Gate

| Scope | Minimum line coverage |
|---|---|
| Overall bundle | 85% |
| Service layer | 90% |
| Crypto layer | 95% |

JaCoCo enforces this — build fails below threshold. Do not suppress or exclude classes to hit the number.

---

## Load Tests

Load tests are a **quality gate**, not optional. They run under `-P load-tests` Maven profile, tagged `@Tag("load")`, excluded from standard `mvn test`.

**When to run:** before closing a phase, after any crypto/service/schema change, before any release.

### AbstractLoadTest

```java
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("load-test")
@Tag("load")
public abstract class AbstractLoadTest {

    @Container
    static final PostgreSQLContainer<?> postgres =
        new PostgreSQLContainer<>("postgres:16-alpine")
            .withCommand("postgres",
                "-c", "shared_buffers=256MB",
                "-c", "max_connections=200",
                "-c", "synchronous_commit=off");   // load test ONLY — never in production
    // captureMetrics(), awaitCompletion(), buildVirtualThreadExecutor() — see plan §10.4
}
```

### Load Test Thresholds

Full thresholds are in `docs/card-tokenisation-plan.md §10.5`. Summary:

| Scenario | 1K | 5K | 10K | 20K | 50K |
|---|---|---|---|---|---|
| Tokenise p99 | ≤500ms | ≤600ms | ≤700ms | ≤800ms | ≤1000ms |
| Detokenise p99 | ≤400ms | ≤500ms | ≤600ms | ≤700ms | ≤900ms |
| Mixed p99 | ≤600ms | ≤700ms | ≤800ms | ≤900ms | ≤1200ms |
| Error rate | **0%** | **0%** | **0%** | **0%** | **0%** |

Error rate is always **0%**. A single unexpected 5xx fails the test.

### Rotation Under Load

- 10K pre-seeded tokens; rotation runs while live traffic flows
- Throughput degradation during rotation ≤ 20%
- Zero errors on live traffic during rotation
- Zero tokens remain on old key after rotation completes
- All pre-rotation tokens detokenisable after rotation

### Tampered Key Under Load

- DB-level key tamper committed mid-load
- `KeyIntegrityException` thrown on next key read
- `TAMPER_ALERT` audit event written within 1s of tamper
- Zero successful detokenisations after tamper committed

### Load Test Result Archival

Every test writes `LoadTestResult` JSON to `target/load-test-results/`. CI fails if p99 increases >15% or heap growth increases >20% vs the previous recorded result for the same scenario.

---

## Self-Check Before Submitting Tests

```
[ ] Test class named correctly (ClassName>Test or <Feature>IntegrationTest)
[ ] No Spring context loaded in unit tests
[ ] Every public method has at least one test
[ ] All documented @throws cases have a test
[ ] No logic (if/for/while) inside test methods
[ ] Assertions use AssertJ assertThat — not assertEquals
[ ] Assertions verify real behaviour, not just assertNotNull
[ ] Integration tests assert DB state, not just response body
[ ] Audit log records asserted where relevant
[ ] The three mandatory security tests exist (PAN in logs, GCM tamper, cross-merchant)
[ ] Load tests run against full stack — no mocks
[ ] Load test result written to target/load-test-results/
```
