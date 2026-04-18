# Gradle Migration Runbook

Maven is the primary build tool. This runbook covers:

1. [Current dual-build setup](#1-current-dual-build-setup) — using Gradle today without migrating
2. [Full migration to Gradle](#2-full-migration-to-gradle) — step-by-step when you want to drop Maven
3. [What changes in each file](#3-what-changes-in-each-file)
4. [Verifying equivalence](#4-verifying-equivalence)
5. [CI/CD updates](#5-cicd-updates)
6. [Differences to be aware of](#6-differences-to-be-aware-of)

---

## 1. Current Dual-Build Setup

The project ships `pom.xml` (Maven, primary) and `build.gradle.kts` (Gradle, secondary) side
by side. Both build tools are fully configured and produce equivalent outputs.

### First-time Gradle setup

The `gradle/wrapper/gradle-wrapper.properties` file is committed, but `gradlew` / `gradlew.bat`
are not (they require local Gradle to bootstrap). Generate them once:

```bash
# Requires Gradle 8.x installed locally (brew install gradle on macOS)
make gradle-wrapper

# Or directly:
gradle wrapper --gradle-version 8.10.2

# Verify
./gradlew --version
```

Commit `gradlew`, `gradlew.bat`, and `gradle/wrapper/gradle-wrapper.jar` to version control.
After this, no local Gradle install is needed — `./gradlew` is self-contained.

### Switching build tool per-invocation

All `make` targets support `BUILD_TOOL=gradle`:

```bash
make build BUILD_TOOL=gradle
make test BUILD_TOOL=gradle
make load-test BUILD_TOOL=gradle SCALE=1k
make db-migrate BUILD_TOOL=gradle
make start BUILD_TOOL=gradle
make clean BUILD_TOOL=gradle
```

Set it for your entire shell session:

```bash
export BUILD_TOOL=gradle
make test        # uses Gradle
make load-test   # uses Gradle
```

### Output directory

Both tools write to `target/`. This is intentional: `LoadTestResult.writeToFile()` and
`scripts/print-results.py` both reference `target/load-test-results/`, so `make results`
works regardless of which tool ran the tests.

### Gradle-equivalent for Maven commands

| Maven (`make ... BUILD_TOOL=maven`) | Gradle (`make ... BUILD_TOOL=gradle`) | Notes |
|--------------------------------------|---------------------------------------|-------|
| `mvn package -DskipTests` | `./gradlew build -x test` | Produces fat JAR in `target/` |
| `mvn test` | `./gradlew test` | Excludes `@Tag("load")` in both |
| `mvn test -P load-tests` | `./gradlew loadTest` | JVM args identical |
| `mvn test -P load-tests -Dtest="*LoadTest#*1000requests*"` | `./gradlew loadTest -Pscale=1k` | Scale filter |
| `mvn flyway:migrate` | `./gradlew flywayMigrate` | Same env vars |
| `mvn spring-boot:run` | `./gradlew bootRun` | Same env vars |
| `mvn clean` | `./gradlew clean` | Both delete `target/` |

---

## 2. Full Migration to Gradle

Follow these steps when you are ready to drop Maven entirely.

### Step 1 — Verify Gradle builds are green

Before removing Maven, confirm both build tools pass the full test suite:

```bash
# Maven (baseline)
make test
make load-test SCALE=1k

# Gradle (must match)
make test BUILD_TOOL=gradle
make load-test BUILD_TOOL=gradle SCALE=1k
```

Both runs should produce zero failures. Compare `make results` output — latency numbers will
differ slightly (different JVM warm-up paths) but all tests must PASS.

### Step 2 — Update the Makefile default

In `Makefile`, change the default build tool:

```makefile
# Before
BUILD_TOOL ?= maven

# After
BUILD_TOOL ?= gradle
```

This makes every bare `make test`, `make build`, etc. use Gradle without requiring
`BUILD_TOOL=gradle` on every invocation.

### Step 3 — Remove Maven files

```bash
rm pom.xml

# If you have a Maven wrapper (mvnw / mvnw.cmd / .mvn/):
rm -f mvnw mvnw.cmd
rm -rf .mvn/
```

Update `.gitignore` — the Maven-specific lines are no longer needed but are harmless to leave.

### Step 4 — Update the Makefile

Remove the Maven-specific variables and simplify the Makefile now that only one build tool
remains. Replace the conditional block with direct Gradle commands:

```makefile
JAVA_HOME  := /opt/homebrew/opt/openjdk@21
GRADLE     := JAVA_HOME=$(JAVA_HOME) ./gradlew

SCALE ?=

.DEFAULT_GOAL := help
.PHONY: help build test load-test results start stop-postgres start-postgres db-migrate clean

## build: compile and package (skip tests)
build:
    $(GRADLE) build -x test

## test: run unit and integration tests
test:
    $(GRADLE) test

## load-test [SCALE=1k|5k|10k|20k|50k]: run load tests
load-test:
    $(GRADLE) loadTest $(if $(SCALE),-Pscale=$(SCALE),)

## results [SCALE=...]: print load test result table
results:
    @python3 scripts/print-results.py $(SCALE)

## db-migrate: run Flyway migrations
db-migrate: start-postgres
    $(GRADLE) flywayMigrate

## start: start the Spring Boot application
start: db-migrate
    $(GRADLE) bootRun

## clean: remove build artifacts
clean:
    $(GRADLE) clean
```

Also remove the `gradle-wrapper` target (no longer needed once `gradlew` is committed).

### Step 5 — Update documentation

| File | Change |
|------|--------|
| `README.md` | Replace all `mvn` commands with `./gradlew` equivalents |
| `docs/pre-production-hardening.md` | Any Maven-specific commands (e.g. `mvn test -Dtest=...`) |
| `docs/ops-runbook.md` | Any build commands referenced |
| `docs/key-rotation-runbook.md` | Any build commands referenced |
| This file (`gradle-migration-runbook.md`) | Remove the dual-build section (§1) |

Search for remaining `mvn` references:

```bash
grep -r "mvn\b" docs/ README.md
```

### Step 6 — Update IDE configuration

#### IntelliJ IDEA

1. **File → Open** the project root — IntelliJ auto-detects `build.gradle.kts`
2. If IntelliJ previously imported the Maven project: **Maven tool window → Unlink Maven project**
3. **Gradle tool window → Reload All Gradle Projects**
4. Verify **Project Structure → SDKs** shows JDK 21

#### VS Code

1. Install the **Gradle for Java** extension
2. Open the project root — the Gradle extension auto-detects `build.gradle.kts`
3. If the Java extension previously used Maven: delete `.classpath` and `.project` files and
   let the Gradle extension regenerate them

---

## 3. What Changes in Each File

### `build.gradle.kts` vs `pom.xml`

| Concept | Maven (`pom.xml`) | Gradle (`build.gradle.kts`) |
|---------|-------------------|------------------------------|
| Parent / platform | `<parent>spring-boot-starter-parent` | `id("org.springframework.boot") version "3.3.4"` + `io.spring.dependency-management` |
| BOM import | `<dependencyManagement><scope>import` | `dependencyManagement { imports { mavenBom(...) } }` |
| Compile dep | `<scope>` absent / `compile` | `implementation(...)` |
| Runtime dep | `<scope>runtime` | `runtimeOnly(...)` |
| Test dep | `<scope>test` | `testImplementation(...)` |
| Optional / compile-only | `<optional>true` | `compileOnly(...)` |
| Annotation processor | `<annotationProcessorPaths>` | `annotationProcessor(...)` |
| Skip tests on build | `mvn package -DskipTests` | `./gradlew build -x test` |
| Load test profile | `<profile id="load-tests">` | Separate `loadTest` task |
| Scale filter | `-Dtest="*LoadTest#*1000requests*"` | `-Pscale=1k` → task filter |
| Flyway migrate | `mvn flyway:migrate` | `./gradlew flywayMigrate` |
| Run app | `mvn spring-boot:run` | `./gradlew bootRun` |
| Fat JAR location | `target/card-tokenisation-*.jar` | `target/libs/card-tokenisation-*.jar` |

### `Makefile`

The `BUILD_TOOL` conditional block and `_CMD_*` variables are replaced with direct
`$(GRADLE)` calls in each target. The `gradle-wrapper` target and `BUILD_TOOL ?=` line
are removed.

### `README.md`

All Quick Start and load test commands change from `mvn ...` to `./gradlew ...`:

```bash
# Before
JAVA_HOME=/opt/homebrew/opt/openjdk@21 mvn test

# After
./gradlew test
```

The Makefile commands (`make build`, `make test`, etc.) do not change — only the
underlying tool changes.

### CI/CD

See [§5 CI/CD updates](#5-cicd-updates).

---

## 4. Verifying Equivalence

Run these checks before completing the migration to confirm no dependencies or behaviour
were lost in translation.

### 4.1 Dependency tree comparison

```bash
# Maven
mvn dependency:tree -Dverbose > /tmp/mvn-deps.txt

# Gradle
./gradlew dependencies --configuration runtimeClasspath > /tmp/gradle-deps.txt

# Compare top-level artifacts (transitive trees will differ in format but should converge)
grep -E "^\[INFO\] \+--|^\[INFO\] \\\\--" /tmp/mvn-deps.txt | sort > /tmp/mvn-top.txt
grep -E "^\+---|\\\\---" /tmp/gradle-deps.txt | sort > /tmp/gradle-top.txt
diff /tmp/mvn-top.txt /tmp/gradle-top.txt
```

### 4.2 Fat JAR equivalence

```bash
# Build both
mvn package -DskipTests
./gradlew build -x test

# Compare manifests
unzip -p target/card-tokenisation-*.jar META-INF/MANIFEST.MF
unzip -p target/libs/card-tokenisation-*.jar META-INF/MANIFEST.MF
# Both should show Main-Class: org.springframework.boot.loader.launch.JarLauncher
# and Start-Class: com.yourorg.tokenisation.CardTokenisationApplication

# Compare class counts (should be equal or very close)
unzip -l target/card-tokenisation-*.jar | wc -l
unzip -l target/libs/card-tokenisation-*.jar | wc -l
```

### 4.3 Full test suite

```bash
make test                         # Maven (baseline)
make test BUILD_TOOL=gradle       # Gradle (must match)

# Both must exit 0 with the same test counts
```

### 4.4 Load test at 1k scale

```bash
make clean && make load-test SCALE=1k
make results SCALE=1k             # Save baseline

make clean BUILD_TOOL=gradle
make load-test BUILD_TOOL=gradle SCALE=1k
make results SCALE=1k             # Compare — all PASS, similar p99
```

### 4.5 Flyway migration

```bash
make stop-postgres start-postgres

make db-migrate                         # Maven
make stop-postgres start-postgres
make db-migrate BUILD_TOOL=gradle       # Gradle
# Both should apply all migrations with no errors
```

---

## 5. CI/CD Updates

### GitHub Actions (before — Maven)

```yaml
- name: Build and test
  run: JAVA_HOME=${{ env.JAVA_HOME }} mvn test

- name: Package
  run: JAVA_HOME=${{ env.JAVA_HOME }} mvn package -DskipTests
```

### GitHub Actions (after — Gradle)

```yaml
- name: Set up JDK 21
  uses: actions/setup-java@v4
  with:
    java-version: '21'
    distribution: 'temurin'
    cache: gradle          # Change from 'maven' to 'gradle'

- name: Build and test
  run: ./gradlew test

- name: Package
  run: ./gradlew build -x test

- name: Load test (optional)
  run: ./gradlew loadTest -Pscale=1k
  env:
    DATASOURCE_URL: ${{ secrets.DATASOURCE_URL }}
    DATASOURCE_USER: ${{ secrets.DATASOURCE_USER }}
    DATASOURCE_PASSWORD: ${{ secrets.DATASOURCE_PASSWORD }}
    KMS_PROVIDER: local-dev
    KMS_LOCAL_DEV_KEK_HEX: ${{ secrets.KMS_LOCAL_DEV_KEK_HEX }}
    PAN_HASH_SECRET: ${{ secrets.PAN_HASH_SECRET }}
    TAMPER_DETECTION_SECRET: ${{ secrets.TAMPER_DETECTION_SECRET }}
```

### Caching

Gradle's local cache lives in `~/.gradle/caches/`. Add it to your CI cache key:

```yaml
- uses: actions/cache@v4
  with:
    path: |
      ~/.gradle/caches
      ~/.gradle/wrapper
    key: gradle-${{ hashFiles('**/*.gradle.kts', 'gradle/wrapper/gradle-wrapper.properties') }}
    restore-keys: gradle-
```

---

## 6. Differences to Be Aware Of

### Fat JAR location

| Tool | JAR path |
|------|----------|
| Maven | `target/card-tokenisation-0.0.1-SNAPSHOT.jar` |
| Gradle | `target/libs/card-tokenisation-0.0.1-SNAPSHOT.jar` |

If your Dockerfile or deployment script references the JAR path directly, update it:

```dockerfile
# Maven
COPY target/card-tokenisation-*.jar app.jar

# Gradle
COPY target/libs/card-tokenisation-*.jar app.jar
```

Or use the `bootJar` task to control the output location:

```kotlin
// build.gradle.kts — put the fat JAR in target/ (same as Maven)
tasks.named<org.springframework.boot.gradle.tasks.bundling.BootJar>("bootJar") {
    destinationDirectory.set(layout.buildDirectory.dir(".").get().asFile)
    archiveFileName.set("card-tokenisation-${version}.jar")
}
```

### `./gradlew bootRun` vs `mvn spring-boot:run`

Both start the application with the same env vars. One difference: `bootRun` runs in a forked
JVM by default in Gradle and respects `jvmArgs` set in the task. If you need custom JVM flags
for local dev, add them to `build.gradle.kts`:

```kotlin
tasks.named<org.springframework.boot.gradle.tasks.run.BootRun>("bootRun") {
    jvmArgs("-Xmx512m")
}
```

### Test reports

| Tool | Report location |
|------|----------------|
| Maven Surefire | `target/surefire-reports/` |
| Gradle | `target/reports/tests/test/index.html` (HTML) |
|        | `target/test-results/test/` (XML, compatible with most CI tools) |

Both produce JUnit XML that CI systems (GitHub Actions, Jenkins, etc.) can parse.

### Incremental builds

Gradle caches task outputs and skips tasks whose inputs have not changed. Maven always
re-runs. This means:

- `./gradlew test` after an unchanged compile will show `> Task :test UP-TO-DATE`
- Use `./gradlew test --rerun` to force a fresh run
- The `loadTest` task has `outputs.upToDateWhen { false }` — it always re-runs

### Flyway validation on every Gradle invocation

The `build.gradle.kts` defers Flyway env var validation to when a `flyway*` task is actually
in the task graph. This means `./gradlew test` does not require `DATASOURCE_URL` to be set —
only `./gradlew flywayMigrate` does. Maven behaves the same way (plugin config is evaluated
lazily).
