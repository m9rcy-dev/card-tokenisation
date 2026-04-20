plugins {
    java
    id("org.springframework.boot") version "3.3.4"
    id("io.spring.dependency-management") version "1.1.6"
    id("org.flywaydb.flyway") version "10.15.0"
}

group = "com.yourorg"
version = "0.0.1-SNAPSHOT"

// ── Output directory ──────────────────────────────────────────────────────────
// Point Gradle's build output to target/ so it is identical to Maven's layout.
// This means:
//   - scripts/print-results.py reads target/load-test-results/ regardless of build tool
//   - make results works without any changes
//   - LoadTestResult.writeToFile() (hardcoded to target/) works for both tools
layout.buildDirectory.set(file("target"))

// ── Java toolchain ────────────────────────────────────────────────────────────
java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

// ── Dependency versions ───────────────────────────────────────────────────────
val awsSdkVersion = "2.26.7"
val testcontainersVersion = "1.21.4"

// ── BOM imports ───────────────────────────────────────────────────────────────
dependencyManagement {
    imports {
        // AWS SDK v2 BOM — pins all AWS module versions together (mirrors pom.xml)
        mavenBom("software.amazon.awssdk:bom:$awsSdkVersion")
        // Testcontainers BOM — pins all testcontainers module versions together
        mavenBom("org.testcontainers:testcontainers-bom:$testcontainersVersion")
    }
}

repositories {
    mavenCentral()
}

// ── Dependencies ──────────────────────────────────────────────────────────────
dependencies {

    // Web
    implementation("org.springframework.boot:spring-boot-starter-web")

    // Persistence
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.flywaydb:flyway-core")
    implementation("org.flywaydb:flyway-database-postgresql")
    runtimeOnly("org.postgresql:postgresql")

    // Validation
    implementation("org.springframework.boot:spring-boot-starter-validation")

    // Security
    implementation("org.springframework.boot:spring-boot-starter-security")

    // Rate limiting (Caffeine in-memory)
    implementation("com.github.ben-manes.caffeine:caffeine")

    // AWS KMS — conditional at runtime via kms.provider=aws
    implementation("software.amazon.awssdk:kms")

    // OpenAPI / Swagger UI
    implementation("org.springdoc:springdoc-openapi-starter-webmvc-ui:2.5.0")

    // Lombok — compile-time only; excluded from the fat JAR automatically
    compileOnly("org.projectlombok:lombok")
    annotationProcessor("org.projectlombok:lombok")

    // ── Test ─────────────────────────────────────────────────────────────────
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
    testImplementation("org.springframework.boot:spring-boot-testcontainers")
    testImplementation("org.testcontainers:junit-jupiter")
    testImplementation("org.testcontainers:postgresql")

    // Lombok in test sources
    testCompileOnly("org.projectlombok:lombok")
    testAnnotationProcessor("org.projectlombok:lombok")
}

// ── Standard test task ────────────────────────────────────────────────────────
// Mirrors: mvn test
// Excludes @Tag("load") so load tests never run during a normal test pass.
tasks.test {
    useJUnitPlatform {
        excludeTags("load")
    }
    jvmArgs("-Xmx1g")
}

// ── Gatling source directory ──────────────────────────────────────────────────
// Add src/gatling/java to the test compilation source set so Gatling simulations
// are compiled alongside test classes and visible on the test classpath.
sourceSets {
    test {
        java {
            srcDir("src/gatling/java")
        }
    }
}

// ── Load test task ────────────────────────────────────────────────────────────
// Mirrors: mvn test -P load-tests [-Dtest="*LoadTest#*1000requests*"]
//
// Usage:
//   ./gradlew loadTest              — run all load tests
//   ./gradlew loadTest -Pscale=1k   — run only *1000requests* methods
//   ./gradlew loadTest -Pscale=5k   — run only *5000requests* methods
//   make load-test BUILD_TOOL=gradle [SCALE=1k]
//
// Virtual-thread scheduler flags:
//   The PostgreSQL JDBC driver uses synchronized blocks for socket I/O. Virtual threads
//   entering a synchronized block are PINNED to their carrier OS thread. With high
//   concurrency and a default ForkJoinPool sized to availableProcessors, threads pile up
//   waiting for a carrier. Setting parallelism=256 gives the scheduler enough carriers to
//   run all concurrently-pinned virtual threads simultaneously (max concurrency = 20).
tasks.register<Test>("loadTest") {
    description = "Run load tests (@Tag(\"load\")). Use -Pscale=1k|5k|10k|20k|50k to filter by scale."
    group = "verification"

    useJUnitPlatform {
        includeTags("load")
    }

    jvmArgs(
        "-Xmx2g",
        "-Xms512m",
        "-Djdk.virtualThreadScheduler.parallelism=256",
        "-Djdk.virtualThreadScheduler.maxPoolSize=512"
    )

    // Optional scale filter: ./gradlew loadTest -Pscale=1k
    // Translates "1k" → "1000" and filters to methods containing "1000requests"
    if (project.hasProperty("scale")) {
        val scale = project.property("scale").toString()
        val requests = scale.replace("k", "000")
        filter {
            includeTestsMatching("*LoadTest.*${requests}requests*")
        }
    }

    // Load tests must never be considered up-to-date — latency results change with system state
    outputs.upToDateWhen { false }
}

// ── Gatling simulation task ───────────────────────────────────────────────────
// Runs against a *running* application instance (./gradlew bootRun or make start first).
// Not a Spring Boot test — no Testcontainers, no embedded context.
//
// Usage:
//   ./gradlew gatlingTest                                          # 20k tokenisation
//   ./gradlew gatlingTest -PsimClass=...DetokenisationSimulation  # detokenisation
//   ./gradlew gatlingTest -PtotalRequests=1000000                 # 1M scale
//   make gatling-test BUILD_TOOL=gradle GATLING_SCALE=50k
//
// Gatling simulations live in src/gatling/java/ and are compiled with the test classpath.
tasks.register<JavaExec>("gatlingTest") {
    description = "Run a Gatling simulation against the running app. Use -PsimClass=... -PtotalRequests=... -PbaseUrl=..."
    group = "verification"
    mainClass.set("io.gatling.app.Gatling")
    classpath = sourceSets["test"].runtimeClasspath
    jvmArgs("-Xmx2g", "-Djdk.virtualThreadScheduler.parallelism=256")
    systemProperties(mapOf(
        "baseUrl"        to (project.findProperty("baseUrl") ?: "http://localhost:8080"),
        "totalRequests"  to (project.findProperty("totalRequests") ?: "20000"),
        "dbUrl"          to (project.findProperty("dbUrl") ?: "jdbc:postgresql://localhost:5432/tokenisation"),
        "dbUser"         to (project.findProperty("dbUser") ?: "tokenisation_app"),
        "dbPass"         to (project.findProperty("dbPass") ?: "change_me")
    ))
    args = listOf(
        "-s", project.findProperty("simClass")?.toString()
                ?: "com.yourorg.tokenisation.TokenisationSimulation",
        "-rd", "target/gatling"
    )
    // Always re-run — latency results are time-sensitive
    outputs.upToDateWhen { false }
}

// ── Flyway plugin ─────────────────────────────────────────────────────────────
// Mirrors: mvn flyway:migrate
// Reads connection details from the same environment variables as the Maven plugin.
//
// Usage:
//   DATASOURCE_URL=... DATASOURCE_USER=... DATASOURCE_PASSWORD=... ./gradlew flywayMigrate
//   make db-migrate BUILD_TOOL=gradle
//
// Configuration uses empty strings as defaults so that tasks like `./gradlew test`
// do not fail at configuration time when Flyway env vars are absent. Validation
// happens in the doFirst block — only when a Flyway task is actually executed.
flyway {
    url       = System.getenv("DATASOURCE_URL")      ?: ""
    user      = System.getenv("DATASOURCE_USER")     ?: ""
    password  = System.getenv("DATASOURCE_PASSWORD") ?: ""
    locations = arrayOf("filesystem:src/main/resources/db/migration")
}

// Fail fast with a clear message if required env vars are missing at execution time.
// This runs only when a flywayMigrate (or other flyway*) task is in the task graph.
tasks.withType<org.flywaydb.gradle.task.AbstractFlywayTask>().configureEach {
    doFirst {
        require(System.getenv("DATASOURCE_URL")?.isNotBlank() == true) {
            "DATASOURCE_URL env var must be set to run $name (e.g. export DATASOURCE_URL=jdbc:postgresql://localhost:5432/tokenisation)"
        }
        require(System.getenv("DATASOURCE_USER")?.isNotBlank() == true) {
            "DATASOURCE_USER env var must be set to run $name"
        }
    }
}
