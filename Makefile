JAVA_HOME       := /opt/homebrew/opt/openjdk@21
MVN             := JAVA_HOME=$(JAVA_HOME) mvn
GRADLE          := JAVA_HOME=$(JAVA_HOME) ./gradlew

# ── Build tool selection ──────────────────────────────────────────────────────
# Default: maven.  Override per-invocation or export for a shell session:
#
#   make build BUILD_TOOL=gradle
#   export BUILD_TOOL=gradle && make test
#
# See docs/gradle-migration-runbook.md for full Gradle migration instructions.
BUILD_TOOL ?= maven

# ── Load test scale filter ────────────────────────────────────────────────────
# Usage: make load-test SCALE=1k   (runs only the *1000requests* methods)
#        make load-test SCALE=5k   (runs only the *5000requests* methods)
#        make load-test SCALE=10k  (runs only the *10000requests* methods)
#        make load-test SCALE=20k  (runs only the *20000requests* methods)
#        make load-test SCALE=50k  (runs only the *50000requests* methods)
#        make load-test            (runs all load tests)
SCALE ?=

# Maven-specific flags
_MVN_SCALE_FILTER  := $(if $(SCALE),-Dtest="*LoadTest\#*$(subst k,000,$(SCALE))requests*",)

# ── Per-tool command table ────────────────────────────────────────────────────
ifeq ($(BUILD_TOOL),gradle)
  _BUILD             := $(GRADLE)
  _CMD_build         := build -x test
  _CMD_test          := test
  _CMD_load_test     := loadTest $(if $(SCALE),-Pscale=$(SCALE),)
  _CMD_flyway        := flywayMigrate
  _CMD_run           := bootRun
  _CMD_clean         := clean
else
  _BUILD             := $(MVN)
  _CMD_build         := package -DskipTests
  _CMD_test          := test
  _CMD_load_test     := test -P load-tests $(_MVN_SCALE_FILTER)
  _CMD_flyway        := flyway:migrate
  _CMD_run           := spring-boot:run
  _CMD_clean         := clean
endif

# ── Postgres (standalone Docker) ──────────────────────────────────────────────
POSTGRES_IMAGE     := postgres:16-alpine
POSTGRES_CONTAINER := card-tokenisation-db
POSTGRES_PORT      := 5432
POSTGRES_DB        := tokenisation
POSTGRES_USER      := tokenisation_app
POSTGRES_PASSWORD  := local-dev-password

# ── App env — local-dev KMS (no AWS, no LocalStack) ──────────────────────────
export DATASOURCE_URL        := jdbc:postgresql://localhost:$(POSTGRES_PORT)/$(POSTGRES_DB)
export DATASOURCE_USER       := $(POSTGRES_USER)
export DATASOURCE_PASSWORD   := $(POSTGRES_PASSWORD)
# PAN_HASH_SECRET is only needed on first boot to seed the initial HMAC key row.
# After the first boot the value in key_versions takes over; remove this env var
# once the first HMAC key rotation completes.
export PAN_HASH_SECRET       := local-dev-pan-hash-secret-32bytes!
export KMS_PROVIDER          := local-dev
export KMS_LOCAL_DEV_KEK_HEX := 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
# HikariCP pool size — must be > rotation.batch.parallelism (8) + 5 headroom = 13 minimum.
# 60 gives 2× headroom over the ~30 concurrent connections needed at 333 rps with a 90ms
# average transaction hold time, absorbing a 50ms GC pause without exhaustion.
export HIKARI_MAX_POOL_SIZE  := 60
# Virtual threads — allows Tomcat to handle high concurrency without a fixed thread pool.
# Required for Gatling simulations to avoid platform-thread exhaustion under load.
export VIRTUAL_THREADS_ENABLED := true

# ── LocalStack KMS settings ───────────────────────────────────────────────────
LOCALSTACK_ENDPOINT  := http://localhost:4566
LOCALSTACK_REGION    := ap-southeast-2
LOCALSTACK_KEY_ALIAS := alias/card-tokenisation-kek

.DEFAULT_GOAL := help

.PHONY: help build test load-test localstack-test results \
        start stop-postgres start-postgres db-migrate \
        start-localstack stop-localstack run-localstack localstack-full \
        clean gradle-wrapper bruno-run bruno-run-admin gatling-test

## help: show this message
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
	@echo ""
	@echo "  Current build tool: $(BUILD_TOOL)  (override with BUILD_TOOL=gradle)"

## build: compile and package (skip tests)
build:
	$(_BUILD) $(_CMD_build)

## test: run unit and integration tests (requires Docker for Testcontainers)
test:
	$(_BUILD) $(_CMD_test)

## load-test [SCALE=1k|5k|10k|20k|50k]: run load tests; omit SCALE to run all
load-test:
	$(_BUILD) $(_CMD_load_test)

## localstack-test: run LocalStack KMS integration tests (requires Docker)
localstack-test:
	$(MVN) test -P localstack-tests

## results [SCALE=1k|5k|10k|20k|50k]: print a summary table of load test results
results:
	@python3 scripts/print-results.py $(SCALE)

# ── Local dev (local-dev KMS — no AWS) ───────────────────────────────────────

## start-postgres: start a standalone local PostgreSQL container
start-postgres:
	@if docker ps -q -f name=$(POSTGRES_CONTAINER) | grep -q .; then \
		echo "postgres already running"; \
	else \
		if docker ps -aq -f name=$(POSTGRES_CONTAINER) | grep -q .; then \
			echo "removing stale postgres container (Postgres flags only apply on create)..."; \
			docker rm $(POSTGRES_CONTAINER); \
		fi; \
		docker run -d \
			--name $(POSTGRES_CONTAINER) \
			-e POSTGRES_DB=$(POSTGRES_DB) \
			-e POSTGRES_USER=$(POSTGRES_USER) \
			-e POSTGRES_PASSWORD=$(POSTGRES_PASSWORD) \
			-p $(POSTGRES_PORT):5432 \
			--shm-size=256m \
			$(POSTGRES_IMAGE) postgres \
			  -c max_connections=200 \
			  -c synchronous_commit=off \
			  -c fsync=off \
			  -c full_page_writes=off; \
		echo "waiting for postgres..."; \
		until docker exec $(POSTGRES_CONTAINER) pg_isready -U $(POSTGRES_USER) -d $(POSTGRES_DB) > /dev/null 2>&1; do sleep 1; done; \
		echo "postgres ready"; \
	fi

## stop-postgres: stop and remove the standalone PostgreSQL container
stop-postgres:
	@if docker ps -q -f name=$(POSTGRES_CONTAINER) | grep -q .; then \
		docker stop $(POSTGRES_CONTAINER) && docker rm $(POSTGRES_CONTAINER); \
		echo "postgres stopped and removed"; \
	elif docker ps -aq -f name=$(POSTGRES_CONTAINER) | grep -q .; then \
		docker rm $(POSTGRES_CONTAINER); \
		echo "postgres container removed (was already stopped)"; \
	else \
		echo "postgres not running"; \
	fi

## db-migrate: run Flyway migrations against the local database (starts postgres first if not running)
db-migrate: start-postgres
	$(_BUILD) $(_CMD_flyway)

## start: start the Spring Boot app with local-dev KMS (no AWS, starts postgres first)
start: db-migrate
	MAVEN_OPTS="-XX:MaxGCPauseMillis=50 -Djava.security.egd=file:/dev/./urandom" \
	$(_BUILD) $(_CMD_run)

# ── LocalStack KMS (real AWS KMS API via LocalStack) ─────────────────────────
#
# Workflow:
#   1. make start-localstack   — start Postgres + LocalStack; creates KMS key via init hook
#   2. make run-localstack     — start Spring Boot app pointed at LocalStack KMS
#   3. make stop-localstack    — tear everything down
#
# Prerequisites: docker, awscli (for the key ARN lookup fallback)

## start-localstack: start Postgres + LocalStack KMS and create the KMS key
start-localstack:
	docker compose -f docker-compose-localstack.yml up -d
	@echo "waiting for LocalStack KMS init hook to complete..."
	@until docker compose -f docker-compose-localstack.yml exec -T localstack \
		test -f /tmp/localstack/kms-key-arn 2>/dev/null; do \
		sleep 2; \
	done
	@echo "LocalStack KMS ready. Key ARN: $$(docker compose -f docker-compose-localstack.yml exec -T localstack cat /tmp/localstack/kms-key-arn)"

## stop-localstack: stop and remove Postgres + LocalStack containers and volumes
stop-localstack:
	docker compose -f docker-compose-localstack.yml down -v

## localstack-full: start Postgres + LocalStack + Spring Boot app with one command (Ctrl+C stops app; then run make stop-localstack)
localstack-full: start-localstack
	$(MAKE) run-localstack

## run-localstack: start Spring Boot app against LocalStack KMS (requires: make start-localstack)
run-localstack:
	$(eval _LS_KEY_ARN := $(shell docker compose -f docker-compose-localstack.yml exec -T localstack cat /tmp/localstack/kms-key-arn 2>/dev/null))
	@[ -n "$(_LS_KEY_ARN)" ] || { echo "ERROR: LocalStack not running or key not created. Run: make start-localstack"; exit 1; }
	@echo "Starting app with LocalStack KMS key: $(_LS_KEY_ARN)"
	SPRING_PROFILES_ACTIVE=localstack \
	KMS_PROVIDER=aws \
	AWS_REGION=$(LOCALSTACK_REGION) \
	AWS_KMS_KEY_ARN=$(_LS_KEY_ARN) \
	KMS_AWS_ENDPOINT_OVERRIDE=$(LOCALSTACK_ENDPOINT) \
	AWS_ACCESS_KEY_ID=test \
	AWS_SECRET_ACCESS_KEY=test \
	DATASOURCE_URL=$(DATASOURCE_URL) \
	DATASOURCE_USER=$(DATASOURCE_USER) \
	DATASOURCE_PASSWORD=$(DATASOURCE_PASSWORD) \
	$(_BUILD) $(_CMD_run)

# ── Utilities ─────────────────────────────────────────────────────────────────

## clean: remove build artifacts
clean:
	$(_BUILD) $(_CMD_clean)

## bruno-run: run token API smoke tests (requires: make start)
bruno-run:
	@command -v bru >/dev/null 2>&1 || { \
		echo "Bruno CLI not found. Install with: npm install -g @usebruno/cli"; exit 1; \
	}
	@curl -sf http://localhost:8080/api/v1/health > /dev/null 2>&1 || { \
		echo "App is not running. Start it first with: make start"; exit 1; \
	}
	cd bruno/card-tokenisation-api && bru run tokens --env local -r

## bruno-run-admin: run admin key rotation smoke tests (requires: make start)
bruno-run-admin:
	@command -v bru >/dev/null 2>&1 || { \
		echo "Bruno CLI not found. Install with: npm install -g @usebruno/cli"; exit 1; \
	}
	@curl -sf http://localhost:8080/api/v1/health > /dev/null 2>&1 || { \
		echo "App is not running. Start it first with: make start"; exit 1; \
	}
	cd bruno/card-tokenisation-api && bru run admin --env local -r

## gradle-wrapper: generate gradlew and gradlew.bat (requires Gradle installed locally, run once)
gradle-wrapper:
	gradle wrapper --gradle-version 8.10.2
	@echo "gradlew generated. Commit gradle/wrapper/ and gradlew to version control."

# ── Gatling simulation targets ────────────────────────────────────────────────
# Gatling simulations run against a *running* application instance (make start first).
# They are NOT Spring Boot tests — no Testcontainers, no embedded DB.
#
# Simulations:
#   MixedSimulation          — 70% tokenise / 30% detokenise  ← DEFAULT (production traffic pattern)
#   TokenisationSimulation   — pure tokenise write load
#   DetokenisationSimulation — pure detokenise read load (seeds 10k tokens first)
#   RotationSimulation       — mixed traffic while KEK rotation runs concurrently
#                              (requires a FRESH app start: make start before this)
#
# Scale:
#   GATLING_SCALE    — total requests (default: 20k). Accepted: 20k, 50k, 100k, 1m
#   GATLING_DURATION — sustain window in seconds (default: 120).
#                      Increase to spread the same SCALE over a longer period (lower RPS):
#                      SCALE=100k DURATION=300 → 333 rps instead of 833 rps
#
# Examples:
#   make gatling-test                                           # 20k mixed (default)
#   make gatling-test GATLING_SCALE=100k                       # 100k mixed, 833 rps
#   make gatling-test GATLING_SCALE=100k GATLING_DURATION=300  # 100k mixed, 333 rps
#   make gatling-test GATLING_SIM=TokenisationSimulation GATLING_SCALE=50k
#   make gatling-test GATLING_SIM=DetokenisationSimulation GATLING_SCALE=50k
#   make gatling-test GATLING_SIM=RotationSimulation GATLING_SCALE=20k   # fresh start required
#
# Override target host:  GATLING_BASE_URL=http://host:8080 make gatling-test
# Override DB creds:     GATLING_DB_URL=... GATLING_DB_USER=... GATLING_DB_PASS=...

_PKG              := com.yourorg.tokenisation
GATLING_BASE_URL  ?= http://localhost:8080
GATLING_DB_URL    ?= jdbc:postgresql://localhost:5432/tokenisation
GATLING_DB_USER   ?= tokenisation_app
GATLING_DB_PASS   ?= local-dev-password
GATLING_SIM       ?= $(_PKG).MixedSimulation
GATLING_SCALE     ?= 20k
GATLING_DURATION  ?= 120
_GATLING_REQUESTS := $(shell echo $(GATLING_SCALE) | sed 's/k/000/g; s/m/000000/g')

## gatling-test [GATLING_SCALE=20k|50k|100k|1m] [GATLING_DURATION=120] [GATLING_SIM=...Simulation]: run Gatling simulation (requires: make start)
gatling-test:
	$(MVN) gatling:test -P gatling-tests \
	  -Dgatling.simulationClass=$(GATLING_SIM) \
	  -DbaseUrl=$(GATLING_BASE_URL) \
	  -DtotalRequests=$(_GATLING_REQUESTS) \
	  -DsustainSeconds=$(GATLING_DURATION) \
	  -DdbUrl=$(GATLING_DB_URL) \
	  -DdbUser=$(GATLING_DB_USER) \
	  -DdbPass=$(GATLING_DB_PASS)
