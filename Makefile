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

# ── Postgres (Docker) ─────────────────────────────────────────────────────────
POSTGRES_IMAGE     := postgres:16
POSTGRES_CONTAINER := card-tokenisation-db
POSTGRES_PORT      := 5432
POSTGRES_DB        := tokenisation
POSTGRES_USER      := tokenisation_app
POSTGRES_PASSWORD  := change_me

# ── App env ───────────────────────────────────────────────────────────────────
export DATASOURCE_URL          := jdbc:postgresql://localhost:$(POSTGRES_PORT)/$(POSTGRES_DB)
export DATASOURCE_USER         := $(POSTGRES_USER)
export DATASOURCE_PASSWORD     := $(POSTGRES_PASSWORD)
export PAN_HASH_SECRET         := local-dev-pan-hash-secret-32bytes!
export TAMPER_DETECTION_SECRET := local-dev-tamper-secret-32bytes!
export KMS_PROVIDER            := local-dev
export KMS_LOCAL_DEV_KEK_HEX   := 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

.DEFAULT_GOAL := help

.PHONY: help build test load-test results start stop-postgres start-postgres db-migrate clean gradle-wrapper

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

## results [SCALE=1k|5k|10k|20k|50k]: print a summary table of load test results
results:
	@python3 scripts/print-results.py $(SCALE)

## start-postgres: start a local PostgreSQL container
start-postgres:
	@if docker ps -q -f name=$(POSTGRES_CONTAINER) | grep -q .; then \
		echo "postgres already running"; \
	else \
		docker run -d \
			--name $(POSTGRES_CONTAINER) \
			-e POSTGRES_DB=$(POSTGRES_DB) \
			-e POSTGRES_USER=$(POSTGRES_USER) \
			-e POSTGRES_PASSWORD=$(POSTGRES_PASSWORD) \
			-p $(POSTGRES_PORT):5432 \
			$(POSTGRES_IMAGE); \
		echo "waiting for postgres..."; \
		until docker exec $(POSTGRES_CONTAINER) pg_isready -U $(POSTGRES_USER) -d $(POSTGRES_DB) > /dev/null 2>&1; do sleep 1; done; \
		echo "postgres ready"; \
	fi

## stop-postgres: stop and remove the local PostgreSQL container
stop-postgres:
	@if docker ps -q -f name=$(POSTGRES_CONTAINER) | grep -q .; then \
		docker stop $(POSTGRES_CONTAINER) && docker rm $(POSTGRES_CONTAINER); \
		echo "postgres stopped"; \
	else \
		echo "postgres not running"; \
	fi

## db-migrate: run Flyway migrations against the local database (starts postgres first if not running)
db-migrate: start-postgres
	$(_BUILD) $(_CMD_flyway)

## start: start the Spring Boot application (starts postgres first if not running)
start: db-migrate
	$(_BUILD) $(_CMD_run)

## clean: remove build artifacts
clean:
	$(_BUILD) $(_CMD_clean)

## gradle-wrapper: generate gradlew and gradlew.bat (requires Gradle installed locally, run once)
gradle-wrapper:
	gradle wrapper --gradle-version 8.10.2
	@echo "gradlew generated. Commit gradle/wrapper/ and gradlew to version control."
