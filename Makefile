SHELL := /bin/bash
.DEFAULT_GOAL := help

ENV_FILE    ?= .env
ENV_EXAMPLE ?= .env.example
COMPOSE     := docker compose -f docker-compose.yml -f docker-compose.dev.yml
export COMPOSE

# Versiones fijadas de las herramientas (único lugar; el CI usa estos mismos targets).
GITLEAKS_IMAGE   := zricethezav/gitleaks:v8.30.1
HADOLINT_IMAGE   := hadolint/hadolint:v2.15.1
SHELLCHECK_IMAGE := koalaman/shellcheck:v0.11.0

LDAP_TEST_IMAGE := auth-ldap:test

SHELL_SCRIPTS := $(shell find . -name '*.sh' -not -path './.git/*' -not -path '*/node_modules/*')
DOCKERFILES   := $(shell find . -name 'Dockerfile*' -not -path './.git/*' -not -path '*/node_modules/*')

.PHONY: help env secrets up down clean logs test test-repo test-ldap-image test-infra lint secrets-scan

help: ## Muestra esta ayuda
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "} {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

env: ## Crea .env desde .env.example con secretos aleatorios (no sobrescribe)
	@scripts/gen-env.sh "$(ENV_EXAMPLE)" "$(ENV_FILE)"

secrets: ## Escribe los *_PASSWORD de .env como archivos en secrets/ (Docker secrets)
	@scripts/sync-secrets.sh "$(ENV_FILE)" secrets

up: secrets ## Levanta los servicios de desarrollo y espera a que estén healthy
	$(COMPOSE) up -d --build --wait

down: ## Detiene los servicios
	$(COMPOSE) down

clean: ## Detiene los servicios y BORRA los volúmenes (datos de postgres y ldap)
	$(COMPOSE) down -v

logs: ## Muestra los logs de los servicios
	$(COMPOSE) logs --no-color

test: test-repo test-ldap-image test-infra ## Corre todos los tests

test-repo: ## Tests del esqueleto del repo
	@test/repo.sh

test-ldap-image: ## Tests de la imagen ldap en aislamiento
	docker build -q -t $(LDAP_TEST_IMAGE) ldap >/dev/null
	@LDAP_TEST_IMAGE=$(LDAP_TEST_IMAGE) test/ldap-image.sh

test-infra: up ## Tests de integración del compose
	@test/infra.sh

lint: ## shellcheck + hadolint
	docker run --rm -v "$(CURDIR):/mnt" -w /mnt $(SHELLCHECK_IMAGE) -x $(SHELL_SCRIPTS)
	$(if $(DOCKERFILES),docker run --rm -v "$(CURDIR):/mnt" -w /mnt $(HADOLINT_IMAGE) hadolint $(DOCKERFILES))

secrets-scan: ## Busca secretos en el historial de git (gitleaks)
	docker run --rm -v "$(CURDIR):/repo" $(GITLEAKS_IMAGE) git --no-banner --redact /repo
