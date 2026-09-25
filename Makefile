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

SHELL_SCRIPTS := $(shell find . -name '*.sh' -not -path './.git/*' -not -path '*/node_modules/*')
DOCKERFILES   := $(shell find . -name 'Dockerfile*' -not -path './.git/*' -not -path '*/node_modules/*')

.PHONY: help env test test-repo lint secrets-scan

help: ## Muestra esta ayuda
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "} {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

env: ## Crea .env desde .env.example con secretos aleatorios (no sobrescribe)
	@scripts/gen-env.sh "$(ENV_EXAMPLE)" "$(ENV_FILE)"

test: test-repo ## Corre todos los tests

test-repo: ## Tests del esqueleto del repo
	@test/repo.sh

lint: ## shellcheck + hadolint
	docker run --rm -v "$(CURDIR):/mnt" -w /mnt $(SHELLCHECK_IMAGE) -x $(SHELL_SCRIPTS)
	$(if $(DOCKERFILES),docker run --rm -v "$(CURDIR):/mnt" -w /mnt $(HADOLINT_IMAGE) hadolint $(DOCKERFILES))

secrets-scan: ## Busca secretos en el historial de git (gitleaks)
	docker run --rm -v "$(CURDIR):/repo" $(GITLEAKS_IMAGE) git --no-banner --redact /repo
