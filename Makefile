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
GOSEC_VERSION       := v2.29.0
GOVULNCHECK_VERSION := v1.8.0

LDAP_TEST_IMAGE     := auth-ldap:test
AUTH_SVC_TEST_IMAGE := auth-svc:test

SHELL_SCRIPTS := $(shell find . -name '*.sh' -not -path './.git/*' -not -path '*/node_modules/*')
DOCKERFILES   := $(shell find . -name 'Dockerfile*' -not -path './.git/*' -not -path '*/node_modules/*')

.PHONY: help env secrets up down clean logs test test-repo test-ldap-image test-auth-svc test-auth-svc-image test-infra test-rotation lint secrets-scan jwt-public-key

help: ## Muestra esta ayuda
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "} {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

env: ## Crea .env desde .env.example con secretos aleatorios (no sobrescribe)
	@scripts/gen-env.sh "$(ENV_EXAMPLE)" "$(ENV_FILE)"

secrets: ## Escribe los *_PASSWORD de .env en secrets/ y genera las claves del JWT si faltan
	@scripts/sync-secrets.sh "$(ENV_FILE)" secrets
	@scripts/gen-jwt-keys.sh secrets

up: ## Levanta los servicios (espera a healthy); si cambió algún secreto, recrea los contenedores
	@changed=$$(scripts/sync-secrets.sh "$(ENV_FILE)" secrets && scripts/gen-jwt-keys.sh secrets) || exit 1; \
	if [ -n "$$changed" ]; then echo "secretos nuevos o cambiados: $$(echo $$changed) → se recrean los contenedores"; fi; \
	$(COMPOSE) up -d --build --wait $${changed:+--force-recreate}

jwt-public-key: ## Imprime la clave pública del JWT (para JWT_PUBLIC_KEY_FILE del repo api)
	@cat secrets/jwt_public_key

down: ## Detiene los servicios
	$(COMPOSE) down

clean: ## Detiene los servicios y BORRA los volúmenes (datos de ldap)
	$(COMPOSE) down -v

logs: ## Muestra los logs de los servicios
	$(COMPOSE) logs --no-color

test: test-repo test-ldap-image test-auth-svc test-auth-svc-image test-infra test-rotation ## Corre todos los tests

test-repo: ## Tests del esqueleto del repo
	@test/repo.sh

test-ldap-image: ## Tests de la imagen ldap en aislamiento
	docker build -q -t $(LDAP_TEST_IMAGE) ldap >/dev/null
	@LDAP_TEST_IMAGE=$(LDAP_TEST_IMAGE) test/ldap-image.sh

test-auth-svc: ## Tests de Go de auth-svc (unitarios + integración con la imagen ldap vía testcontainers)
	docker build -q -t $(LDAP_TEST_IMAGE) ldap >/dev/null
	cd auth-svc && LDAP_TEST_IMAGE=$(LDAP_TEST_IMAGE) go test -race -count=1 ./...

test-auth-svc-image: ## Tests de la imagen auth-svc en aislamiento
	docker build -q -t $(AUTH_SVC_TEST_IMAGE) auth-svc >/dev/null
	@AUTH_SVC_TEST_IMAGE=$(AUTH_SVC_TEST_IMAGE) test/auth-svc-image.sh

test-infra: up ## Tests de integración del compose
	@test/infra.sh

test-rotation: up ## Rotación de contraseñas de extremo a extremo (restaura tu .env al final)
	@test/rotation.sh

lint: ## shellcheck + hadolint + gofmt, go vet, gosec y govulncheck
	docker run --rm -v "$(CURDIR):/mnt" -w /mnt $(SHELLCHECK_IMAGE) -x $(SHELL_SCRIPTS)
	$(if $(DOCKERFILES),docker run --rm -v "$(CURDIR):/mnt" -w /mnt $(HADOLINT_IMAGE) hadolint $(DOCKERFILES))
	cd auth-svc && test -z "$$(gofmt -l . | tee /dev/stderr)"
	cd auth-svc && go vet ./...
	cd auth-svc && go run github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION) -quiet ./...
	cd auth-svc && go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

secrets-scan: ## Busca secretos en el historial de git (gitleaks)
	docker run --rm -v "$(CURDIR):/repo" $(GITLEAKS_IMAGE) git --no-banner --redact /repo
