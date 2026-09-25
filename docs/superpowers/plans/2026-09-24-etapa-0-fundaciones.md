# Etapa 0 – Fundaciones: plan de implementación

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Dejar listo el monorepo: esqueleto con Makefile y `.env` generado, imagen OpenLDAP propia, docker-compose con postgres + ldap, CI en GitHub Actions y protección de `main`. Todo cubierto por smoke tests.

**Architecture:** Toda la automatización vive en el `Makefile` y en scripts de shell probados. El CI solo invoca targets de `make`, así que en local y en CI corre exactamente lo mismo (DRY). La imagen `ldap` es Alpine + OpenLDAP 2.6 con un `entrypoint.sh` que genera la configuración desde variables de entorno en el primer arranque. Los tests son scripts bash con un pequeño `test/lib.sh` de aserciones.

**Tech Stack:** Docker / Compose v2, Alpine 3.24, OpenLDAP 2.6 (`slapd`, `mdb`, `argon2`), PostgreSQL 18, bash, GNU Make, GitHub Actions, gitleaks v8.30.1, hadolint v2.15.1, shellcheck v0.11.0.

**Spec:** `docs/superpowers/specs/2026-09-24-auth-dashboard-design.md`

## Global Constraints

- Nada hardcodeado: la configuración sale de `.env`; en compose se usa `${VAR:?mensaje}` para fallar si falta. Las **versiones** de imágenes y herramientas sí se fijan en el código (Dockerfile, compose, Makefile), nunca en `.env`.
- Los secretos nunca van como variables de entorno visibles: se pasan como Docker secrets (`*_FILE`). `.env` está en `.gitignore` y se crea con `make env` (secretos aleatorios de 48 caracteres hex). `make secrets` (prerrequisito de `make up`) escribe cada `*_PASSWORD` de `.env` en `secrets/<nombre>` y compose los monta con `file:`, porque los secretos de tipo `environment:` no funcionan con contenedores `read_only`.
- Los valores de `.env` no llevan comillas ni espacios (se leen desde bash y desde compose).
- Contenedores non-root cuando la imagen lo permite; `no-new-privileges`; la imagen `ldap` corre `read_only` con `cap_drop: ALL`.
- Los puertos de desarrollo se publican solo en `127.0.0.1`.
- Los logs y mensajes de error nunca muestran valores de secretos.
- Un issue = una rama `feat/<n>-<slug>` = un PR con `Closes #n`, merge por squash. Commits convencionales, que terminan con `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Los scripts de test **no** usan `set -e` ni `pipefail` (las aserciones manejan los fallos y `grep -q` cortaría el pipe); los scripts de producción sí usan `set -eu`.

## Review Focus

1. **Reinicio con el volumen existente**: la imagen `ldap` no debe re-inicializarse ni fallar; si un primer arranque quedó a medias, debe reintentarlo desde cero → test en la Task 3 (reinicio + conteo de "primer arranque") y en la Task 2 (marcador `.initialized`).
2. **Contraseñas con caracteres especiales** (`$`, `&`, `/`, `\`, `"`, espacios) al pasar por `envsubst`/`slappasswd` → test en la Task 2.
3. **Variable faltante o plantilla con placeholder no definido**: el contenedor debe fallar al arrancar, nombrar la variable y no mostrar valores → tests en la Task 2.
4. **ACLs**: el anónimo, un usuario u otro usuario no pueden leer entradas ajenas ni `userPassword`; la cuenta de servicio no puede escribir → tests en la Task 3.
5. **Secretos commiteados por error** (`.env`): ignorado por git y detectado por gitleaks → tests en las Tasks 1 y 4.

---

## Prerrequisitos (humano)

- Docker Desktop encendido (`docker version` debe mostrar el Server).
- `gh auth refresh -s workflow` (sin eso no se puede subir `.github/workflows/ci.yml` en la Task 4).

## Mapa de archivos

| Archivo | Responsabilidad | Task |
|---|---|---|
| `.gitignore` | Excluir secretos, builds y dependencias | 1 |
| `.env.example` | Plantilla documentada de configuración (`__GENERATE__` = secreto aleatorio) | 1, 3 |
| `scripts/gen-env.sh` | Generar `.env` desde la plantilla sin sobrescribir | 1 |
| `Makefile` | Punto de entrada único: help, env, up/down, test, lint, secrets-scan | 1–4 |
| `test/lib.sh` | Aserciones y helpers compartidos por todos los smoke tests | 1 |
| `test/repo.sh` | Tests del esqueleto (gitignore, gen-env) | 1 |
| `README.md`, `CLAUDE.md` | Uso y convenciones | 1 |
| `.hadolint.yaml` | Reglas de hadolint | 2 |
| `ldap/Dockerfile` | Imagen OpenLDAP propia | 2 |
| `ldap/entrypoint.sh` | Validación, secretos, hashing, render e init idempotente | 2 |
| `ldap/templates/config.ldif` | `cn=config`: módulos, schemas, base mdb, ACLs | 2 |
| `ldap/templates/base.ldif` | Árbol base + cuenta de servicio | 2 |
| `test/ldap-image.sh` | Tests de la imagen en aislamiento (`docker run`) | 2 |
| `ldap/seed/users.ldif` | Usuarios y grupo semilla (solo dev) | 3 |
| `scripts/sync-secrets.sh` | Escribir los `*_PASSWORD` de `.env` como archivos en `secrets/` | 3 |
| `docker-compose.yml` | Servicios base postgres + ldap | 3 |
| `docker-compose.dev.yml` | Puertos en localhost + seed | 3 |
| `test/infra.sh` | Tests de integración del compose | 3 |
| `.github/workflows/ci.yml` | CI que invoca targets de make | 4 |
| `.github/PULL_REQUEST_TEMPLATE.md`, `.github/ISSUE_TEMPLATE/feature.md` | Plantillas | 5 |

---

### Task 1: Esqueleto del monorepo (issue #1)

**Files:**
- Create: `.gitignore`, `.env.example`, `scripts/gen-env.sh`, `Makefile`, `test/lib.sh`, `test/repo.sh`, `README.md`, `CLAUDE.md`

**Interfaces:**
- Produces:
  - `test/lib.sh`: `check <desc> <cmd...>`, `check_fails <desc> <cmd...>`, `check_output <desc> <regex> <cmd...>`, `check_no_output <desc> <regex> <cmd...>`, `wait_healthy <container-id>` (0 si llega a healthy en ≤60 s), `load_env` (exporta las variables de `${ENV_FILE:-.env}`), `summary` (exit 1 si hubo fallos).
  - `scripts/gen-env.sh <plantilla> <destino>`.
  - Make: `help`, `env` (acepta `ENV_EXAMPLE=` y `ENV_FILE=`), `test`, `test-repo`, `lint`, `secrets-scan`. Variable `COMPOSE` exportada.

- [ ] **Step 1: Crear la rama**

```bash
git switch -c feat/1-monorepo-skeleton
```

- [ ] **Step 2: Escribir `test/lib.sh`**

```bash
#!/usr/bin/env bash
# Helpers mínimos de aserción para los smoke tests en shell.
# Uso: source test/lib.sh; check ...; summary

FAILED=0

pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILED=$((FAILED + 1)); }

# check <desc> <cmd...>: el comando debe terminar con código 0.
check() {
  local desc=$1; shift
  if "$@" >/dev/null 2>&1; then pass "$desc"; else fail "$desc"; fi
}

# check_fails <desc> <cmd...>: el comando debe fallar.
check_fails() {
  local desc=$1; shift
  if "$@" >/dev/null 2>&1; then fail "$desc"; else pass "$desc"; fi
}

# check_output <desc> <regex> <cmd...>: stdout+stderr debe contener <regex> (ERE).
check_output() {
  local desc=$1 re=$2; shift 2
  if "$@" 2>&1 | grep -Eq -- "$re"; then pass "$desc"; else fail "$desc"; fi
}

# check_no_output <desc> <regex> <cmd...>: stdout+stderr NO debe contener <regex>.
check_no_output() {
  local desc=$1 re=$2; shift 2
  if "$@" 2>&1 | grep -Eq -- "$re"; then fail "$desc"; else pass "$desc"; fi
}

# wait_healthy <container-id>: espera hasta 60 s a que el healthcheck esté "healthy".
wait_healthy() {
  local status
  for _ in $(seq 60); do
    status=$(docker inspect -f '{{.State.Health.Status}}' "$1" 2>/dev/null)
    case $status in
      healthy) return 0 ;;
      unhealthy) return 1 ;;
    esac
    sleep 1
  done
  return 1
}

# load_env: exporta las variables de ${ENV_FILE:-.env}.
load_env() {
  local file=${ENV_FILE:-.env}
  [[ -f $file ]] || { echo "falta $file: ejecuta 'make env'" >&2; exit 1; }
  set -a
  # shellcheck disable=SC1090
  . "$file"
  set +a
}

summary() {
  if [[ $FAILED -eq 0 ]]; then
    echo "OK"
  else
    echo "$FAILED test(s) fallaron" >&2
    exit 1
  fi
}
```

- [ ] **Step 3: Escribir el test que falla, `test/repo.sh`**

```bash
#!/usr/bin/env bash
# Tests del esqueleto del repo: .gitignore y generación de .env.
set -u
cd "$(dirname "$0")/.." || exit 1
# shellcheck source=test/lib.sh
. test/lib.sh

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
printf 'PLAIN=valor\nSECRET_A=__GENERATE__\nSECRET_B=__GENERATE__\n' > "$tmp/example"

echo "repo:"
check "git ignora .env" git check-ignore -q .env
check "make help lista el target env" sh -c 'make -s help | grep -q "env"'
check "make env genera el archivo" make -s env ENV_EXAMPLE="$tmp/example" ENV_FILE="$tmp/a.env"
check_no_output "no quedan marcadores __GENERATE__" '__GENERATE__' cat "$tmp/a.env"
check_output "conserva los valores no secretos" '^PLAIN=valor$' cat "$tmp/a.env"
check_output "genera secretos de 48 hex" '^SECRET_A=[0-9a-f]{48}$' cat "$tmp/a.env"
a=$(sed -n 's/^SECRET_A=//p' "$tmp/a.env")
b=$(sed -n 's/^SECRET_B=//p' "$tmp/a.env")
check "cada secreto es distinto" test "$a" != "$b"
check_output "el archivo solo lo lee su dueño (600)" '^-rw-------' ls -l "$tmp/a.env"
check_fails "no sobrescribe un .env existente" make -s env ENV_EXAMPLE="$tmp/example" ENV_FILE="$tmp/a.env"

summary
```

```bash
chmod +x test/lib.sh test/repo.sh
```

- [ ] **Step 4: Ejecutar para ver que falla**

Run: `test/repo.sh`
Expected: FAIL en todos los checks (no existen `.gitignore` ni `Makefile`), termina con `N test(s) fallaron`.

- [ ] **Step 5: Implementar `.gitignore`**

```gitignore
# Secretos y configuración local
.env
*.env
!.env.example
*.pem
*.key
secrets/

# Dependencias y builds
node_modules/
dist/
bin/
coverage/

# Editor / SO
.DS_Store
.idea/
.vscode/
```

- [ ] **Step 6: Implementar `scripts/gen-env.sh`**

```bash
#!/usr/bin/env bash
# Genera un .env a partir de la plantilla, reemplazando __GENERATE__ por secretos aleatorios.
# Nunca sobrescribe un archivo existente.
set -euo pipefail

src=${1:?uso: gen-env.sh <plantilla> <destino>}
dst=${2:?uso: gen-env.sh <plantilla> <destino>}

if [[ -e $dst ]]; then
  echo "gen-env: $dst ya existe; bórralo si quieres regenerarlo" >&2
  exit 1
fi

umask 077
while IFS= read -r line || [[ -n $line ]]; do
  if [[ $line == *=__GENERATE__ ]]; then
    printf '%s=%s\n' "${line%%=*}" "$(openssl rand -hex 24)"
  else
    printf '%s\n' "$line"
  fi
done < "$src" > "$dst"

echo "gen-env: $dst creado"
```

```bash
chmod +x scripts/gen-env.sh
```

- [ ] **Step 7: Implementar `.env.example` (versión inicial; la Task 3 la amplía)**

```dotenv
# Plantilla de configuración. Crea tu .env con:  make env
# - Los valores __GENERATE__ se reemplazan por secretos aleatorios.
# - Sin comillas ni espacios en los valores.

COMPOSE_PROJECT_NAME=auth
```

- [ ] **Step 8: Implementar el `Makefile`**

```makefile
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
```

- [ ] **Step 9: Ejecutar los tests para ver que pasan**

Run: `make test`
Expected: todos los checks en `ok` y `OK` al final.

- [ ] **Step 10: Lint y escaneo de secretos**

Run: `make lint && make secrets-scan`
Expected: shellcheck sin hallazgos (no hay Dockerfiles aún, así que hadolint no corre); gitleaks `no leaks found`.

Si gitleaks falla con `dubious ownership` (el repo montado pertenece a otro uid), cambiar el target a:
`docker run --rm -v "$(CURDIR):/repo" --entrypoint sh $(GITLEAKS_IMAGE) -c 'git config --global --add safe.directory /repo && gitleaks git --no-banner --redact /repo'`

- [ ] **Step 11: Escribir `README.md`**

````markdown
# auth

Dashboard con login contra LDAP, sesión por cookie HttpOnly (Go + `scs`) y JWT para clientes que no son navegador. Todo corre en Docker.

Diseño: [`docs/superpowers/specs/2026-09-24-auth-dashboard-design.md`](docs/superpowers/specs/2026-09-24-auth-dashboard-design.md)

## Requisitos

- Docker Desktop / Docker Engine con Compose v2
- GNU Make, bash, openssl

## Primeros pasos

```bash
make env     # crea .env con secretos aleatorios (una sola vez)
make help    # lista los comandos disponibles
make test    # corre todos los tests
```

## Estructura

| Carpeta | Contenido |
|---|---|
| `ldap/` | Imagen OpenLDAP propia |
| `test/` | Smoke tests de infraestructura |
| `scripts/` | Utilidades del repo |
| `docs/` | Spec y planes por etapa |
````

- [ ] **Step 12: Escribir `CLAUDE.md`**

```markdown
# Convenciones del proyecto

- **Spec:** `docs/superpowers/specs/2026-09-24-auth-dashboard-design.md`. Los planes por etapa están en `docs/superpowers/plans/`.
- **TDD:** cada feature empieza con un test que falla. No se da por terminado nada sin tests en verde.
- **Nada hardcodeado:** la configuración sale de variables de entorno (`.env`, generado con `make env`); los secretos van como Docker secrets (`*_FILE`). Las versiones de imágenes y herramientas se fijan en el código (Dockerfile, compose, Makefile).
- **KISS / DRY / YAGNI:** el Makefile es el único punto de entrada; el CI solo invoca targets de `make`.
- **Seguridad:** non-root, puertos de desarrollo solo en 127.0.0.1, nunca loguear secretos ni tokens.
- **Git:** un issue = una rama `feat/<n>-<slug>` = un PR con `Closes #n`, merge por squash a `main`. Conventional Commits.
- **Tests de shell:** usan `test/lib.sh`; sin `set -e`/`pipefail` en los tests.
```

- [ ] **Step 13: Commit, push y PR**

```bash
git add .gitignore .env.example scripts/gen-env.sh Makefile test/lib.sh test/repo.sh README.md CLAUDE.md
git commit -m "chore: monorepo skeleton with Makefile, env generation and shell test helpers

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push -u origin feat/1-monorepo-skeleton
gh pr create --title "chore: esqueleto del monorepo" --body "Closes #1

- \`make env\` genera \`.env\` con secretos aleatorios (no sobrescribe, permisos 600)
- \`test/lib.sh\` con aserciones reutilizables; \`test/repo.sh\` con los tests del esqueleto
- \`make lint\` (shellcheck/hadolint) y \`make secrets-scan\` (gitleaks)

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
```

- [ ] **Step 14: Merge**

Con el PR revisado (todavía no hay CI; la verificación es `make test` en local):

```bash
gh pr merge --squash --delete-branch
git switch main && git pull
```

---

### Task 2: Imagen OpenLDAP propia (issue #2, parte 1)

**Files:**
- Create: `ldap/Dockerfile`, `ldap/entrypoint.sh`, `ldap/templates/config.ldif`, `ldap/templates/base.ldif`, `.hadolint.yaml`, `test/ldap-image.sh`
- Modify: `Makefile` (targets `test-ldap-image`, `test`)

**Interfaces:**
- Consumes: `test/lib.sh` (Task 1).
- Produces (el contrato de la imagen, que usan la Task 3 y la Etapa 1):
  - Variables obligatorias: `LDAP_BASE_DN` (forma `dc=x,dc=y`), `LDAP_ORG_NAME`, `LDAP_PORT`, `LDAP_SERVICE_CN`, `LDAP_DB_MAX_SIZE` (bytes), `LDAP_LOG_LEVEL`, `LDAP_ADMIN_PASSWORD[_FILE]`, `LDAP_SERVICE_PASSWORD[_FILE]`.
  - Cualquier `LDAP_*_PASSWORD[_FILE]` genera `${LDAP_*_PASSWORD_HASH}` (ARGON2), disponible para las plantillas.
  - DNs: admin `cn=admin,$LDAP_BASE_DN`; servicio `cn=$LDAP_SERVICE_CN,ou=services,$LDAP_BASE_DN`; usuarios `ou=users,$LDAP_BASE_DN`; grupos `ou=groups,$LDAP_BASE_DN`.
  - Seed opcional: cualquier `/seed/*.ldif` se renderiza y se carga en el primer arranque.
  - Volumen: `/var/lib/openldap`. Escribe solo en ese volumen y en `/tmp`.
  - En el primer arranque loguea la línea `entrypoint: primer arranque, inicializando el directorio`.
  - Make: `test-ldap-image`; imagen de test `auth-ldap:test` (variable `LDAP_TEST_IMAGE`).

- [ ] **Step 1: Crear la rama**

```bash
git switch main && git pull && git switch -c feat/2-ldap-image-compose
```

- [ ] **Step 2: Escribir el test que falla, `test/ldap-image.sh`**

```bash
#!/usr/bin/env bash
# Tests de la imagen ldap en aislamiento (docker run, sin compose).
# Usa valores de prueba propios; no depende de .env.
set -u
cd "$(dirname "$0")/.." || exit 1
# shellcheck source=test/lib.sh
. test/lib.sh

IMG=${LDAP_TEST_IMAGE:?LDAP_TEST_IMAGE no definida (usa make test-ldap-image)}
PORT=1389
BASE=dc=test,dc=local
URI="ldap://127.0.0.1:$PORT"
BASE_ENV=(-e "LDAP_BASE_DN=$BASE" -e LDAP_ORG_NAME=Test -e "LDAP_PORT=$PORT"
          -e LDAP_SERVICE_CN=svc -e LDAP_DB_MAX_SIZE=104857600 -e LDAP_LOG_LEVEL=stats)
PW_ENV=(-e LDAP_ADMIN_PASSWORD=admin-test -e LDAP_SERVICE_PASSWORD=svc-test)

# run_once <docker-run-args...>: arranca el contenedor, espera hasta 30 s a que termine
# e imprime sus logs. Devuelve su código de salida, o 0 si sigue corriendo (no falló).
run_once() {
  local cid code
  cid=$(docker run -d "$@" "$IMG") || return 1
  for _ in $(seq 30); do
    [[ $(docker inspect -f '{{.State.Running}}' "$cid") == false ]] && break
    sleep 1
  done
  docker logs "$cid" 2>&1
  code=$(docker inspect -f '{{if .State.Running}}0{{else}}{{.State.ExitCode}}{{end}}' "$cid")
  docker rm -fv "$cid" >/dev/null
  return "$code"
}

echo "ldap-image: configuración inválida"
check_fails  "sin variables → sale con error" run_once
check_output "sin variables → nombra LDAP_BASE_DN" 'LDAP_BASE_DN' run_once
check_output "falta un secreto → lo nombra" 'LDAP_ADMIN_PASSWORD' \
  run_once "${BASE_ENV[@]}" -e LDAP_SERVICE_PASSWORD=valor-que-no-debe-salir
check_no_output "el error no muestra valores de secretos" 'valor-que-no-debe-salir' \
  run_once "${BASE_ENV[@]}" -e LDAP_SERVICE_PASSWORD=valor-que-no-debe-salir
check_output "base DN inválido → error" 'LDAP_BASE_DN debe' \
  run_once "${BASE_ENV[@]}" "${PW_ENV[@]}" -e LDAP_BASE_DN=o=foo

seed=$(mktemp -d)
# shellcheck disable=SC2016  # el ${...} es literal: es la plantilla
printf 'dn: cn=x,${LDAP_BASE_DN}\nobjectClass: organizationalRole\ncn: ${NO_DEFINIDA}\n' > "$seed/x.ldif"
chmod -R a+rX "$seed"
check_output "plantilla con variable no definida → la nombra" 'NO_DEFINIDA' \
  run_once "${BASE_ENV[@]}" "${PW_ENV[@]}" -v "$seed:/seed:ro"
check_fails "plantilla con variable no definida → sale con error" \
  run_once "${BASE_ENV[@]}" "${PW_ENV[@]}" -v "$seed:/seed:ro"
rm -rf "$seed"

echo "ldap-image: arranque válido"
WEIRD='p@$$ w/o\rd&"x'
cid=$(docker run -d -v /var/lib/openldap "${BASE_ENV[@]}" \
  -e LDAP_ADMIN_PASSWORD="$WEIRD" -e LDAP_SERVICE_PASSWORD="$WEIRD" "$IMG")
trap 'docker rm -fv "$cid" >/dev/null 2>&1' EXIT

check "llega a healthy" wait_healthy "$cid"
check "bind de la cuenta de servicio con contraseña con caracteres especiales" \
  docker exec "$cid" ldapwhoami -x -H "$URI" -D "cn=svc,ou=services,$BASE" -w "$WEIRD"
check "bind del admin con contraseña con caracteres especiales" \
  docker exec "$cid" ldapwhoami -x -H "$URI" -D "cn=admin,$BASE" -w "$WEIRD"
check_fails "contraseña errónea es rechazada" \
  docker exec "$cid" ldapwhoami -x -H "$URI" -D "cn=svc,ou=services,$BASE" -w incorrecta
# userPassword es binario → ldapsearch lo devuelve en base64; e0FSR09OMn0 = "{ARGON2}"
check_output "el hash guardado es ARGON2" '^userPassword:: e0FSR09OMn0' \
  docker exec "$cid" ldapsearch -x -LLL -H "$URI" -D "cn=admin,$BASE" -w "$WEIRD" \
    -b "cn=svc,ou=services,$BASE" userPassword -o ldif-wrap=no
# shellcheck disable=SC2016  # $(id -u) debe expandirse dentro del contenedor
check_fails "no corre como root" docker exec "$cid" sh -c 'test "$(id -u)" = 0'
check_no_output "slapd no conserva contraseñas en su entorno" 'PASSWORD' \
  docker exec "$cid" sh -c 'tr "\0" "\n" < /proc/1/environ'

summary
```

Nota: `ldapsearch` devuelve `userPassword` en base64 (`userPassword:: e0FSR09OMn0...`). Si la línea aparece con `::`, cambiar el check por `check_output '...' 'userPassword:: e0FSR09OMn0'` (`{ARGON2}` codificado en base64 empieza por `e0FSR09OMn0`).

```bash
chmod +x test/ldap-image.sh
```

- [ ] **Step 3: Agregar el target de make**

En el `Makefile`, agregar la variable junto a las demás y los targets (y actualizar `test` y `.PHONY`):

```makefile
LDAP_TEST_IMAGE := auth-ldap:test
```

```makefile
.PHONY: help env test test-repo test-ldap-image lint secrets-scan

test: test-repo test-ldap-image ## Corre todos los tests

test-ldap-image: ## Tests de la imagen ldap en aislamiento
	docker build -q -t $(LDAP_TEST_IMAGE) ldap >/dev/null
	@LDAP_TEST_IMAGE=$(LDAP_TEST_IMAGE) test/ldap-image.sh
```

- [ ] **Step 4: Ejecutar para ver que falla**

Run: `make test-ldap-image`
Expected: FAIL en `docker build` (no existe `ldap/Dockerfile`).

- [ ] **Step 5: Implementar `ldap/templates/config.ldif`**

```ldif
dn: cn=config
objectClass: olcGlobal
cn: config

dn: cn=module{0},cn=config
objectClass: olcModuleList
cn: module{0}
olcModulePath: /usr/lib/openldap
olcModuleLoad: back_mdb.so
olcModuleLoad: argon2.so

dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema

include: file:///etc/openldap/schema/core.ldif

include: file:///etc/openldap/schema/cosine.ldif

include: file:///etc/openldap/schema/inetorgperson.ldif

dn: olcDatabase={-1}frontend,cn=config
objectClass: olcDatabaseConfig
objectClass: olcFrontendConfig
olcDatabase: {-1}frontend
olcPasswordHash: {ARGON2}
olcSizeLimit: 500
olcAccess: {0}to dn.base="" by * read
olcAccess: {1}to dn.base="cn=Subschema" by * read

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config
olcAccess: {0}to * by * none

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
objectClass: olcMdbConfig
olcDatabase: {1}mdb
olcDbDirectory: /var/lib/openldap/data
olcSuffix: ${LDAP_BASE_DN}
olcRootDN: cn=admin,${LDAP_BASE_DN}
olcRootPW: ${LDAP_ADMIN_PASSWORD_HASH}
olcDbMaxSize: ${LDAP_DB_MAX_SIZE}
olcDbIndex: objectClass eq
olcDbIndex: uid eq
olcDbIndex: member eq
olcAccess: {0}to attrs=userPassword by anonymous auth by * none
olcAccess: {1}to dn.subtree="ou=users,${LDAP_BASE_DN}" by dn.exact="cn=${LDAP_SERVICE_CN},ou=services,${LDAP_BASE_DN}" read by self read by anonymous auth by * none
olcAccess: {2}to dn.subtree="ou=groups,${LDAP_BASE_DN}" by dn.exact="cn=${LDAP_SERVICE_CN},ou=services,${LDAP_BASE_DN}" read by * none
olcAccess: {3}to dn.subtree="ou=services,${LDAP_BASE_DN}" by anonymous auth by * none
olcAccess: {4}to * by * none
```

- [ ] **Step 6: Implementar `ldap/templates/base.ldif`**

```ldif
dn: ${LDAP_BASE_DN}
objectClass: top
objectClass: dcObject
objectClass: organization
dc: ${LDAP_DC}
o: ${LDAP_ORG_NAME}

dn: ou=users,${LDAP_BASE_DN}
objectClass: organizationalUnit
ou: users

dn: ou=groups,${LDAP_BASE_DN}
objectClass: organizationalUnit
ou: groups

dn: ou=services,${LDAP_BASE_DN}
objectClass: organizationalUnit
ou: services

dn: cn=${LDAP_SERVICE_CN},ou=services,${LDAP_BASE_DN}
objectClass: organizationalRole
objectClass: simpleSecurityObject
cn: ${LDAP_SERVICE_CN}
description: Cuenta de solo lectura para auth-svc
userPassword: ${LDAP_SERVICE_PASSWORD_HASH}
```

- [ ] **Step 7: Implementar `ldap/entrypoint.sh`**

```sh
#!/bin/sh
# Inicializa slapd desde variables de entorno en el primer arranque y lo ejecuta en primer plano.
# Nunca imprime valores de variables (pueden ser secretos).
set -eu

ROOT_DIR=/var/lib/openldap
CONFIG_DIR=$ROOT_DIR/slapd.d
DATA_DIR=$ROOT_DIR/data
MARKER=$ROOT_DIR/.initialized
TEMPLATES_DIR=/etc/openldap/templates
SEED_DIR=/seed

die() { echo "entrypoint: $*" >&2; exit 1; }

# require VAR...: falla si alguna variable no está definida o está vacía.
require() {
  for var in "$@"; do
    eval "val=\${$var:-}"
    [ -n "$val" ] || die "falta la variable obligatoria $var"
  done
}

# Convierte cada LDAP_*_PASSWORD_FILE en LDAP_*_PASSWORD (Docker secrets).
load_secret_files() {
  for fvar in $(env | sed -n 's/^\(LDAP_[A-Z0-9_]*_PASSWORD_FILE\)=.*/\1/p'); do
    file=$(printenv "$fvar")
    [ -r "$file" ] || die "$fvar apunta a un archivo que no se puede leer"
    val=$(cat "$file")
    export "${fvar%_FILE}=$val"
    unset "$fvar"
  done
}

# Genera LDAP_*_PASSWORD_HASH (ARGON2) para cada LDAP_*_PASSWORD.
hash_passwords() {
  for var in $(env | sed -n 's/^\(LDAP_[A-Z0-9_]*_PASSWORD\)=.*/\1/p'); do
    eval "val=\${$var}"
    hash=$(printf '%s' "$val" | slappasswd -o module-path=/usr/lib/openldap -o module-load=argon2.so -h '{ARGON2}' -T /dev/stdin)
    export "${var}_HASH=$hash"
  done
}

# Borra de este proceso las contraseñas y sus hashes antes de ejecutar slapd.
forget_passwords() {
  for var in $(env | sed -n 's/^\(LDAP_[A-Z0-9_]*_PASSWORD\(_HASH\)\{0,1\}\)=.*/\1/p'); do
    unset "$var"
  done
}

# render <plantilla>: sustituye solo los ${VAR} que usa la plantilla; falla si alguno no está definido.
render() {
  # shellcheck disable=SC2016  # buscamos el texto literal ${VAR}
  vars=$(grep -o '\${[A-Za-z_][A-Za-z0-9_]*}' "$1" | sort -u || true)
  for placeholder in $vars; do
    var=${placeholder#??}
    var=${var%?}
    eval "val=\${$var:-}"
    [ -n "$val" ] || die "$(basename "$1") usa \${$var}, que no está definida"
  done
  envsubst "$vars" < "$1"
}

initialize() {
  echo "entrypoint: primer arranque, inicializando el directorio"
  rm -rf "$CONFIG_DIR" "$DATA_DIR"
  mkdir -p "$CONFIG_DIR" "$DATA_DIR"
  work=$(mktemp -d)

  hash_passwords
  render "$TEMPLATES_DIR/config.ldif" > "$work/config.ldif"
  {
    render "$TEMPLATES_DIR/base.ldif"
    for seed in "$SEED_DIR"/*.ldif; do
      [ -e "$seed" ] || continue
      echo
      render "$seed"
    done
  } > "$work/data.ldif"

  slapadd -n 0 -F "$CONFIG_DIR" -l "$work/config.ldif"
  slapadd -n 1 -F "$CONFIG_DIR" -l "$work/data.ldif"
  rm -rf "$work"
  touch "$MARKER"
}

require LDAP_BASE_DN LDAP_ORG_NAME LDAP_PORT LDAP_SERVICE_CN LDAP_DB_MAX_SIZE LDAP_LOG_LEVEL
echo "$LDAP_BASE_DN" | grep -Eq '^dc=[A-Za-z0-9-]+(,dc=[A-Za-z0-9-]+)*$' \
  || die "LDAP_BASE_DN debe tener la forma dc=ejemplo,dc=org"
LDAP_DC=${LDAP_BASE_DN%%,*}
export LDAP_DC="${LDAP_DC#dc=}"

load_secret_files
require LDAP_ADMIN_PASSWORD LDAP_SERVICE_PASSWORD

[ -f "$MARKER" ] || initialize
forget_passwords

exec slapd -d "$LDAP_LOG_LEVEL" -F "$CONFIG_DIR" -h "ldap://0.0.0.0:${LDAP_PORT}/"
```

Notas de diseño:
- `render` usa `envsubst "$vars"` para sustituir **solo** los placeholders de la plantilla; así un `$` dentro de un hash o de un valor no se toca.
- Si un primer arranque falló a medias no existe `$MARKER`, así que `initialize` borra lo que haya quedado y empieza de cero.
- Las funciones `die` dentro de `{ ... } > archivo` salen del script porque las llaves no crean un subshell en `sh`.

- [ ] **Step 8: Implementar `ldap/Dockerfile`**

```dockerfile
# syntax=docker/dockerfile:1
ARG ALPINE_VERSION=3.24
FROM alpine:${ALPINE_VERSION}

RUN apk add --no-cache \
      openldap \
      openldap-back-mdb \
      openldap-clients \
      openldap-passwd-argon2 \
      gettext-envsubst \
 && install -d -o ldap -g ldap -m 0700 /var/lib/openldap

COPY --chmod=0755 entrypoint.sh /usr/local/bin/entrypoint.sh
COPY templates/ /etc/openldap/templates/

# uid/gid del usuario `ldap` que crea el paquete openldap de Alpine (numérico: no depende de /etc/passwd)
USER 100:101
VOLUME /var/lib/openldap

HEALTHCHECK --interval=10s --timeout=3s --start-period=30s --start-interval=1s \
  CMD ["sh", "-c", "ldapsearch -x -H \"ldap://127.0.0.1:${LDAP_PORT}\" -b '' -s base namingContexts >/dev/null"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
```

- [ ] **Step 9: Implementar `.hadolint.yaml`**

```yaml
ignored:
  # Las versiones de los paquetes de Alpine se fijan mediante ALPINE_VERSION;
  # fijar cada paquete rompe el build cuando Alpine publica parches de seguridad.
  - DL3018
```

- [ ] **Step 10: Ejecutar los tests hasta que pasen**

Run: `make test-ldap-image`
Expected: todos `ok` y `OK`.

Si falla el build o el arranque, verificar dentro de la imagen (no adivinar):
- Nombres de paquetes: `docker run --rm alpine:3.24 sh -c 'apk update -q && apk search openldap gettext-envsubst'`
- Módulos: `docker run --rm --entrypoint ls auth-ldap:test /usr/lib/openldap` (debe listar `back_mdb.so` y `argon2.so`)
- Schemas: `docker run --rm --entrypoint ls auth-ldap:test /etc/openldap/schema`
- Usuario: `docker run --rm --entrypoint id auth-ldap:test`
- Nivel de log: si `slapd -d stats` no acepta la palabra, usar `LDAP_LOG_LEVEL=256` en el test y en `.env.example`.
- Logs del arranque: `docker logs <cid>`.

Corregir la causa en el archivo correspondiente y volver a ejecutar. Si algún ajuste cambia el contrato de *Interfaces*, actualizar este plan.

- [ ] **Step 11: Lint**

Run: `make lint`
Expected: shellcheck y hadolint sin hallazgos.

- [ ] **Step 12: Commit**

```bash
git add ldap/ .hadolint.yaml test/ldap-image.sh Makefile
git commit -m "feat(ldap): own OpenLDAP image configured from env with argon2 and least-privilege ACLs

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: docker-compose con postgres + ldap y seed de desarrollo (issue #2, parte 2)

**Files:**
- Create: `docker-compose.yml`, `docker-compose.dev.yml`, `ldap/seed/users.ldif`, `test/infra.sh`
- Modify: `.env.example`, `Makefile` (targets `up`, `down`, `clean`, `logs`, `test-infra`, `test`), `README.md` (sección de uso)

**Interfaces:**
- Consumes: el contrato de la imagen `ldap` (Task 2); `test/lib.sh` (`load_env`, `check*`, `summary`).
- Produces:
  - Servicios `postgres` y `ldap` en el compose; secretos montados en `/run/secrets/{postgres_password,ldap_admin_password,ldap_service_password,ldap_seed_user_password}`.
  - Usuarios semilla `uid=alice` y `uid=bob` en `ou=users`, con la contraseña `LDAP_SEED_USER_PASSWORD`; grupo `cn=staff,ou=groups` con ambos.
  - Make: `up` (build + `--wait`), `down`, `clean` (borra volúmenes), `logs`, `test-infra`.

- [ ] **Step 1: Escribir el test que falla, `test/infra.sh`**

```bash
#!/usr/bin/env bash
# Tests de integración del compose de desarrollo (postgres + ldap con seed).
# Requiere los servicios levantados: make test-infra lo hace.
set -u
cd "$(dirname "$0")/.." || exit 1
# shellcheck source=test/lib.sh
. test/lib.sh
load_env

read -ra DC <<< "${COMPOSE:?COMPOSE no definida (usa make test-infra)}"
in_ldap() { "${DC[@]}" exec -T ldap "$@"; }

URI="ldap://127.0.0.1:${LDAP_PORT}"
USERS="ou=users,${LDAP_BASE_DN}"
SVC_DN="cn=${LDAP_SERVICE_CN},ou=services,${LDAP_BASE_DN}"
ALICE="uid=alice,${USERS}"
SVC_PW=/run/secrets/ldap_service_password
SEED_PW=/run/secrets/ldap_seed_user_password

as_svc()   { in_ldap ldapsearch -x -LLL -H "$URI" -D "$SVC_DN" -y "$SVC_PW" "$@"; }
as_alice() { in_ldap ldapsearch -x -LLL -H "$URI" -D "$ALICE" -y "$SEED_PW" "$@"; }
as_anon()  { in_ldap ldapsearch -x -LLL -H "$URI" "$@"; }
alice_whoami() { in_ldap ldapwhoami -x -H "$URI" -D "$ALICE" -y "$SEED_PW"; }
svc_modify_alice() {
  printf 'dn: %s\nchangetype: modify\nreplace: mail\nmail: x@example.org\n' "$ALICE" \
    | in_ldap ldapmodify -x -H "$URI" -D "$SVC_DN" -y "$SVC_PW"
}
init_count() { "${DC[@]}" logs ldap 2>&1 | grep -c 'primer arranque'; }

echo "infra: postgres"
check_output "responde a select 1" '^1$' \
  "${DC[@]}" exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc 'select 1'

echo "infra: ldap"
check_output    "el Root DSE es legible de forma anónima" "namingContexts: ${LDAP_BASE_DN}" \
  as_anon -b "" -s base namingContexts
check_no_output "el anónimo no ve usuarios" 'dn: uid=' as_anon -b "$USERS" '(uid=*)'
check_output    "la cuenta de servicio encuentra a alice con mail" '^mail: ' \
  as_svc -b "$USERS" '(uid=alice)' uid cn mail
check_no_output "la cuenta de servicio no lee userPassword" 'userPassword' \
  as_svc -b "$USERS" '(uid=alice)' userPassword
check_output    "la cuenta de servicio lee los miembros del grupo" "member: ${ALICE}" \
  as_svc -b "ou=groups,${LDAP_BASE_DN}" '(cn=staff)' member
check_output    "la cuenta de servicio no puede escribir" 'Insufficient access' svc_modify_alice
check_output    "alice se autentica" "dn:${ALICE}" alice_whoami
check_output    "contraseña errónea → Invalid credentials (49)" 'Invalid credentials \(49\)' \
  in_ldap ldapwhoami -x -H "$URI" -D "$ALICE" -w contraseña-incorrecta
check_no_output "alice no puede leer a bob" 'dn: uid=bob' as_alice -b "$USERS" '(uid=bob)'
check_no_output "cn=config no es legible" 'olcRootPW' as_anon -b cn=config

echo "infra: reinicio"
before=$(init_count)
"${DC[@]}" restart ldap >/dev/null 2>&1
"${DC[@]}" up -d --wait ldap >/dev/null 2>&1
check "no se vuelve a inicializar al reiniciar" test "$(init_count)" = "$before"
check_output "alice sigue autenticándose tras el reinicio" "dn:${ALICE}" alice_whoami

summary
```

```bash
chmod +x test/infra.sh
```

- [ ] **Step 2: Agregar los targets al `Makefile`**

```makefile
.PHONY: help env up down clean logs test test-repo test-ldap-image test-infra lint secrets-scan

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

test-infra: up ## Tests de integración del compose
	@test/infra.sh
```

- [ ] **Step 3: Ejecutar para ver que falla**

Run: `make env && make test-infra`
Expected: FAIL en `docker compose` (no existen `docker-compose.yml` ni `docker-compose.dev.yml`).

(Si `.env` ya existía de la Task 1: `rm .env && make env` después del Step 4, para que incluya las variables nuevas.)

- [ ] **Step 4: Ampliar `.env.example`**

```dotenv
# Plantilla de configuración. Crea tu .env con:  make env
# - Los valores __GENERATE__ se reemplazan por secretos aleatorios.
# - Sin comillas ni espacios en los valores.

COMPOSE_PROJECT_NAME=auth

# ── PostgreSQL ────────────────────────────────────────────
POSTGRES_DB=auth
POSTGRES_USER=auth
POSTGRES_PASSWORD=__GENERATE__
# Puerto publicado en 127.0.0.1 (solo docker-compose.dev.yml)
POSTGRES_HOST_PORT=5432

# ── OpenLDAP (imagen propia en ldap/) ─────────────────────
LDAP_BASE_DN=dc=auth,dc=local
LDAP_ORG_NAME=Auth
# Puerto de slapd dentro del contenedor (non-root, por eso >1024)
LDAP_PORT=1389
# Puerto publicado en 127.0.0.1 (solo docker-compose.dev.yml)
LDAP_HOST_PORT=1389
# Cuenta de solo lectura que usa auth-svc: cn=<valor>,ou=services,<LDAP_BASE_DN>
LDAP_SERVICE_CN=auth-svc
# Tamaño máximo de la base mdb en bytes (1 GiB)
LDAP_DB_MAX_SIZE=1073741824
LDAP_LOG_LEVEL=stats
LDAP_ADMIN_PASSWORD=__GENERATE__
LDAP_SERVICE_PASSWORD=__GENERATE__
# Solo desarrollo: contraseña de los usuarios semilla (alice, bob)
LDAP_SEED_USER_PASSWORD=__GENERATE__
```

- [ ] **Step 5: Implementar `docker-compose.yml`**

```yaml
# Servicios base. Toda la configuración sale de .env (ver .env.example);
# ${VAR:?} hace fallar a compose si falta una variable.
services:
  postgres:
    image: postgres:18.6-alpine3.24
    environment:
      POSTGRES_DB: ${POSTGRES_DB:?POSTGRES_DB no definida}
      POSTGRES_USER: ${POSTGRES_USER:?POSTGRES_USER no definida}
      POSTGRES_PASSWORD_FILE: /run/secrets/postgres_password
    secrets:
      - postgres_password
    volumes:
      - pgdata:/var/lib/postgresql
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U \"$$POSTGRES_USER\" -d \"$$POSTGRES_DB\""]
      interval: 10s
      timeout: 3s
      retries: 5
      start_period: 30s
      start_interval: 1s
    security_opt:
      - no-new-privileges:true
    restart: unless-stopped

  ldap:
    build: ./ldap
    environment:
      LDAP_BASE_DN: ${LDAP_BASE_DN:?LDAP_BASE_DN no definida}
      LDAP_ORG_NAME: ${LDAP_ORG_NAME:?LDAP_ORG_NAME no definida}
      LDAP_PORT: ${LDAP_PORT:?LDAP_PORT no definida}
      LDAP_SERVICE_CN: ${LDAP_SERVICE_CN:?LDAP_SERVICE_CN no definida}
      LDAP_DB_MAX_SIZE: ${LDAP_DB_MAX_SIZE:?LDAP_DB_MAX_SIZE no definida}
      LDAP_LOG_LEVEL: ${LDAP_LOG_LEVEL:?LDAP_LOG_LEVEL no definida}
      LDAP_ADMIN_PASSWORD_FILE: /run/secrets/ldap_admin_password
      LDAP_SERVICE_PASSWORD_FILE: /run/secrets/ldap_service_password
    secrets:
      - ldap_admin_password
      - ldap_service_password
    volumes:
      - ldapdata:/var/lib/openldap
    read_only: true
    tmpfs:
      - /tmp
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    restart: unless-stopped

# Archivos generados desde .env por `make secrets` (secrets/ está en .gitignore).
secrets:
  postgres_password:
    file: ./secrets/postgres_password
  ldap_admin_password:
    file: ./secrets/ldap_admin_password
  ldap_service_password:
    file: ./secrets/ldap_service_password

volumes:
  pgdata:
  ldapdata:
```

- [ ] **Step 6: Implementar `docker-compose.dev.yml`**

```yaml
# Solo desarrollo: publica los puertos en localhost y carga los usuarios semilla.
services:
  postgres:
    ports:
      - "127.0.0.1:${POSTGRES_HOST_PORT:?POSTGRES_HOST_PORT no definida}:5432"

  ldap:
    ports:
      - "127.0.0.1:${LDAP_HOST_PORT:?LDAP_HOST_PORT no definida}:${LDAP_PORT:?LDAP_PORT no definida}"
    environment:
      LDAP_SEED_USER_PASSWORD_FILE: /run/secrets/ldap_seed_user_password
    secrets:
      - ldap_seed_user_password
    volumes:
      - ./ldap/seed:/seed:ro

secrets:
  ldap_seed_user_password:
    file: ./secrets/ldap_seed_user_password
```

- [ ] **Step 7: Implementar `ldap/seed/users.ldif`**

```ldif
dn: uid=alice,ou=users,${LDAP_BASE_DN}
objectClass: inetOrgPerson
uid: alice
cn: Alice Example
sn: Example
givenName: Alice
mail: alice@example.org
userPassword: ${LDAP_SEED_USER_PASSWORD_HASH}

dn: uid=bob,ou=users,${LDAP_BASE_DN}
objectClass: inetOrgPerson
uid: bob
cn: Bob Example
sn: Example
givenName: Bob
mail: bob@example.org
userPassword: ${LDAP_SEED_USER_PASSWORD_HASH}

dn: cn=staff,ou=groups,${LDAP_BASE_DN}
objectClass: groupOfNames
cn: staff
member: uid=alice,ou=users,${LDAP_BASE_DN}
member: uid=bob,ou=users,${LDAP_BASE_DN}
```

- [ ] **Step 8: Ejecutar los tests hasta que pasen**

Run: `make clean; make test-infra`
Expected: todos `ok` y `OK`.

Si falla, verificar:
- Permisos de los secretos para el usuario `ldap`: `docker compose ... exec ldap ls -l /run/secrets`. Si no son legibles, usar la sintaxis larga en el servicio (`- source: ldap_admin_password` + `mode: 0444`) y repetir.
- `ldapwhoami -y` usa el archivo tal cual: si el secreto tiene un salto de línea al final, el bind falla. Comprobar con `exec ldap sh -c 'od -c /run/secrets/ldap_seed_user_password | tail -2'`.
- Logs: `make logs`.

- [ ] **Step 9: Suite completa + lint**

Run: `make test && make lint`
Expected: `OK` en los tres scripts; lint sin hallazgos.

- [ ] **Step 10: Documentar el uso en el `README.md`**

Agregar después de "Primeros pasos":

````markdown
## Servicios de desarrollo

```bash
make up      # postgres + ldap (espera a que estén healthy)
make logs
make down    # detiene
make clean   # detiene y BORRA los datos
```

- Postgres: `127.0.0.1:$POSTGRES_HOST_PORT`, base/usuario en `.env`.
- LDAP: `ldap://127.0.0.1:$LDAP_HOST_PORT`, base `LDAP_BASE_DN`.
  Usuarios semilla `alice` y `bob` (contraseña `LDAP_SEED_USER_PASSWORD` de tu `.env`):

```bash
ldapwhoami -x -H ldap://127.0.0.1:1389 -D uid=alice,ou=users,dc=auth,dc=local -W
```

El seed se carga solo en el **primer** arranque; para recargarlo: `make clean && make up`.
````

- [ ] **Step 11: Commit, push y PR**

```bash
git add docker-compose.yml docker-compose.dev.yml ldap/seed/ test/infra.sh .env.example Makefile README.md
git commit -m "feat(infra): docker-compose with postgres and ldap, dev seed and integration tests

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push -u origin feat/2-ldap-image-compose
gh pr create --title "feat: imagen OpenLDAP propia + docker-compose base" --body "Closes #2

- Imagen \`ldap\` propia (Alpine + OpenLDAP 2.6): config desde env, secretos \`*_FILE\`, ARGON2, init idempotente, ACLs de mínimo privilegio, non-root/read-only
- Compose con postgres + ldap; dev publica en 127.0.0.1 y carga el seed (alice, bob, staff)
- Tests: \`test/ldap-image.sh\` (imagen aislada) y \`test/infra.sh\` (integración)

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
```

- [ ] **Step 12: Merge**

Con el PR revisado (todavía no hay CI; la verificación es `make clean && make test` en local):

```bash
gh pr merge --squash --delete-branch
git switch main && git pull
```

---

### Task 4: CI en GitHub Actions (issue #3)

**Files:**
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: targets `make lint`, `make secrets-scan`, `make env`, `make test`, `make logs`.
- Produces: el check `ci` (job agregador), que es el que requiere la protección de rama en la Task 5. Las etapas siguientes agregan jobs y los suman al `needs` de `ci`.

- [ ] **Step 1: Crear la rama**

```bash
git switch main && git pull && git switch -c feat/3-ci
```

- [ ] **Step 2: Implementar `.github/workflows/ci.yml`**

```yaml
name: CI

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - run: make lint

  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
      - run: make secrets-scan

  infra:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - run: make env
      - run: make test
      - if: failure()
        run: make logs

  # Único check requerido por la protección de main. Al agregar un job, súmalo a `needs`.
  ci:
    if: always()
    needs: [lint, secrets, infra]
    runs-on: ubuntu-latest
    steps:
      - name: Todos los jobs pasaron
        run: |
          test "${{ contains(needs.*.result, 'failure') || contains(needs.*.result, 'cancelled') || contains(needs.*.result, 'skipped') }}" = "false"
```

- [ ] **Step 3: Verificar el permiso `workflow` de gh**

Run: `gh auth status 2>&1 | grep -o "'workflow'"`
Expected: `'workflow'`. Si no aparece, pedir al humano `gh auth refresh -s workflow` y esperar.

- [ ] **Step 4: Commit, push y PR; ver el CI en verde**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: lint, secret scan and infra smoke tests via make targets

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push -u origin feat/3-ci
gh pr create --title "ci: GitHub Actions con lint, gitleaks y smoke tests" --body "Closes #3

El CI solo invoca targets de \`make\` (lo mismo que en local). \`ci\` es el job agregador y el único check requerido.

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
gh pr checks --watch
```

Expected: `lint`, `secrets`, `infra` y `ci` en verde.

- [ ] **Step 5: Comprobar que el CI detecta un fallo (y revertir)**

```bash
printf '#!/usr/bin/env bash\necho $UNQUOTED\n' > scripts/ci-canary.sh
git add scripts/ci-canary.sh && git commit -m "test: ci canary (se revierte)" && git push
gh pr checks --watch   # Expected: lint FAIL (SC2086) y ci FAIL
git revert --no-edit HEAD && git push
gh pr checks --watch   # Expected: todo en verde de nuevo
```


- [ ] **Step 6: Merge**

Con el PR revisado y `ci` en verde:

```bash
gh pr merge --squash --delete-branch
git switch main && git pull
```

---

### Task 5: Gobernanza del repo (issue #4)

**Files:**
- Create: `.github/PULL_REQUEST_TEMPLATE.md`, `.github/ISSUE_TEMPLATE/feature.md`

**Interfaces:**
- Consumes: el check `ci` (Task 4).
- Produces: `main` protegida (PR obligatorio, `ci` en verde, historial lineal, sin force-push, aplica también a admins).

- [ ] **Step 1: Crear la rama**

```bash
git switch main && git pull && git switch -c feat/4-repo-governance
```

- [ ] **Step 2: Implementar `.github/PULL_REQUEST_TEMPLATE.md`**

```markdown
Closes #

## Qué cambia


## Checklist
- [ ] Empecé con un test que falla (TDD) y ahora todos pasan (`make test`)
- [ ] `make lint` y `make secrets-scan` limpios
- [ ] Nada hardcodeado: configuración por env y secretos por `*_FILE`
- [ ] Sin secretos ni tokens en logs o mensajes de error
- [ ] Documentación actualizada (README / `.env.example` / spec) si aplica
```

- [ ] **Step 3: Implementar `.github/ISSUE_TEMPLATE/feature.md`**

```markdown
---
name: Feature
about: Una feature de una etapa del plan
labels: []
---

## Descripción


## Criterios de aceptación
- [ ]

## Tests (TDD)
-

## Seguridad
-

---
Spec: `docs/superpowers/specs/2026-09-24-auth-dashboard-design.md`
**Definition of Done:** tests en verde en CI · sin valores hardcodeados (config por env/secrets) · KISS/DRY · PR con `Closes #<n>`.
```

- [ ] **Step 4: Configurar las opciones de merge**

```bash
gh repo edit JesusMaVe/auth --enable-squash-merge --enable-merge-commit=false \
  --enable-rebase-merge=false --delete-branch-on-merge
```

- [ ] **Step 5: Proteger `main`**

```bash
gh api -X PUT repos/JesusMaVe/auth/branches/main/protection --input - <<'JSON'
{
  "required_status_checks": { "strict": true, "checks": [{ "context": "ci" }] },
  "enforce_admins": true,
  "required_pull_request_reviews": { "required_approving_review_count": 0 },
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
```

- [ ] **Step 6: Verificar la protección**

```bash
gh api repos/JesusMaVe/auth/branches/main/protection \
  --jq '{checks: [.required_status_checks.checks[].context], admins: .enforce_admins.enabled, linear: .required_linear_history.enabled}'
```

Expected: `{"checks":["ci"],"admins":true,"linear":true}`

```bash
git switch main && git commit --allow-empty -m "test: push directo (debe rechazarse)"
git push origin main   # Expected: rechazado con "protected branch"
git reset --hard origin/main
```

- [ ] **Step 7: Commit, push, PR y merge**

```bash
git switch feat/4-repo-governance
git add .github/PULL_REQUEST_TEMPLATE.md .github/ISSUE_TEMPLATE/feature.md
git commit -m "chore: PR and issue templates

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push -u origin feat/4-repo-governance
gh pr create --title "chore: plantillas y protección de main" --body "Closes #4

- Plantillas de PR e issue con checklist de TDD y seguridad
- main protegida: PR obligatorio, check \`ci\`, historial lineal, sin force-push; squash merge y borrado de ramas

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
gh pr checks --watch
```

- [ ] **Step 8: Merge**

Con el PR revisado y `ci` en verde (la protección ya exige el check):

```bash
gh pr merge --squash --delete-branch
git switch main && git pull
```

---

## Cierre de la etapa

- [ ] Los PRs de #1–#4 están mergeados en `main` (squash) y los issues se cerraron solos por el `Closes #n`.
- [ ] En `main`: `make clean && make test` en verde en local; el CI de `main` en verde.
- [ ] El milestone "Etapa 0 – Fundaciones" queda en 4/4 cerrados: `gh api repos/JesusMaVe/auth/milestones/1 --jq '{open: .open_issues, closed: .closed_issues}'`.
