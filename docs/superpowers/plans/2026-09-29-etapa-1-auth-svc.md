# Etapa 1 – API de LDAP (auth-svc) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Un servicio Go `auth-svc` que recibe `POST /token {username,password}`, autentica contra nuestro OpenLDAP con search-then-bind y devuelve un JWT EdDSA; corre en el compose junto a `ldap`.

**Architecture:** Módulo Go en `auth-svc/` con cinco paquetes pequeños: `config` (env fail-fast), `ldap` (search-then-bind), `token` (firma EdDSA), `ratelimit` (token bucket por clave) y `httpapi` (handler). `cmd/auth-svc` los conecta. La clave privada la genera `make secrets/up` con openssl y llega como Docker secret; la pública queda en `secrets/jwt_public_key` para el repo `api`.

**Tech Stack:** Go 1.27.1 (`net/http`, `log/slog`), `github.com/go-ldap/ldap/v3` v3.4.14, `github.com/golang-jwt/jwt/v5` v5.3.1, `golang.org/x/time/rate` v0.16.0, `github.com/testcontainers/testcontainers-go` v0.44.0, imagen `golang:1.27.1-alpine3.24` → `gcr.io/distroless/static-debian13:nonroot`.

**Spec:** `docs/superpowers/specs/2026-09-24-auth-dashboard-design.md`

## Global Constraints

- Issues: #5 (config), #6 (cliente LDAP), #7 (emisor JWT), #8 (`POST /token` + rate limit + Dockerfile). Un issue = una rama `feat/<n>-<slug>` = un PR con `Closes #n`, squash a `main`. Conventional Commits. Cada commit termina con `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`; cada PR con `🤖 Generated with [Claude Code](https://claude.com/claude-code)`.
- TDD: test en rojo → implementación mínima → verde → commit.
- Nada hardcodeado: toda la configuración por env; secretos solo por `*_FILE`. Sin defaults: todas las variables son obligatorias y están en `.env.example`.
- Versiones fijadas en el código (go.mod, Dockerfile, Makefile, SHA de las actions).
- El Makefile es el único punto de entrada; el CI solo invoca targets de `make`.
- Nunca loguear contraseñas, tokens ni valores de secretos (tampoco en mensajes de error de config).
- Puertos de desarrollo solo en `127.0.0.1`. Contenedores non-root, `read_only`, `cap_drop: ALL`, `no-new-privileges`.
- Algoritmo JWT fijo: EdDSA. Claims: `sub`, `name`, `email`, `groups`, `iss`, `aud`, `iat`, `nbf`, `exp`, `jti`.
- Errores genéricos: 401 `{"error":"invalid credentials"}` sin distinguir usuario inexistente de contraseña errónea.
- Tests de shell: usan `test/lib.sh`; sin `set -e`/`pipefail`.
- Módulo Go: `github.com/JesusMaVe/auth/auth-svc`.

## Review Focus

- Usuario con otra capitalización (`ALICE`): LDAP compara `uid` sin distinguir mayúsculas; el `sub` del token debe ser el `uid` canónico del directorio (`alice`), no lo que escribió el usuario → test en Task 2.
- Contraseña con espacios al inicio o al final: se pasa intacta al bind (nunca se recorta) → test en Task 5.
- LDAP caído: `/token` responde 502 rápido (dentro del timeout), no se cuelga ni responde 401 → tests en Task 2 y Task 5.
- Muchos usuarios distintos contra el rate limit: el mapa de limitadores no crece sin límite; las entradas inactivas se barren → test en Task 4.
- Detrás del proxy de Vite todas las peticiones llegan con la misma IP: el límite por IP es compartido; el límite por usuario sigue siendo independiente → test de claves independientes en Task 4 y nota en el README (Task 6).

---

### Task 1: Módulo Go + paquete `config` fail-fast + targets de make y CI (#5)

**Files:**
- Create: `auth-svc/go.mod`
- Create: `auth-svc/internal/config/config.go`
- Test: `auth-svc/internal/config/config_test.go`
- Modify: `Makefile` (variables de versión, `test`, `lint`, nuevo `test-auth-svc`)
- Modify: `.github/workflows/ci.yml` (setup-go en `lint` e `infra`)

**Interfaces:**
- Produces:
  ```go
  package config
  type Config struct {
      Port               string
      LogLevel           slog.Level
      LDAPURL            string
      LDAPBindDN         string
      LDAPBindPassword   string
      LDAPUsersDN        string
      LDAPGroupsDN       string
      LDAPStartTLS       bool
      LDAPTimeout        time.Duration
      JWTPrivateKeyPEM   []byte
      JWTIssuer          string
      JWTAudience        string
      JWTTTL             time.Duration
      RateLimitPerMinute int
      RateLimitBurst     int
  }
  func Load(getenv func(string) string) (Config, error)
  ```
  Variables de entorno: `AUTH_SVC_PORT`, `LOG_LEVEL`, `LDAP_URL`, `LDAP_BIND_DN`, `LDAP_BIND_PASSWORD_FILE`, `LDAP_USERS_DN`, `LDAP_GROUPS_DN`, `LDAP_STARTTLS`, `LDAP_TIMEOUT`, `JWT_PRIVATE_KEY_FILE`, `JWT_ISSUER`, `JWT_AUDIENCE`, `JWT_TTL`, `RATE_LIMIT_PER_MINUTE`, `RATE_LIMIT_BURST`.

- [ ] **Step 1: Rama y módulo**

```bash
git switch main && git pull -q
git switch -c feat/5-auth-svc-config
mkdir -p auth-svc/internal/config
cd auth-svc && go mod init github.com/JesusMaVe/auth/auth-svc && cd ..
```

Edita `auth-svc/go.mod` para que la línea `go` sea exactamente:

```
module github.com/JesusMaVe/auth/auth-svc

go 1.27.1
```

- [ ] **Step 2: Test que falla**

`auth-svc/internal/config/config_test.go`:

```go
package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const secretValue = "valor-secreto-que-no-debe-salir"

// validEnv devuelve un entorno completo y válido; los *_FILE apuntan a archivos temporales.
func validEnv(t *testing.T) map[string]string {
	t.Helper()
	dir := t.TempDir()
	pw := filepath.Join(dir, "ldap_pw")
	key := filepath.Join(dir, "jwt_key")
	if err := os.WriteFile(pw, []byte(secretValue+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		"AUTH_SVC_PORT":           "8081",
		"LOG_LEVEL":               "info",
		"LDAP_URL":                "ldap://ldap:1389",
		"LDAP_BIND_DN":            "cn=svc,ou=services,dc=test,dc=local",
		"LDAP_BIND_PASSWORD_FILE": pw,
		"LDAP_USERS_DN":           "ou=users,dc=test,dc=local",
		"LDAP_GROUPS_DN":          "ou=groups,dc=test,dc=local",
		"LDAP_STARTTLS":           "false",
		"LDAP_TIMEOUT":            "5s",
		"JWT_PRIVATE_KEY_FILE":    key,
		"JWT_ISSUER":              "auth-svc",
		"JWT_AUDIENCE":            "auth-dashboard-api",
		"JWT_TTL":                 "30m",
		"RATE_LIMIT_PER_MINUTE":   "10",
		"RATE_LIMIT_BURST":        "10",
	}
}

func load(env map[string]string) (Config, error) {
	return Load(func(k string) string { return env[k] })
}

func TestLoadValid(t *testing.T) {
	c, err := load(validEnv(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Port != "8081" || c.LDAPURL != "ldap://ldap:1389" || c.JWTIssuer != "auth-svc" {
		t.Errorf("valores inesperados: %+v", c)
	}
	if c.LDAPBindPassword != secretValue {
		t.Errorf("la contraseña debe leerse del archivo sin el salto de línea final")
	}
	if !strings.HasPrefix(string(c.JWTPrivateKeyPEM), "-----BEGIN PRIVATE KEY-----") {
		t.Errorf("JWTPrivateKeyPEM no se leyó del archivo")
	}
	if c.LDAPTimeout != 5*time.Second || c.JWTTTL != 30*time.Minute {
		t.Errorf("duraciones: timeout=%v ttl=%v", c.LDAPTimeout, c.JWTTTL)
	}
	if c.LDAPStartTLS || c.LogLevel != slog.LevelInfo || c.RateLimitPerMinute != 10 || c.RateLimitBurst != 10 {
		t.Errorf("valores inesperados: %+v", c)
	}
}

func TestLoadMissing(t *testing.T) {
	for key := range validEnv(t) {
		t.Run(key, func(t *testing.T) {
			env := validEnv(t)
			delete(env, key)
			_, err := load(env)
			if err == nil || !strings.Contains(err.Error(), key) {
				t.Fatalf("falta %s: se esperaba un error que la nombre, got %v", key, err)
			}
		})
	}
}

func TestLoadInvalid(t *testing.T) {
	cases := []struct{ key, value string }{
		{"AUTH_SVC_PORT", "0"},
		{"AUTH_SVC_PORT", "http"},
		{"LDAP_URL", "http://ldap:1389"},
		{"LDAP_URL", "ldap://"},
		{"LDAP_TIMEOUT", "5"},
		{"LDAP_TIMEOUT", "-1s"},
		{"JWT_TTL", "abc"},
		{"LDAP_STARTTLS", "si"},
		{"RATE_LIMIT_PER_MINUTE", "0"},
		{"RATE_LIMIT_BURST", "muchos"},
		{"LOG_LEVEL", "verbose"},
		{"LDAP_BIND_PASSWORD_FILE", "/no/existe"},
		{"JWT_PRIVATE_KEY_FILE", "/no/existe"},
	}
	for _, tc := range cases {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			env := validEnv(t)
			env[tc.key] = tc.value
			_, err := load(env)
			if err == nil || !strings.Contains(err.Error(), tc.key) {
				t.Fatalf("se esperaba un error que nombre %s, got %v", tc.key, err)
			}
			if strings.Contains(err.Error(), secretValue) {
				t.Fatalf("el error muestra el valor de un secreto: %v", err)
			}
		})
	}
}

func TestLoadEmptySecretFile(t *testing.T) {
	env := validEnv(t)
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env["LDAP_BIND_PASSWORD_FILE"] = empty
	if _, err := load(env); err == nil || !strings.Contains(err.Error(), "LDAP_BIND_PASSWORD_FILE") {
		t.Fatalf("un secreto vacío debe fallar, got %v", err)
	}
}

func TestLoadReportsAllErrors(t *testing.T) {
	_, err := load(map[string]string{})
	if err == nil {
		t.Fatal("se esperaba error")
	}
	for _, key := range []string{"AUTH_SVC_PORT", "LDAP_URL", "JWT_TTL"} {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("el error debe nombrar %s: %v", key, err)
		}
	}
}
```

- [ ] **Step 3: Verificar que falla**

Run: `cd auth-svc && go test ./internal/config/`
Expected: FAIL de compilación (`undefined: Load`, `undefined: Config`).

- [ ] **Step 4: Implementación mínima**

`auth-svc/internal/config/config.go`:

```go
// Package config lee y valida la configuración de auth-svc desde variables de entorno.
// Falla al arrancar si falta algo; los mensajes nombran la variable, nunca su valor.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Port               string
	LogLevel           slog.Level
	LDAPURL            string
	LDAPBindDN         string
	LDAPBindPassword   string
	LDAPUsersDN        string
	LDAPGroupsDN       string
	LDAPStartTLS       bool
	LDAPTimeout        time.Duration
	JWTPrivateKeyPEM   []byte
	JWTIssuer          string
	JWTAudience        string
	JWTTTL             time.Duration
	RateLimitPerMinute int
	RateLimitBurst     int
}

// Load construye la Config con getenv (os.Getenv en producción) y devuelve todos los errores juntos.
func Load(getenv func(string) string) (Config, error) {
	r := reader{getenv: getenv}
	c := Config{
		Port:               r.port("AUTH_SVC_PORT"),
		LogLevel:           r.logLevel("LOG_LEVEL"),
		LDAPURL:            r.url("LDAP_URL", "ldap", "ldaps"),
		LDAPBindDN:         r.str("LDAP_BIND_DN"),
		LDAPBindPassword:   string(r.file("LDAP_BIND_PASSWORD_FILE")),
		LDAPUsersDN:        r.str("LDAP_USERS_DN"),
		LDAPGroupsDN:       r.str("LDAP_GROUPS_DN"),
		LDAPStartTLS:       r.boolean("LDAP_STARTTLS"),
		LDAPTimeout:        r.duration("LDAP_TIMEOUT"),
		JWTPrivateKeyPEM:   r.file("JWT_PRIVATE_KEY_FILE"),
		JWTIssuer:          r.str("JWT_ISSUER"),
		JWTAudience:        r.str("JWT_AUDIENCE"),
		JWTTTL:             r.duration("JWT_TTL"),
		RateLimitPerMinute: r.positiveInt("RATE_LIMIT_PER_MINUTE"),
		RateLimitBurst:     r.positiveInt("RATE_LIMIT_BURST"),
	}
	if err := errors.Join(r.errs...); err != nil {
		return Config{}, fmt.Errorf("config:\n%w", err)
	}
	return c, nil
}

type reader struct {
	getenv func(string) string
	errs   []error
}

func (r *reader) invalid(key, want string) {
	r.errs = append(r.errs, fmt.Errorf("%s inválida: %s", key, want))
}

func (r *reader) str(key string) string {
	v := strings.TrimSpace(r.getenv(key))
	if v == "" {
		r.errs = append(r.errs, fmt.Errorf("falta %s", key))
	}
	return v
}

func (r *reader) port(key string) string {
	v := r.str(key)
	if v == "" {
		return ""
	}
	if n, err := strconv.Atoi(v); err != nil || n < 1 || n > 65535 {
		r.invalid(key, "debe ser un puerto entre 1 y 65535")
	}
	return v
}

func (r *reader) positiveInt(key string) int {
	v := r.str(key)
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		r.invalid(key, "debe ser un entero positivo")
		return 0
	}
	return n
}

func (r *reader) duration(key string) time.Duration {
	v := r.str(key)
	if v == "" {
		return 0
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		r.invalid(key, "debe ser una duración positiva, p. ej. 15m")
		return 0
	}
	return d
}

func (r *reader) boolean(key string) bool {
	v := r.str(key)
	if v == "" {
		return false
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		r.invalid(key, "debe ser true o false")
	}
	return b
}

func (r *reader) url(key string, schemes ...string) string {
	v := r.str(key)
	if v == "" {
		return ""
	}
	u, err := url.Parse(v)
	if err != nil || !slices.Contains(schemes, u.Scheme) || u.Host == "" {
		r.invalid(key, "debe ser una URL con esquema "+strings.Join(schemes, " o "))
	}
	return v
}

func (r *reader) logLevel(key string) slog.Level {
	v := r.str(key)
	var l slog.Level
	if v != "" && l.UnmarshalText([]byte(v)) != nil {
		r.invalid(key, "debe ser debug, info, warn o error")
	}
	return l
}

// file lee un secreto montado como archivo (Docker secret) y quita el salto de línea final.
func (r *reader) file(key string) []byte {
	path := r.str(key)
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path) // #nosec G304 -- la ruta la define el operador (Docker secret)
	if err != nil {
		r.invalid(key, "no se puede leer el archivo")
		return nil
	}
	b = bytes.TrimRight(b, "\r\n")
	if len(b) == 0 {
		r.invalid(key, "el archivo está vacío")
	}
	return b
}
```

- [ ] **Step 5: Verificar que pasa**

Run: `cd auth-svc && go test -race ./internal/config/ -v`
Expected: PASS en todos los subtests.

- [ ] **Step 6: Targets de make**

En `Makefile`, bajo las versiones fijadas, agrega:

```make
GOSEC_VERSION       := v2.29.0
GOVULNCHECK_VERSION := v1.8.0
```

Cambia la línea `.PHONY` para incluir `test-auth-svc`, la línea `test:` por:

```make
test: test-repo test-ldap-image test-postgres-image test-auth-svc test-infra test-rotation ## Corre todos los tests
```

agrega después de `test-postgres-image`:

```make
test-auth-svc: ## Tests de Go de auth-svc (unitarios + integración con la imagen ldap vía testcontainers)
	docker build -q -t $(LDAP_TEST_IMAGE) ldap >/dev/null
	cd auth-svc && LDAP_TEST_IMAGE=$(LDAP_TEST_IMAGE) go test -race -count=1 ./...
```

y reemplaza el target `lint` por:

```make
lint: ## shellcheck + hadolint + gofmt, go vet, gosec y govulncheck
	docker run --rm -v "$(CURDIR):/mnt" -w /mnt $(SHELLCHECK_IMAGE) -x $(SHELL_SCRIPTS)
	$(if $(DOCKERFILES),docker run --rm -v "$(CURDIR):/mnt" -w /mnt $(HADOLINT_IMAGE) hadolint $(DOCKERFILES))
	cd auth-svc && test -z "$$(gofmt -l . | tee /dev/stderr)"
	cd auth-svc && go vet ./...
	cd auth-svc && go run github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION) -quiet ./...
	cd auth-svc && go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...
```

- [ ] **Step 7: CI con Go**

En `.github/workflows/ci.yml`, en los jobs `lint` e `infra`, agrega después del `checkout`:

```yaml
      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with:
          go-version-file: auth-svc/go.mod
          cache: false
```

- [ ] **Step 8: Verificar**

Run: `make lint && make test-auth-svc`
Expected: sin hallazgos de gofmt/vet/gosec/govulncheck; `ok github.com/JesusMaVe/auth/auth-svc/internal/config`.

- [ ] **Step 9: Commit y PR**

```bash
git add auth-svc Makefile .github/workflows/ci.yml docs/superpowers/plans/2026-09-29-etapa-1-auth-svc.md
git commit -m "feat(auth-svc): paquete config con validación fail-fast

Closes #5

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push -u origin feat/5-auth-svc-config
gh pr create --title "feat(auth-svc): paquete config con validación fail-fast" --body "Módulo Go de auth-svc, \`internal/config\` (todas las variables obligatorias, secretos por \`*_FILE\`, errores sin valores), targets \`test-auth-svc\` y lint de Go, y setup-go en el CI.

Closes #5

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
gh pr checks --watch
gh pr merge --squash --delete-branch && git switch main && git pull -q
```

---

### Task 2: Cliente LDAP search-then-bind (#6)

**Files:**
- Create: `auth-svc/internal/ldap/ldap.go`
- Test: `auth-svc/internal/ldap/ldap_test.go`

**Interfaces:**
- Consumes: nada de otras tasks (recibe su propia `Config`).
- Produces:
  ```go
  package ldap
  var ErrInvalidCredentials error
  type Identity struct { Username, Name, Email string; Groups []string }
  type Config struct {
      URL, BindDN, BindPassword, UsersDN, GroupsDN string
      StartTLS bool
      Timeout  time.Duration
  }
  func New(cfg Config) *Client
  func (c *Client) Authenticate(ctx context.Context, username, password string) (Identity, error)
  ```
  `Groups` nunca es `nil` (lista vacía si no hay grupos). Cualquier error que no sea `ErrInvalidCredentials` significa "LDAP no disponible o mal configurado".

- [ ] **Step 1: Rama y dependencias**

```bash
git switch -c feat/6-auth-svc-ldap
mkdir -p auth-svc/internal/ldap
cd auth-svc
go get github.com/go-ldap/ldap/v3@v3.4.14 github.com/testcontainers/testcontainers-go@v0.44.0
cd ..
```

- [ ] **Step 2: Test que falla**

`auth-svc/internal/ldap/ldap_test.go`:

```go
package ldap

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	testBaseDN   = "dc=test,dc=local"
	svcPassword  = "svc-test"
	seedPassword = "seed-test"
)

// startLDAP arranca nuestra imagen OpenLDAP (make la construye y exporta LDAP_TEST_IMAGE)
// con el seed de desarrollo (alice y bob en el grupo staff).
func startLDAP(t *testing.T) Config {
	t.Helper()
	image := os.Getenv("LDAP_TEST_IMAGE")
	if image == "" {
		t.Skip("LDAP_TEST_IMAGE no definida: corre `make test-auth-svc`")
	}
	seed, err := filepath.Abs("../../../ldap/seed/users.ldif")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ctr, err := testcontainers.Run(ctx, image,
		testcontainers.WithEnv(map[string]string{
			"LDAP_BASE_DN":            testBaseDN,
			"LDAP_ORG_NAME":           "Test",
			"LDAP_PORT":               "1389",
			"LDAP_SERVICE_CN":         "svc",
			"LDAP_DB_MAX_SIZE":        "104857600",
			"LDAP_LOG_LEVEL":          "stats",
			"LDAP_ADMIN_PASSWORD":     "admin-test",
			"LDAP_SERVICE_PASSWORD":   svcPassword,
			"LDAP_SEED_USER_PASSWORD": seedPassword,
		}),
		testcontainers.WithFiles(testcontainers.ContainerFile{
			HostFilePath: seed, ContainerFilePath: "/seed/users.ldif", FileMode: 0o644,
		}),
		testcontainers.WithExposedPorts("1389/tcp"),
		testcontainers.WithWaitStrategy(wait.ForHealthCheck().WithStartupTimeout(90*time.Second)),
	)
	testcontainers.CleanupContainer(t, ctr)
	if err != nil {
		t.Fatalf("arrancar ldap: %v", err)
	}
	endpoint, err := ctr.PortEndpoint(ctx, "1389/tcp", "ldap")
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		URL:          endpoint,
		BindDN:       "cn=svc,ou=services," + testBaseDN,
		BindPassword: svcPassword,
		UsersDN:      "ou=users," + testBaseDN,
		GroupsDN:     "ou=groups," + testBaseDN,
		Timeout:      5 * time.Second,
	}
}

func TestAuthenticate(t *testing.T) {
	cfg := startLDAP(t)
	c := New(cfg)
	ctx := context.Background()

	t.Run("credenciales válidas", func(t *testing.T) {
		id, err := c.Authenticate(ctx, "alice", seedPassword)
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if id.Username != "alice" || id.Name != "Alice Example" || id.Email != "alice@example.org" {
			t.Errorf("identidad inesperada: %+v", id)
		}
		if !slices.Equal(id.Groups, []string{"staff"}) {
			t.Errorf("grupos: %v", id.Groups)
		}
	})

	t.Run("el username devuelto es el uid canónico", func(t *testing.T) {
		id, err := c.Authenticate(ctx, "ALICE", seedPassword)
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if id.Username != "alice" {
			t.Errorf("Username = %q, se esperaba el uid del directorio", id.Username)
		}
	})

	invalid := []struct{ name, user, pass string }{
		{"contraseña errónea", "alice", "incorrecta"},
		{"usuario inexistente", "nadie", seedPassword},
		{"contraseña vacía", "alice", ""},
		{"inyección en el filtro", "*)(uid=*", seedPassword},
		{"comodín", "*", seedPassword},
		{"contraseña con espacios extra", "alice", " " + seedPassword + " "},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.Authenticate(ctx, tc.user, tc.pass)
			if !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("se esperaba ErrInvalidCredentials, got %v", err)
			}
		})
	}

	t.Run("cuenta de servicio mal configurada no es un 401", func(t *testing.T) {
		bad := cfg
		bad.BindPassword = "incorrecta"
		_, err := New(bad).Authenticate(ctx, "alice", seedPassword)
		if err == nil || errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("se esperaba un error de infraestructura, got %v", err)
		}
	})
}

func TestAuthenticateEmptyPasswordSkipsServer(t *testing.T) {
	c := New(Config{URL: "ldap://127.0.0.1:1", Timeout: time.Second})
	if _, err := c.Authenticate(context.Background(), "alice", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("se esperaba ErrInvalidCredentials sin contactar al servidor, got %v", err)
	}
}

func TestAuthenticateServerDown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	c := New(Config{URL: "ldap://" + addr, Timeout: 2 * time.Second})
	start := time.Now()
	_, err = c.Authenticate(context.Background(), "alice", "x")
	if err == nil || errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("se esperaba un error de conexión, got %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("tardó %v; debe respetar el timeout", time.Since(start))
	}
}
```

- [ ] **Step 3: Verificar que falla**

Run: `make test-auth-svc`
Expected: FAIL de compilación (`undefined: New`, `undefined: Config`, `undefined: ErrInvalidCredentials`).

- [ ] **Step 4: Implementación mínima**

`auth-svc/internal/ldap/ldap.go`:

```go
// Package ldap autentica usuarios contra OpenLDAP con search-then-bind:
// la cuenta de servicio busca el DN del usuario y luego se hace bind con su contraseña.
package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
)

// ErrInvalidCredentials no distingue entre usuario inexistente y contraseña errónea.
var ErrInvalidCredentials = errors.New("credenciales inválidas")

type Identity struct {
	Username string
	Name     string
	Email    string
	Groups   []string
}

type Config struct {
	URL          string
	BindDN       string
	BindPassword string
	UsersDN      string
	GroupsDN     string
	StartTLS     bool
	Timeout      time.Duration
}

type Client struct{ cfg Config }

func New(cfg Config) *Client { return &Client{cfg: cfg} }

func (c *Client) Authenticate(ctx context.Context, username, password string) (Identity, error) {
	// Una contraseña vacía sería un "unauthenticated bind", que el servidor puede aceptar.
	if username == "" || password == "" {
		return Identity{}, ErrInvalidCredentials
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return Identity{}, err
	}
	defer func() { _ = conn.Close() }()

	if err := conn.Bind(c.cfg.BindDN, c.cfg.BindPassword); err != nil {
		return Identity{}, fmt.Errorf("ldap: bind de la cuenta de servicio: %w", err)
	}
	entry, err := c.findUser(conn, username)
	if err != nil {
		return Identity{}, err
	}
	// Los grupos se leen como cuenta de servicio (el usuario no tiene acceso a ou=groups).
	groups, err := c.groupsOf(conn, entry.DN)
	if err != nil {
		return Identity{}, err
	}
	if err := conn.Bind(entry.DN, password); err != nil {
		if goldap.IsErrorWithCode(err, goldap.LDAPResultInvalidCredentials) {
			return Identity{}, ErrInvalidCredentials
		}
		return Identity{}, fmt.Errorf("ldap: bind del usuario: %w", err)
	}
	return Identity{
		Username: entry.GetAttributeValue("uid"),
		Name:     entry.GetAttributeValue("cn"),
		Email:    entry.GetAttributeValue("mail"),
		Groups:   groups,
	}, nil
}

func (c *Client) dial(ctx context.Context) (*goldap.Conn, error) {
	timeout := c.cfg.Timeout
	if d, ok := ctx.Deadline(); ok {
		timeout = min(timeout, time.Until(d))
	}
	if timeout <= 0 {
		return nil, context.DeadlineExceeded
	}
	conn, err := goldap.DialURL(c.cfg.URL, goldap.DialWithDialer(&net.Dialer{Timeout: timeout}))
	if err != nil {
		return nil, fmt.Errorf("ldap: conexión: %w", err)
	}
	conn.SetTimeout(timeout)
	if c.cfg.StartTLS {
		u, err := url.Parse(c.cfg.URL)
		if err == nil {
			err = conn.StartTLS(&tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12})
		}
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("ldap: starttls: %w", err)
		}
	}
	return conn, nil
}

func (c *Client) findUser(conn *goldap.Conn, username string) (*goldap.Entry, error) {
	req := goldap.NewSearchRequest(
		c.cfg.UsersDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		2, 0, false, // sizeLimit 2: basta para detectar un uid ambiguo
		fmt.Sprintf("(&(objectClass=inetOrgPerson)(uid=%s))", goldap.EscapeFilter(username)),
		[]string{"uid", "cn", "mail"}, nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		if goldap.IsErrorWithCode(err, goldap.LDAPResultSizeLimitExceeded) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("ldap: búsqueda del usuario: %w", err)
	}
	if len(res.Entries) != 1 {
		return nil, ErrInvalidCredentials
	}
	return res.Entries[0], nil
}

func (c *Client) groupsOf(conn *goldap.Conn, userDN string) ([]string, error) {
	req := goldap.NewSearchRequest(
		c.cfg.GroupsDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(&(objectClass=groupOfNames)(member=%s))", goldap.EscapeFilter(userDN)),
		[]string{"cn"}, nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("ldap: búsqueda de grupos: %w", err)
	}
	groups := make([]string, 0, len(res.Entries))
	for _, e := range res.Entries {
		groups = append(groups, e.GetAttributeValue("cn"))
	}
	return groups, nil
}
```

- [ ] **Step 5: Verificar que pasa**

Run: `make test-auth-svc`
Expected: PASS, incluido `TestAuthenticate` con todos sus subtests (no debe aparecer `SKIP`). Si `WithFiles` falla porque `/seed` no existe en la imagen, cámbialo por `testcontainers.WithMounts(testcontainers.BindMount(filepath.Dir(seed), "/seed"))` y vuelve a correr.

- [ ] **Step 6: Lint**

Run: `make lint`
Expected: sin hallazgos.

- [ ] **Step 7: Commit y PR**

```bash
git add auth-svc
git commit -m "feat(auth-svc): cliente LDAP con search-then-bind

Closes #6

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push -u origin feat/6-auth-svc-ldap
gh pr create --title "feat(auth-svc): cliente LDAP con search-then-bind" --body "\`internal/ldap\`: bind de la cuenta de servicio → búsqueda con filtro escapado → grupos → bind del usuario. \`ErrInvalidCredentials\` único; contraseña vacía rechazada; timeout; StartTLS opcional. Tests de integración con testcontainers sobre nuestra imagen OpenLDAP.

Closes #6

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
gh pr checks --watch
gh pr merge --squash --delete-branch && git switch main && git pull -q
```

---

### Task 3: Emisor de JWT EdDSA (#7)

**Files:**
- Create: `auth-svc/internal/token/token.go`
- Test: `auth-svc/internal/token/token_test.go`

**Interfaces:**
- Consumes: `ldap.Identity` (Task 2).
- Produces:
  ```go
  package token
  type Claims struct {
      Name   string   `json:"name"`
      Email  string   `json:"email"`
      Groups []string `json:"groups"`
      jwt.RegisteredClaims
  }
  func NewIssuer(privateKeyPEM []byte, issuer, audience string, ttl time.Duration, now func() time.Time) (*Issuer, error)
  func (i *Issuer) Issue(id ldap.Identity) (string, error)
  ```

- [ ] **Step 1: Rama y dependencia**

```bash
git switch -c feat/7-auth-svc-jwt
mkdir -p auth-svc/internal/token
cd auth-svc && go get github.com/golang-jwt/jwt/v5@v5.3.1 && cd ..
```

- [ ] **Step 2: Test que falla**

`auth-svc/internal/token/token_test.go`:

```go
package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"slices"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/JesusMaVe/auth/auth-svc/internal/ldap"
)

var fixedNow = time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)

func pemOf(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func newKeys(t *testing.T) (ed25519.PublicKey, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, pemOf(t, priv)
}

func parse(t *testing.T, tok string, pub ed25519.PublicKey) (*jwt.Token, *Claims, error) {
	t.Helper()
	claims := &Claims{}
	parsed, err := jwt.ParseWithClaims(tok, claims, func(*jwt.Token) (any, error) { return pub, nil },
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithIssuer("auth-svc"),
		jwt.WithAudience("auth-dashboard-api"),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(func() time.Time { return fixedNow }),
	)
	return parsed, claims, err
}

var alice = ldap.Identity{Username: "alice", Name: "Alice Example", Email: "alice@example.org", Groups: []string{"staff"}}

func TestIssue(t *testing.T) {
	pub, privPEM := newKeys(t)
	iss, err := NewIssuer(privPEM, "auth-svc", "auth-dashboard-api", 30*time.Minute, func() time.Time { return fixedNow })
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	tok, err := iss.Issue(alice)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	parsed, c, err := parse(t, tok, pub)
	if err != nil {
		t.Fatalf("el token no verifica con la clave pública: %v", err)
	}
	if parsed.Header["alg"] != "EdDSA" {
		t.Errorf("alg = %v", parsed.Header["alg"])
	}
	if c.Subject != "alice" || c.Name != "Alice Example" || c.Email != "alice@example.org" || !slices.Equal(c.Groups, []string{"staff"}) {
		t.Errorf("claims: %+v", c)
	}
	if !c.IssuedAt.Equal(fixedNow) || !c.NotBefore.Equal(fixedNow) || !c.ExpiresAt.Equal(fixedNow.Add(30*time.Minute)) {
		t.Errorf("tiempos: iat=%v nbf=%v exp=%v", c.IssuedAt, c.NotBefore, c.ExpiresAt)
	}
	if c.ID == "" {
		t.Error("falta jti")
	}
	other, _ := iss.Issue(alice)
	if _, c2, _ := parse(t, other, pub); c2.ID == c.ID {
		t.Error("cada token debe tener un jti distinto")
	}
}

func TestIssueExpired(t *testing.T) {
	pub, privPEM := newKeys(t)
	past := fixedNow.Add(-time.Hour)
	iss, _ := NewIssuer(privPEM, "auth-svc", "auth-dashboard-api", 30*time.Minute, func() time.Time { return past })
	tok, _ := iss.Issue(alice)
	if _, _, err := parse(t, tok, pub); err == nil {
		t.Fatal("un token con exp en el pasado no debe verificar")
	}
}

func TestIssueOtherKeyDoesNotVerify(t *testing.T) {
	_, privPEM := newKeys(t)
	otherPub, _ := newKeys(t)
	iss, _ := NewIssuer(privPEM, "auth-svc", "auth-dashboard-api", time.Minute, func() time.Time { return fixedNow })
	tok, _ := iss.Issue(alice)
	if _, _, err := parse(t, tok, otherPub); err == nil {
		t.Fatal("no debe verificar con otra clave pública")
	}
}

func TestNewIssuerRejectsBadKeys(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string][]byte{
		"no es PEM": []byte("basura"),
		"RSA":       pemOf(t, rsaKey),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewIssuer(key, "i", "a", time.Minute, time.Now); err == nil {
				t.Fatal("se esperaba error")
			}
		})
	}
}
```

- [ ] **Step 3: Verificar que falla**

Run: `cd auth-svc && go test ./internal/token/`
Expected: FAIL de compilación (`undefined: NewIssuer`, `undefined: Claims`).

- [ ] **Step 4: Implementación mínima**

`auth-svc/internal/token/token.go`:

```go
// Package token firma los JWT de auth-svc con EdDSA (Ed25519).
package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/JesusMaVe/auth/auth-svc/internal/ldap"
)

type Claims struct {
	Name   string   `json:"name"`
	Email  string   `json:"email"`
	Groups []string `json:"groups"`
	jwt.RegisteredClaims
}

type Issuer struct {
	key      ed25519.PrivateKey
	issuer   string
	audience string
	ttl      time.Duration
	now      func() time.Time
}

func NewIssuer(privateKeyPEM []byte, issuer, audience string, ttl time.Duration, now func() time.Time) (*Issuer, error) {
	key, err := jwt.ParseEdPrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("token: clave privada inválida: %w", err)
	}
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("token: la clave privada no es Ed25519")
	}
	return &Issuer{key: edKey, issuer: issuer, audience: audience, ttl: ttl, now: now}, nil
}

func (i *Issuer) Issue(id ldap.Identity) (string, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", fmt.Errorf("token: jti: %w", err)
	}
	now := i.now()
	claims := Claims{
		Name:   id.Name,
		Email:  id.Email,
		Groups: id.Groups,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   id.Username,
			Issuer:    i.issuer,
			Audience:  jwt.ClaimStrings{i.audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(i.ttl)),
			ID:        hex.EncodeToString(jti),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(i.key)
}
```

- [ ] **Step 5: Verificar que pasa**

Run: `cd auth-svc && go test -race ./internal/token/ -v && cd .. && make lint`
Expected: PASS; lint sin hallazgos.

- [ ] **Step 6: Commit y PR**

```bash
git add auth-svc
git commit -m "feat(auth-svc): emisor de JWT firmado con EdDSA

Closes #7

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push -u origin feat/7-auth-svc-jwt
gh pr create --title "feat(auth-svc): emisor de JWT firmado con EdDSA" --body "\`internal/token\`: \`Issuer.Issue(Identity)\` con claims \`sub,name,email,groups,iss,aud,iat,nbf,exp,jti\`, reloj inyectable, clave Ed25519 PKCS#8 desde PEM.

Closes #7

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
gh pr checks --watch
gh pr merge --squash --delete-branch && git switch main && git pull -q
```

---

### Task 4: Rate limiter por clave (#8, parte 1)

**Files:**
- Create: `auth-svc/internal/ratelimit/ratelimit.go`
- Test: `auth-svc/internal/ratelimit/ratelimit_test.go`

**Interfaces:**
- Produces:
  ```go
  package ratelimit
  func New(perMinute, burst int, now func() time.Time) *Keyed
  func (k *Keyed) Allow(key string) bool
  ```

- [ ] **Step 1: Rama y dependencia**

```bash
git switch -c feat/8-auth-svc-token-endpoint
mkdir -p auth-svc/internal/ratelimit
cd auth-svc && go get golang.org/x/time@v0.16.0 && cd ..
```

- [ ] **Step 2: Test que falla**

`auth-svc/internal/ratelimit/ratelimit_test.go`:

```go
package ratelimit

import (
	"fmt"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newClock() *clock { return &clock{t: time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)} }

func TestBurstThenDeny(t *testing.T) {
	c := newClock()
	k := New(60, 3, c.now)
	for i := range 3 {
		if !k.Allow("alice") {
			t.Fatalf("la petición %d debía pasar", i+1)
		}
	}
	if k.Allow("alice") {
		t.Fatal("la cuarta petición debía rechazarse")
	}
}

func TestKeysAreIndependent(t *testing.T) {
	k := New(60, 1, newClock().now)
	if !k.Allow("alice") || !k.Allow("bob") {
		t.Fatal("cada clave tiene su propio cupo")
	}
	if k.Allow("alice") {
		t.Fatal("alice ya agotó su cupo")
	}
}

func TestRefills(t *testing.T) {
	c := newClock()
	k := New(60, 1, c.now) // 1 por segundo
	k.Allow("alice")
	if k.Allow("alice") {
		t.Fatal("sin cupo inmediatamente después")
	}
	c.advance(time.Second)
	if !k.Allow("alice") {
		t.Fatal("tras 1 s debe haber cupo de nuevo")
	}
}

func TestSweepsIdleKeys(t *testing.T) {
	c := newClock()
	k := New(60, 5, c.now)
	for i := range 1000 {
		k.Allow(fmt.Sprintf("user-%d", i))
	}
	c.advance(10 * time.Minute)
	k.Allow("otro")
	if n := len(k.entries); n != 1 {
		t.Fatalf("quedaron %d entradas; las inactivas deben barrerse", n)
	}
}
```

- [ ] **Step 3: Verificar que falla**

Run: `cd auth-svc && go test ./internal/ratelimit/`
Expected: FAIL de compilación (`undefined: New`).

- [ ] **Step 4: Implementación mínima**

`auth-svc/internal/ratelimit/ratelimit.go`:

```go
// Package ratelimit limita peticiones por clave (IP o usuario) con un token bucket por clave.
package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// sweepEvery es cada cuánto se revisan las claves inactivas (detalle interno, no configuración).
const sweepEvery = time.Minute

type Keyed struct {
	mu        sync.Mutex
	limit     rate.Limit
	burst     int
	idle      time.Duration // tras este tiempo sin uso el bucket está lleno: borrarlo no cambia nada
	now       func() time.Time
	entries   map[string]*entry
	lastSweep time.Time
}

type entry struct {
	lim  *rate.Limiter
	seen time.Time
}

func New(perMinute, burst int, now func() time.Time) *Keyed {
	limit := rate.Limit(float64(perMinute) / 60)
	return &Keyed{
		limit:     limit,
		burst:     burst,
		idle:      time.Duration(float64(burst) / float64(limit) * float64(time.Second)),
		now:       now,
		entries:   map[string]*entry{},
		lastSweep: now(),
	}
}

func (k *Keyed) Allow(key string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	k.sweep(now)
	e, ok := k.entries[key]
	if !ok {
		e = &entry{lim: rate.NewLimiter(k.limit, k.burst)}
		k.entries[key] = e
	}
	e.seen = now
	return e.lim.AllowN(now, 1)
}

func (k *Keyed) sweep(now time.Time) {
	if now.Sub(k.lastSweep) < sweepEvery {
		return
	}
	k.lastSweep = now
	for key, e := range k.entries {
		if now.Sub(e.seen) >= k.idle {
			delete(k.entries, key)
		}
	}
}
```

- [ ] **Step 5: Verificar que pasa**

Run: `cd auth-svc && go test -race ./internal/ratelimit/ -v`
Expected: PASS.

- [ ] **Step 6: Commit (el PR se abre al final de la Task 6)**

```bash
git add auth-svc
git commit -m "feat(auth-svc): rate limiter por clave con barrido de inactivas

Refs #8

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Handler HTTP `POST /token` y `/healthz` (#8, parte 2)

**Files:**
- Create: `auth-svc/internal/httpapi/httpapi.go`
- Test: `auth-svc/internal/httpapi/httpapi_test.go`

**Interfaces:**
- Consumes: `ldap.Identity`, `ldap.ErrInvalidCredentials` (Task 2); `ratelimit.Keyed` satisface `Limiter` (Task 4); `token.Issuer` satisface `TokenIssuer` (Task 3); `ldap.Client` satisface `Authenticator`.
- Produces:
  ```go
  package httpapi
  type Authenticator interface { Authenticate(ctx context.Context, username, password string) (ldap.Identity, error) }
  type TokenIssuer interface { Issue(ldap.Identity) (string, error) }
  type Limiter interface { Allow(key string) bool }
  func New(auth Authenticator, issuer TokenIssuer, byIP, byUser Limiter, log *slog.Logger) http.Handler
  ```
  Respuestas: 200 `{"token":"…"}` + `Cache-Control: no-store`; 400 `{"error":"invalid request"}`; 401 `{"error":"invalid credentials"}`; 413 `{"error":"request too large"}`; 429 `{"error":"too many requests"}` + `Retry-After: 60`; 502 `{"error":"authentication service unavailable"}`; 500 `{"error":"internal error"}`. `GET /healthz` → 200 `{"status":"ok"}`.

- [ ] **Step 1: Test que falla**

`auth-svc/internal/httpapi/httpapi_test.go`:

```go
package httpapi

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JesusMaVe/auth/auth-svc/internal/ldap"
)

const (
	password = "contraseña-de-prueba"
	tokenStr = "header.payload.firma"
)

type fakeAuth struct {
	err        error
	called     bool
	user, pass string
}

func (f *fakeAuth) Authenticate(_ context.Context, u, p string) (ldap.Identity, error) {
	f.called, f.user, f.pass = true, u, p
	if f.err != nil {
		return ldap.Identity{}, f.err
	}
	return ldap.Identity{Username: "alice"}, nil
}

type fakeIssuer struct{ err error }

func (f fakeIssuer) Issue(ldap.Identity) (string, error) { return tokenStr, f.err }

type fakeLimiter struct {
	deny bool
	keys []string
}

func (f *fakeLimiter) Allow(k string) bool { f.keys = append(f.keys, k); return !f.deny }

type env struct {
	auth         *fakeAuth
	issuer       fakeIssuer
	byIP, byUser *fakeLimiter
	logs         bytes.Buffer
}

func newEnv() *env { return &env{auth: &fakeAuth{}, byIP: &fakeLimiter{}, byUser: &fakeLimiter{}} }

func (e *env) do(method, path, body string) *httptest.ResponseRecorder {
	h := New(e.auth, e.issuer, e.byIP, e.byUser, slog.New(slog.NewJSONHandler(&e.logs, nil)))
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "192.0.2.10:5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func expect(t *testing.T, rec *httptest.ResponseRecorder, status int, body string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, se esperaba %d (body %s)", rec.Code, status, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), body) {
		t.Fatalf("body = %s, se esperaba que contuviera %s", rec.Body, body)
	}
}

const aliceBody = `{"username":"Alice","password":"` + password + `"}`

func TestTokenOK(t *testing.T) {
	e := newEnv()
	rec := e.do("POST", "/token", aliceBody)
	expect(t, rec, 200, `{"token":"`+tokenStr+`"}`)
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("falta Cache-Control: no-store")
	}
	if e.auth.user != "Alice" || e.auth.pass != password {
		t.Errorf("el autenticador recibió %q/%q", e.auth.user, e.auth.pass)
	}
	if len(e.byIP.keys) != 1 || e.byIP.keys[0] != "192.0.2.10" {
		t.Errorf("clave por IP: %v", e.byIP.keys)
	}
	if len(e.byUser.keys) != 1 || e.byUser.keys[0] != "alice" {
		t.Errorf("la clave por usuario debe ir en minúsculas: %v", e.byUser.keys)
	}
}

func TestTokenPasswordNotTrimmed(t *testing.T) {
	e := newEnv()
	e.do("POST", "/token", `{"username":"alice","password":"  con espacios  "}`)
	if e.auth.pass != "  con espacios  " {
		t.Fatalf("la contraseña debe llegar intacta, llegó %q", e.auth.pass)
	}
}

func TestTokenBadRequest(t *testing.T) {
	for name, body := range map[string]string{
		"JSON malformado":  `{"username":`,
		"falta password":   `{"username":"alice"}`,
		"campo extra":      `{"username":"alice","password":"x","admin":true}`,
		"username enorme":  `{"username":"` + strings.Repeat("a", maxUsernameLen+1) + `","password":"x"}`,
		"password enorme":  `{"username":"alice","password":"` + strings.Repeat("a", maxPasswordLen+1) + `"}`,
		"username vacío":   `{"username":"","password":"x"}`,
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv()
			expect(t, e.do("POST", "/token", body), 400, `"invalid request"`)
			if e.auth.called {
				t.Error("no debe llamar al autenticador")
			}
		})
	}
}

func TestTokenTooLarge(t *testing.T) {
	e := newEnv()
	body := `{"username":"alice","password":"` + strings.Repeat("a", maxBodyBytes) + `"}`
	expect(t, e.do("POST", "/token", body), 413, `"request too large"`)
}

func TestTokenInvalidCredentials(t *testing.T) {
	e := newEnv()
	e.auth.err = ldap.ErrInvalidCredentials
	expect(t, e.do("POST", "/token", aliceBody), 401, `{"error":"invalid credentials"}`)
}

func TestTokenLDAPDown(t *testing.T) {
	e := newEnv()
	e.auth.err = errors.New("ldap: conexión: detalle interno")
	rec := e.do("POST", "/token", aliceBody)
	expect(t, rec, 502, `"authentication service unavailable"`)
	if strings.Contains(rec.Body.String(), "detalle interno") {
		t.Error("la respuesta no debe filtrar detalles internos")
	}
}

func TestTokenIssuerError(t *testing.T) {
	e := newEnv()
	e.issuer.err = errors.New("fallo")
	expect(t, e.do("POST", "/token", aliceBody), 500, `"internal error"`)
}

func TestTokenRateLimited(t *testing.T) {
	for _, which := range []string{"ip", "user"} {
		t.Run(which, func(t *testing.T) {
			e := newEnv()
			if which == "ip" {
				e.byIP.deny = true
			} else {
				e.byUser.deny = true
			}
			rec := e.do("POST", "/token", aliceBody)
			expect(t, rec, 429, `"too many requests"`)
			if rec.Header().Get("Retry-After") == "" {
				t.Error("falta Retry-After")
			}
			if e.auth.called {
				t.Error("no debe llamar al autenticador")
			}
		})
	}
}

func TestLogsNeverContainSecrets(t *testing.T) {
	e := newEnv()
	e.do("POST", "/token", aliceBody)
	e.auth.err = ldap.ErrInvalidCredentials
	e.do("POST", "/token", aliceBody)
	logs := e.logs.String()
	if strings.Contains(logs, password) || strings.Contains(logs, tokenStr) {
		t.Fatalf("los logs contienen la contraseña o el token: %s", logs)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	if rec := newEnv().do("GET", "/token", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /token = %d", rec.Code)
	}
}

func TestHealthz(t *testing.T) {
	expect(t, newEnv().do("GET", "/healthz", ""), 200, `{"status":"ok"}`)
}
```

- [ ] **Step 2: Verificar que falla**

Run: `cd auth-svc && go test ./internal/httpapi/`
Expected: FAIL de compilación (`undefined: New`, `undefined: maxUsernameLen`…).

- [ ] **Step 3: Implementación mínima**

`auth-svc/internal/httpapi/httpapi.go`:

```go
// Package httpapi expone POST /token (credenciales → JWT) y GET /healthz.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/JesusMaVe/auth/auth-svc/internal/ldap"
)

// Límites del protocolo (no son configuración de despliegue).
const (
	maxBodyBytes   = 4 << 10
	maxUsernameLen = 64
	maxPasswordLen = 256
)

type Authenticator interface {
	Authenticate(ctx context.Context, username, password string) (ldap.Identity, error)
}

type TokenIssuer interface {
	Issue(ldap.Identity) (string, error)
}

type Limiter interface {
	Allow(key string) bool
}

type tokenHandler struct {
	auth         Authenticator
	issuer       TokenIssuer
	byIP, byUser Limiter
	log          *slog.Logger
}

func New(auth Authenticator, issuer TokenIssuer, byIP, byUser Limiter, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.Handle("POST /token", &tokenHandler{auth: auth, issuer: issuer, byIP: byIP, byUser: byUser, log: log})
	return mux
}

type tokenRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *tokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !h.byIP.Allow(ip) {
		h.log.Warn("rate limit", "por", "ip", "ip", ip)
		tooManyRequests(w)
		return
	}

	var req tokenRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "request too large")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.Username == "" || req.Password == "" || len(req.Username) > maxUsernameLen || len(req.Password) > maxPasswordLen {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	user := strings.ToLower(req.Username)
	if !h.byUser.Allow(user) {
		h.log.Warn("rate limit", "por", "usuario", "user", user, "ip", ip)
		tooManyRequests(w)
		return
	}

	id, err := h.auth.Authenticate(r.Context(), req.Username, req.Password)
	switch {
	case errors.Is(err, ldap.ErrInvalidCredentials):
		h.log.Info("login fallido", "user", user, "ip", ip)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	case err != nil:
		h.log.Error("ldap no disponible", "err", err)
		writeError(w, http.StatusBadGateway, "authentication service unavailable")
		return
	}

	tok, err := h.issuer.Issue(id)
	if err != nil {
		h.log.Error("no se pudo emitir el token", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	h.log.Info("login correcto", "user", id.Username, "ip", ip)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"token": tok})
}

// clientIP usa la IP de la conexión; X-Forwarded-For no se usa porque el cliente lo controla.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func tooManyRequests(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "60")
	writeError(w, http.StatusTooManyRequests, "too many requests")
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
```

- [ ] **Step 4: Verificar que pasa**

Run: `cd auth-svc && go test -race ./internal/httpapi/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add auth-svc
git commit -m "feat(auth-svc): POST /token con rate limit y /healthz

Refs #8

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: `main`, Dockerfile, claves JWT, compose y smoke tests (#8, parte 3)

**Files:**
- Create: `auth-svc/cmd/auth-svc/main.go`
- Create: `auth-svc/Dockerfile`, `auth-svc/.dockerignore`
- Create: `scripts/gen-jwt-keys.sh`
- Create: `test/auth-svc-image.sh`
- Modify: `Makefile` (`secrets`, `up`, `test`, nuevos `test-auth-svc-image`, `jwt-public-key`)
- Modify: `docker-compose.yml`, `docker-compose.dev.yml`, `.env.example`
- Modify: `test/repo.sh`, `test/infra.sh`, `test/rotation.sh`
- Modify: `README.md`

**Interfaces:**
- Consumes: `config.Load` (Task 1), `ldap.New`/`ldap.Config` (Task 2), `token.NewIssuer` (Task 3), `ratelimit.New` (Task 4), `httpapi.New` (Task 5).
- Produces: servicio `auth-svc` en el compose; `POST http://127.0.0.1:${AUTH_SVC_HOST_PORT}/token`; `secrets/jwt_public_key` (PEM SPKI Ed25519) para el repo `api`; `make jwt-public-key` la imprime.

- [ ] **Step 1: Tests de shell que fallan (claves)**

Agrega al final de `test/repo.sh`, antes de `summary`:

```bash
echo "repo: claves del JWT"
keys="$tmp/keys"
check_output "genera la privada e informa el cambio" '^jwt_private_key$' scripts/gen-jwt-keys.sh "$keys"
check "la privada es Ed25519" sh -c "openssl pkey -in '$keys/jwt_private_key' -noout -text | grep -q ED25519"
check "la pública corresponde a la privada" \
  test "$(openssl pkey -in "$keys/jwt_private_key" -pubout)" = "$(cat "$keys/jwt_public_key")"
priv_before=$(cat "$keys/jwt_private_key")
check_no_output "si ya existen no informa nada" '.' scripts/gen-jwt-keys.sh "$keys"
check "no sobrescribe la privada" test "$(cat "$keys/jwt_private_key")" = "$priv_before"
rm "$keys/jwt_public_key"
scripts/gen-jwt-keys.sh "$keys" >/dev/null 2>&1
check "regenera la pública si falta" test -s "$keys/jwt_public_key"
```

Run: `test/repo.sh`
Expected: FAIL en las checks de "claves del JWT" (`scripts/gen-jwt-keys.sh` no existe).

- [ ] **Step 2: Script de claves**

`scripts/gen-jwt-keys.sh` (y `chmod +x scripts/gen-jwt-keys.sh`):

```bash
#!/usr/bin/env bash
# Genera el par Ed25519 del JWT en <dir> si no existe: jwt_private_key (Docker secret de auth-svc)
# y jwt_public_key (se copia al repo api como JWT_PUBLIC_KEY_FILE). Nunca sobrescribe la privada.
# Imprime "jwt_private_key" si la creó, para que `make up` recree los contenedores.
set -euo pipefail

dir=${1:?uso: gen-jwt-keys.sh <directorio>}
priv="$dir/jwt_private_key"
pub="$dir/jwt_public_key"

openssl version | grep -q '^OpenSSL 3' \
  || { echo "gen-jwt-keys: se requiere OpenSSL 3 (en macOS: brew install openssl)" >&2; exit 1; }

install -d -m 700 "$dir"
if [[ -f $priv ]]; then
  [[ -f $pub ]] || { openssl pkey -in "$priv" -pubout -out "$pub"; chmod 644 "$pub"; }
  exit 0
fi

tmp=$(mktemp "$dir/.jwt.XXXXXX")
trap 'rm -f "$tmp"' EXIT
openssl genpkey -algorithm ed25519 -out "$tmp"
openssl pkey -in "$tmp" -pubout -out "$pub"
# 644 como los demás secretos: el contenedor corre con otro uid (non-root); el directorio es 700.
chmod 644 "$tmp" "$pub"
mv "$tmp" "$priv"
trap - EXIT
echo "jwt_private_key"
```

Run: `test/repo.sh`
Expected: `OK`.

- [ ] **Step 3: main**

`auth-svc/cmd/auth-svc/main.go`:

```go
// Command auth-svc: POST /token autentica contra LDAP y devuelve un JWT EdDSA.
// Con -healthcheck consulta su propio /healthz (la imagen distroless no tiene shell ni curl).
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/JesusMaVe/auth/auth-svc/internal/config"
	"github.com/JesusMaVe/auth/auth-svc/internal/httpapi"
	"github.com/JesusMaVe/auth/auth-svc/internal/ldap"
	"github.com/JesusMaVe/auth/auth-svc/internal/ratelimit"
	"github.com/JesusMaVe/auth/auth-svc/internal/token"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		os.Exit(healthcheck())
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func healthcheck() int {
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + os.Getenv("AUTH_SVC_PORT") + "/healthz")
	if err != nil {
		return 1
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func run() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))

	issuer, err := token.NewIssuer(cfg.JWTPrivateKeyPEM, cfg.JWTIssuer, cfg.JWTAudience, cfg.JWTTTL, time.Now)
	if err != nil {
		return err
	}
	auth := ldap.New(ldap.Config{
		URL:          cfg.LDAPURL,
		BindDN:       cfg.LDAPBindDN,
		BindPassword: cfg.LDAPBindPassword,
		UsersDN:      cfg.LDAPUsersDN,
		GroupsDN:     cfg.LDAPGroupsDN,
		StartTLS:     cfg.LDAPStartTLS,
		Timeout:      cfg.LDAPTimeout,
	})
	handler := httpapi.New(auth, issuer,
		ratelimit.New(cfg.RateLimitPerMinute, cfg.RateLimitBurst, time.Now),
		ratelimit.New(cfg.RateLimitPerMinute, cfg.RateLimitBurst, time.Now),
		log)

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      cfg.LDAPTimeout + 5*time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() {
		log.Info("auth-svc escuchando", "port", cfg.Port)
		errCh <- srv.ListenAndServe()
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	log.Info("apagando")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
```

Run: `cd auth-svc && go build ./... && go vet ./...`
Expected: sin errores.

- [ ] **Step 4: Test de la imagen que falla**

`test/auth-svc-image.sh` (y `chmod +x test/auth-svc-image.sh`):

```bash
#!/usr/bin/env bash
# Tests de la imagen auth-svc en aislamiento (docker run, sin compose).
set -u
cd "$(dirname "$0")/.." || exit 1
# shellcheck source=test/lib.sh
. test/lib.sh

IMG=${AUTH_SVC_TEST_IMAGE:?AUTH_SVC_TEST_IMAGE no definida (usa make test-auth-svc-image)}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
printf 'valor-que-no-debe-salir' > "$tmp/pw"
chmod -R a+rX "$tmp"

echo "auth-svc-image:"
check_fails  "sin variables → sale con error" docker run --rm "$IMG"
check_output "sin variables → nombra AUTH_SVC_PORT" 'AUTH_SVC_PORT' docker run --rm "$IMG"
check_no_output "el error no muestra el valor de un secreto" 'valor-que-no-debe-salir' \
  docker run --rm -v "$tmp:/s:ro" -e LDAP_BIND_PASSWORD_FILE=/s/pw "$IMG"
check_output "corre como non-root" '^nonroot' docker image inspect -f '{{.Config.User}}' "$IMG"
check_output "tiene healthcheck" 'healthcheck' docker image inspect -f '{{.Config.Healthcheck.Test}}' "$IMG"

summary
```

En `Makefile`: agrega `AUTH_SVC_TEST_IMAGE := auth-svc:test` junto a las otras imágenes de test, `test-auth-svc-image` y `jwt-public-key` a `.PHONY`, y:

```make
test-auth-svc-image: ## Tests de la imagen auth-svc en aislamiento
	docker build -q -t $(AUTH_SVC_TEST_IMAGE) auth-svc >/dev/null
	@AUTH_SVC_TEST_IMAGE=$(AUTH_SVC_TEST_IMAGE) test/auth-svc-image.sh
```

Run: `make test-auth-svc-image`
Expected: FAIL (`docker build` no encuentra `auth-svc/Dockerfile`).

- [ ] **Step 5: Dockerfile**

`auth-svc/Dockerfile`:

```dockerfile
# syntax=docker/dockerfile:1
ARG GO_VERSION=1.27.1
ARG ALPINE_VERSION=3.24

FROM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/auth-svc ./cmd/auth-svc

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/auth-svc /auth-svc
USER nonroot:nonroot
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --start-interval=1s \
  CMD ["/auth-svc", "-healthcheck"]
ENTRYPOINT ["/auth-svc"]
```

`auth-svc/.dockerignore`:

```
Dockerfile
.dockerignore
**/*_test.go
```

Run: `make test-auth-svc-image`
Expected: `OK`.

- [ ] **Step 6: Tests de integración que fallan (compose)**

Agrega al final de `test/infra.sh`, antes de `summary`:

```bash
echo "infra: auth-svc"
AUTH="http://127.0.0.1:${AUTH_SVC_HOST_PORT}"
token_req() { curl -s -X POST "$AUTH/token" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$1\",\"password\":\"$2\"}"; }
token_status() { curl -s -o /dev/null -w '%{http_code}' -X POST "$AUTH/token" \
  -H 'Content-Type: application/json' -d "{\"username\":\"$1\",\"password\":\"$2\"}"; }
# jwt_payload <json>: decodifica (sin verificar) el payload del token de la respuesta.
jwt_payload() {
  local p
  p=$(sed -E 's/.*"token":"[^.]+\.([^.]+)\..*/\1/' <<< "$1" | tr '_-' '/+')
  while (( ${#p} % 4 )); do p+='='; done
  base64 -d <<< "$p" 2>/dev/null
}

check_output "healthz responde" '"status":"ok"' curl -s "$AUTH/healthz"
resp=$(token_req alice "$LDAP_SEED_USER_PASSWORD")
check_output "alice obtiene un JWT" '"token":"[^".]+\.[^".]+\.[^".]+"' echo "$resp"
check_output "el JWT es de alice" '"sub":"alice"' jwt_payload "$resp"
check_output "el JWT trae el emisor configurado" "\"iss\":\"${JWT_ISSUER}\"" jwt_payload "$resp"
check_output "contraseña errónea → 401" '^401$' token_status alice contraseña-incorrecta
check_output "usuario inexistente → 401" '^401$' token_status nadie "$LDAP_SEED_USER_PASSWORD"
check_no_output "los logs no contienen la contraseña" "$LDAP_SEED_USER_PASSWORD" "${DC[@]}" logs auth-svc
check_output "sin puerto publicado fuera de 127.0.0.1" '127\.0\.0\.1' "${DC[@]}" port auth-svc "$AUTH_SVC_PORT"
```

Y en `test/rotation.sh`, después de `check "alice: la contraseña nueva funciona" …`:

```bash
auth_status() { curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:${AUTH_SVC_HOST_PORT}/token" \
  -H 'Content-Type: application/json' -d "{\"username\":\"alice\",\"password\":\"$1\"}"; }
check_output "auth-svc: alice obtiene token con la contraseña rotada" '^200$' \
  auth_status "${LDAP_SEED_USER_PASSWORD}-rotada"
```

Run: `make test-infra`
Expected: FAIL (`AUTH_SVC_HOST_PORT` no definida / no hay servicio `auth-svc`).

- [ ] **Step 7: .env.example, compose y Makefile**

Agrega al final de `.env.example`:

```
# ── auth-svc (API de LDAP que emite el JWT) ───────────────
# Puerto dentro del contenedor
AUTH_SVC_PORT=8081
# Puerto publicado en 127.0.0.1 (solo docker-compose.dev.yml); el proxy /auth del frontend apunta aquí
AUTH_SVC_HOST_PORT=8081
AUTH_SVC_LOG_LEVEL=info
# StartTLS hacia ldap (la imagen de desarrollo no tiene TLS)
LDAP_STARTTLS=false
LDAP_TIMEOUT=5s
# Deben coincidir con JWT_ISSUER/JWT_AUDIENCE del repo api
JWT_ISSUER=auth-svc
JWT_AUDIENCE=auth-dashboard-api
JWT_TTL=30m
# Por IP y por usuario. Detrás del proxy de Vite todas las peticiones comparten IP.
RATE_LIMIT_PER_MINUTE=10
RATE_LIMIT_BURST=10
```

Y copia esas mismas líneas en tu `.env` local (`make env` no sobrescribe uno existente).

En `docker-compose.yml`, agrega el servicio (después de `ldap`):

```yaml
  auth-svc:
    build: ./auth-svc
    environment:
      AUTH_SVC_PORT: ${AUTH_SVC_PORT:?AUTH_SVC_PORT no definida}
      LOG_LEVEL: ${AUTH_SVC_LOG_LEVEL:?AUTH_SVC_LOG_LEVEL no definida}
      LDAP_URL: ldap://ldap:${LDAP_PORT:?LDAP_PORT no definida}
      LDAP_BIND_DN: cn=${LDAP_SERVICE_CN:?LDAP_SERVICE_CN no definida},ou=services,${LDAP_BASE_DN:?LDAP_BASE_DN no definida}
      LDAP_BIND_PASSWORD_FILE: /run/secrets/ldap_service_password
      LDAP_USERS_DN: ou=users,${LDAP_BASE_DN:?LDAP_BASE_DN no definida}
      LDAP_GROUPS_DN: ou=groups,${LDAP_BASE_DN:?LDAP_BASE_DN no definida}
      LDAP_STARTTLS: ${LDAP_STARTTLS:?LDAP_STARTTLS no definida}
      LDAP_TIMEOUT: ${LDAP_TIMEOUT:?LDAP_TIMEOUT no definida}
      JWT_PRIVATE_KEY_FILE: /run/secrets/jwt_private_key
      JWT_ISSUER: ${JWT_ISSUER:?JWT_ISSUER no definida}
      JWT_AUDIENCE: ${JWT_AUDIENCE:?JWT_AUDIENCE no definida}
      JWT_TTL: ${JWT_TTL:?JWT_TTL no definida}
      RATE_LIMIT_PER_MINUTE: ${RATE_LIMIT_PER_MINUTE:?RATE_LIMIT_PER_MINUTE no definida}
      RATE_LIMIT_BURST: ${RATE_LIMIT_BURST:?RATE_LIMIT_BURST no definida}
    secrets:
      - ldap_service_password
      - jwt_private_key
    depends_on:
      ldap:
        condition: service_healthy
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    restart: unless-stopped
```

y en su bloque `secrets:`:

```yaml
  jwt_private_key:
    file: ./secrets/jwt_private_key
```

En `docker-compose.dev.yml`, agrega bajo `services:`:

```yaml
  auth-svc:
    ports:
      - "127.0.0.1:${AUTH_SVC_HOST_PORT:?AUTH_SVC_HOST_PORT no definida}:${AUTH_SVC_PORT:?AUTH_SVC_PORT no definida}"
```

En `Makefile`, reemplaza `secrets`, `up` y `test`, y agrega `jwt-public-key`:

```make
secrets: ## Escribe los *_PASSWORD de .env en secrets/ y genera las claves del JWT si faltan
	@scripts/sync-secrets.sh "$(ENV_FILE)" secrets
	@scripts/gen-jwt-keys.sh secrets

up: ## Levanta los servicios (espera a healthy); si cambió algún secreto, recrea los contenedores
	@changed=$$(scripts/sync-secrets.sh "$(ENV_FILE)" secrets && scripts/gen-jwt-keys.sh secrets) || exit 1; \
	if [ -n "$$changed" ]; then echo "secretos nuevos o cambiados: $$(echo $$changed) → se recrean los contenedores"; fi; \
	$(COMPOSE) up -d --build --wait $${changed:+--force-recreate}

jwt-public-key: ## Imprime la clave pública del JWT (para JWT_PUBLIC_KEY_FILE del repo api)
	@cat secrets/jwt_public_key

test: test-repo test-ldap-image test-postgres-image test-auth-svc test-auth-svc-image test-infra test-rotation ## Corre todos los tests
```

- [ ] **Step 8: Verificar todo**

Run: `make lint && make test`
Expected: todas las secciones en `OK` (repo, ldap-image, postgres-image, auth-svc Go, auth-svc-image, infra con la sección `auth-svc`, rotation con la check de auth-svc).

Prueba manual:

```bash
curl -s -X POST 127.0.0.1:8081/token -H 'Content-Type: application/json' \
  -d "{\"username\":\"alice\",\"password\":\"$(sed -n 's/^LDAP_SEED_USER_PASSWORD=//p' .env)\"}"
```

Expected: `{"token":"eyJ…"}`.

- [ ] **Step 9: README**

Agrega a `README.md` una sección:

````markdown
## auth-svc (API de LDAP que emite el JWT)

`POST /token {"username","password"}` → `{"token":"<JWT EdDSA>"}`. Errores: 400 cuerpo inválido, 401 credenciales inválidas (genérico), 413 cuerpo demasiado grande, 429 rate limit (por IP y por usuario; detrás del proxy de Vite todas las peticiones comparten IP), 502 LDAP no disponible.

```bash
make up
curl -s -X POST 127.0.0.1:${AUTH_SVC_HOST_PORT}/token -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"<LDAP_SEED_USER_PASSWORD de tu .env>"}'
```

`make up` genera el par Ed25519 en `secrets/` si no existe. La **clave pública** (`make jwt-public-key`) se copia al repo `api` como `JWT_PUBLIC_KEY_FILE`; `JWT_ISSUER` y `JWT_AUDIENCE` deben coincidir en ambos repos. Requiere OpenSSL 3 en el host.
````

- [ ] **Step 10: Commit y PR**

```bash
git add auth-svc scripts/gen-jwt-keys.sh test Makefile docker-compose.yml docker-compose.dev.yml .env.example README.md
git commit -m "feat(auth-svc): servicio POST /token en el compose con claves Ed25519

Closes #8

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push -u origin feat/8-auth-svc-token-endpoint
gh pr create --title "feat(auth-svc): POST /token, rate limit, Dockerfile y compose" --body "- \`internal/ratelimit\` (por IP y por usuario) y \`internal/httpapi\` (\`POST /token\`, \`/healthz\`).
- \`cmd/auth-svc\` con graceful shutdown y \`-healthcheck\` para la imagen distroless non-root.
- \`make up\` genera el par Ed25519 (\`scripts/gen-jwt-keys.sh\`); \`make jwt-public-key\` para el repo api.
- Servicio en el compose (read_only, cap_drop ALL, puerto solo en 127.0.0.1 en dev).
- Smoke tests: imagen, compose (token de alice, 401, logs sin contraseña) y rotación.

Closes #8

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
gh pr checks --watch
gh pr merge --squash --delete-branch && git switch main && git pull -q
```
