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
