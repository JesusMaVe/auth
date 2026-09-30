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
		"TRUSTED_PROXIES":         "172.30.0.0/24, 10.0.0.0/8",
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
	if len(c.TrustedProxies) != 2 || c.TrustedProxies[0].String() != "172.30.0.0/24" || c.TrustedProxies[1].String() != "10.0.0.0/8" {
		t.Errorf("TrustedProxies = %v", c.TrustedProxies)
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
		{"TRUSTED_PROXIES", "no-es-cidr"},
		{"TRUSTED_PROXIES", "10.0.0.1"},
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
