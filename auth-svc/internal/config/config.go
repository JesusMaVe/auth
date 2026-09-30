// Package config lee y valida la configuración de auth-svc desde variables de entorno.
// Falla al arrancar si falta algo; los mensajes nombran la variable, nunca su valor.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
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
	TrustedProxies     []netip.Prefix
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
		TrustedProxies:     r.prefixes("TRUSTED_PROXIES"),
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

// prefixes lee una lista de CIDR separada por comas (p. ej. "172.30.0.0/24, 10.0.0.0/8").
func (r *reader) prefixes(key string) []netip.Prefix {
	v := r.str(key)
	if v == "" {
		return nil
	}
	var out []netip.Prefix
	for _, part := range strings.Split(v, ",") {
		p, err := netip.ParsePrefix(strings.TrimSpace(part))
		if err != nil {
			r.invalid(key, "debe ser una lista de CIDR separada por comas, p. ej. 172.30.0.0/24")
			return nil
		}
		out = append(out, p.Masked())
	}
	return out
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
