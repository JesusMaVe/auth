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
