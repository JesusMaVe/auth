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
