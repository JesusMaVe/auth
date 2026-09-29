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
		"JSON malformado": `{"username":`,
		"falta password":  `{"username":"alice"}`,
		"campo extra":     `{"username":"alice","password":"x","admin":true}`,
		"username enorme": `{"username":"` + strings.Repeat("a", maxUsernameLen+1) + `","password":"x"}`,
		"password enorme": `{"username":"alice","password":"` + strings.Repeat("a", maxPasswordLen+1) + `"}`,
		"username vacío":  `{"username":"","password":"x"}`,
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
