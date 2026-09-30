// Package httpapi expone POST /token (credenciales → JWT) y GET /healthz.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
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
	trusted      []netip.Prefix
	log          *slog.Logger
}

func New(auth Authenticator, issuer TokenIssuer, byIP, byUser Limiter, trusted []netip.Prefix, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.Handle("POST /token", &tokenHandler{auth: auth, issuer: issuer, byIP: byIP, byUser: byUser, trusted: trusted, log: log})
	return mux
}

type tokenRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *tokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r, h.trusted)
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

	// Como compara LDAP (caseIgnoreMatch): sin mayúsculas ni espacios de más.
	user := strings.Join(strings.Fields(strings.ToLower(req.Username)), " ")
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

// clientIP es la IP de la conexión, salvo que venga de un proxy de confianza (nginx en la red
// compartida): entonces es la dirección de más a la derecha de X-Forwarded-For que no sea un
// proxy. Las de la izquierda las pudo escribir el cliente; la de la derecha la agregó el proxy.
func clientIP(r *http.Request, trusted []netip.Prefix) string {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peer = r.RemoteAddr
	}
	if !isTrusted(peer, trusted) {
		return peer
	}
	hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(hops[i])
		if hop == "" || isTrusted(hop, trusted) {
			continue
		}
		if _, err := netip.ParseAddr(hop); err != nil {
			return peer
		}
		return hop
	}
	return peer
}

func isTrusted(ip string, trusted []netip.Prefix) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, p := range trusted {
		if p.Contains(addr.Unmap()) {
			return true
		}
	}
	return false
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
