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
	"strconv"
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
	// Solo un número de puerto: el host es fijo (127.0.0.1) y no se arma la URL con texto libre.
	port, err := strconv.Atoi(os.Getenv("AUTH_SVC_PORT"))
	if err != nil || port < 1 || port > 65535 {
		return 1
	}
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", port)) // #nosec G704 -- host fijo (loopback) y puerto entero validado
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
		cfg.TrustedProxies,
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
