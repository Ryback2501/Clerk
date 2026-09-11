// Command clerk runs the Clerk OpenID Connect identity provider.
//
// Clerk is a deliberately small OIDC provider for development and testing: the
// protocol, signing and token handling are real, while user authentication is
// reduced to picking a test identity from a list. It is not intended to
// authenticate real users.
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

	"github.com/Ryback2501/Clerk/internal/admin"
	"github.com/Ryback2501/Clerk/internal/adminauth"
	"github.com/Ryback2501/Clerk/internal/config"
	"github.com/Ryback2501/Clerk/internal/keys"
	"github.com/Ryback2501/Clerk/internal/oidc"
	"github.com/Ryback2501/Clerk/internal/store"
)

// Shutdown budget for in-flight requests once a signal arrives.
const shutdownTimeout = 10 * time.Second

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	if err := run(logger); err != nil {
		logger.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}

	db, err := store.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer func() { _ = db.Close() }()

	signer, err := keys.LoadOrGenerate(cfg.KeysPath)
	if err != nil {
		return fmt.Errorf("signing key: %w", err)
	}
	// The key id is safe to log; the key itself never is.
	logger.Info("signing key ready", "kid", signer.KeyID(), "path", cfg.KeysPath)

	provider := oidc.New(cfg.Issuer, signer).WithLogger(logger)

	// Admin authentication is not implemented yet, so the only authenticator
	// available authorises everyone. Refuse to start in that state unless the
	// operator has explicitly asked for it: otherwise every image built from
	// this source would quietly expose application creation, secret
	// regeneration and deletion to anyone who can reach the port.
	if !cfg.AdminInsecure {
		return errors.New("administration has no authentication in this build: " +
			"set CLERK_ADMIN_INSECURE=true to run anyway, and do not expose the port to an untrusted network")
	}
	logger.Warn(adminauth.Warning)

	adminHandler, err := admin.New(db, adminauth.AllowAll{}, true)
	if err != nil {
		return fmt.Errorf("admin interface: %w", err)
	}
	adminHandler = adminHandler.WithLogger(logger)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           newHandler(provider, adminHandler),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Signal handling is installed before the listener starts so a signal
	// arriving during startup is not lost.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", cfg.ListenAddr, "issuer", cfg.Issuer.String())
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
		logger.Info("shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	return nil
}

// newHandler builds the HTTP routes. The provider and the admin interface are
// registered independently so that an admin-side failure cannot affect token
// issuance.
func newHandler(provider *oidc.Provider, adminHandler *admin.Handler) http.Handler {
	mux := http.NewServeMux()
	provider.Register(mux)
	adminHandler.Register(mux)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	return mux
}
