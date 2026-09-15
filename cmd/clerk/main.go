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
	"github.com/Ryback2501/Clerk/internal/web"
)

// Shutdown budget for in-flight requests once a signal arrives.
const shutdownTimeout = 10 * time.Second

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	// The container healthcheck runs this same binary, because the runtime
	// image is distroless and has neither a shell nor curl.
	if healthcheckRequested(os.Args[1:]) {
		if err := runHealthcheck(os.Getenv("LISTEN_ADDR")); err != nil {
			exitUnhealthy(err)
		}
		return
	}

	if err := run(logger); err != nil {
		logger.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	// Signal handling is installed first so a signal arriving during startup —
	// which now includes reaching out to the sign-in providers — is not lost.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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

	provider, err := oidc.New(oidc.Options{
		Issuer:         cfg.Issuer,
		Signer:         signer,
		Store:          db,
		CodeTTL:        cfg.CodeTTL,
		AccessTokenTTL: cfg.AccessTokenTTL,
		IDTokenTTL:     cfg.IDTokenTTL,
		Logger:         logger,
	})
	if err != nil {
		return fmt.Errorf("oidc provider: %w", err)
	}

	adminHandler, err := buildAdmin(ctx, cfg, db, logger)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           newHandler(provider, adminHandler),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Expired authorization requests and codes are useless but not harmless:
	// left alone they grow the database without bound. Reclaiming them is
	// background work, so a failure is logged rather than fatal.
	go purgeExpired(ctx, db, logger)

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

// buildAdmin wires the administration interface behind external sign-in and
// the role service. There is no unauthenticated mode.
func buildAdmin(ctx context.Context, cfg *config.Config, db *store.Store, logger *slog.Logger) (*admin.Handler, error) {
	bouncer, err := adminauth.NewBouncer(adminauth.BouncerConfig{
		BaseURL:      cfg.BouncerURL,
		APIKey:       cfg.BouncerAPIKey,
		RequiredRole: cfg.BouncerRequiredRole,
	})
	if err != nil {
		return nil, fmt.Errorf("role service: %w", err)
	}

	providers := make(map[string]adminauth.ClientCredentials, len(cfg.AdminProviders))
	for name, creds := range cfg.AdminProviders {
		providers[name] = adminauth.ClientCredentials{
			ClientID:     creds.ClientID,
			ClientSecret: creds.ClientSecret,
			Issuer:       creds.Issuer,
		}
	}

	// Discovery happens here, so an unreachable provider or a typo in an
	// issuer is a startup failure rather than a broken sign-in later.
	oauth, err := adminauth.NewOAuth(ctx, adminauth.OAuthConfig{
		PublicURL:  cfg.Issuer,
		Providers:  providers,
		Store:      admin.NewSessionStore(db),
		Authorizer: bouncer,
	})
	if err != nil {
		return nil, fmt.Errorf("admin sign-in: %w", err)
	}

	for _, name := range oauth.EnabledProviders() {
		// The callback must be registered with each provider exactly, so it is
		// worth stating plainly at startup.
		logger.Info("admin sign-in provider ready", "provider", name, "callback", oauth.CallbackURL(name))
	}
	logger.Info("administration authorized by the role service",
		"url", cfg.BouncerURL, "required_role", cfg.BouncerRequiredRole)

	handler, err := admin.NewWithOAuth(db, oauth)
	if err != nil {
		return nil, fmt.Errorf("admin interface: %w", err)
	}
	return handler.WithLogger(logger), nil
}

// purgeInterval is how often expired authorization state is reclaimed. The
// rows are small and short-lived, so this does not need to be frequent.
const purgeInterval = 10 * time.Minute

// purgeExpired reclaims timed-out authorization state until ctx is cancelled.
func purgeExpired(ctx context.Context, db *store.Store, logger *slog.Logger) {
	ticker := time.NewTicker(purgeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := db.PurgeExpired(ctx); err != nil && ctx.Err() == nil {
				logger.Error("purge expired authorization state", "err", err)
			}
		}
	}
}

// newHandler builds the HTTP routes. The provider and the admin interface are
// registered independently so that an admin-side failure cannot affect token
// issuance.
func newHandler(provider *oidc.Provider, adminHandler *admin.Handler) http.Handler {
	mux := http.NewServeMux()
	provider.Register(mux)
	adminHandler.Register(mux)
	web.Register(mux)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	return mux
}
