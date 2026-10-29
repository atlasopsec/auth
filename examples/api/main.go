// Command api is an example Go API built on the auth module. It serves the
// Next.js template (templates/nextjs) in development and in its end-to-end
// tests, and shows how a project wires auth.New.
//
// It prints emails, with their live links, instead of sending them, so it
// must never be deployed.
//
// Settings, from environment variables:
//
//	DATABASE_URL     Postgres connection string (required)
//	ENCRYPTION_KEY   32 random bytes, base64 (required)
//	PORT             port to listen on (default 8080)
//	APP_URL          the web app's URL, for links (default http://localhost:3000)
//	MAIL_FILE        file to append emails to (default: standard output)
//	TRUSTED_PROXIES  comma-separated networks allowed to forward the
//	                 client's IP and user agent (default: loopback)
//	DISABLE_BREACH_CHECK  "true" skips Have I Been Pwned, for tests that
//	                 mustn't use the network
//	GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GITHUB_CLIENT_ID,
//	GITHUB_CLIENT_SECRET  turn on those providers when set
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/atlasopsec/auth"
	"github.com/atlasopsec/auth/mail"
	"github.com/atlasopsec/auth/rbac"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		slog.Error("example api", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		return fmt.Errorf("connecting to Postgres: %w", err)
	}
	defer pool.Close()
	if err := auth.Migrate(ctx, pool); err != nil {
		return fmt.Errorf("migrating: %w", err)
	}

	var mailOut io.Writer = os.Stdout
	if path := os.Getenv("MAIL_FILE"); path != "" {
		// The path is the operator's own setting for a development tool.
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // G304, G703: MAIL_FILE is set by whoever runs this, not by a request
		if err != nil {
			return fmt.Errorf("opening MAIL_FILE: %w", err)
		}
		defer func() {
			if err := f.Close(); err != nil {
				slog.Error("closing MAIL_FILE", slog.String("error", err.Error()))
			}
		}()
		mailOut = f
	}
	trusted, err := parsePrefixes(envOr("TRUSTED_PROXIES", "127.0.0.0/8,::1/128"))
	if err != nil {
		return fmt.Errorf("TRUSTED_PROXIES: %w", err)
	}

	a, err := auth.New(auth.Config{
		DB:                 pool,
		Mailer:             mail.NewWriter(mailOut),
		AppURL:             envOr("APP_URL", "http://localhost:3000"),
		AppName:            "Example",
		EncryptionKey:      os.Getenv("ENCRYPTION_KEY"),
		TrustedProxies:     trusted,
		DisableBreachCheck: os.Getenv("DISABLE_BREACH_CHECK") == "true",
		OrgRoles: rbac.Roles{
			auth.OwnerRole: {rbac.All},
			"admin":        {auth.PermOrganizationUpdate, auth.PermMembersRead, auth.PermMembersManage},
			"member":       {auth.PermMembersRead},
		},
		OAuth: oauthFromEnv(),
	})
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	a.Register(mux)
	mux.Handle("GET /healthz", a.Public(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})))
	srv := &http.Server{
		Addr:              ":" + envOr("PORT", "8080"),
		Handler:           a.Protect(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errs := make(chan error, 1)
	go func() { errs <- srv.ListenAndServe() }()
	slog.Info("example api listening", slog.String("addr", srv.Addr))
	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdown); err != nil {
		return fmt.Errorf("shutting down: %w", err)
	}
	return a.Close(shutdown)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func parsePrefixes(list string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range strings.Split(list, ",") {
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func oauthFromEnv() auth.OAuth {
	var o auth.OAuth
	if id := os.Getenv("GOOGLE_CLIENT_ID"); id != "" {
		o.Google = &auth.Google{ClientID: id, ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET")}
	}
	if id := os.Getenv("GITHUB_CLIENT_ID"); id != "" {
		o.GitHub = &auth.GitHub{ClientID: id, ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET")}
	}
	return o
}
