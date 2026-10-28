package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/atlasopsec/auth/internal/db"
	"github.com/atlasopsec/auth/internal/emailtoken"
	"github.com/atlasopsec/auth/internal/sender"
	"github.com/atlasopsec/auth/internal/session"
	"github.com/atlasopsec/auth/mail"
)

// Config configures the module. Only DB is required.
type Config struct {
	// DB is the project's Postgres pool. Run Migrate on it first.
	DB *pgxpool.Pool

	// TrustedProxies are the networks allowed to set X-Forwarded-For and
	// X-Forwarded-User-Agent, normally the Next.js server on Railway's
	// private network. Requests from anywhere else use the connection's
	// own address and User-Agent.
	TrustedProxies []netip.Prefix

	Hooks Hooks

	// Logger receives the module's logs. Default: slog.Default().
	Logger *slog.Logger

	// Now returns the current time. Default: time.Now. Set it in tests to
	// control session expiry.
	Now func() time.Time

	// Mailer sends the module's emails. Required. Use mail/resend in
	// production.
	Mailer mail.Mailer

	// AppURL is the web app's base URL, for links in emails, e.g.
	// "https://app.example.com". Required. It must use https, except on
	// localhost.
	AppURL string

	// AppName appears in email subjects and text, e.g. "Acme". Required.
	AppName string

	// AllowUnverifiedLogin lets users log in before verifying their email,
	// and makes sign-up log them in immediately. Off by default: new users
	// must verify their email, with their password, before they can log
	// in. See docs/api.md.
	AllowUnverifiedLogin bool

	// Emails overrides the default email templates.
	Emails Emails
}

// Hooks let a project react to auth events.
type Hooks struct {
	// OnUserCreated runs inside the sign-up transaction. Returning an error
	// cancels the sign-up, so a project's own rows (e.g. a profile) are
	// created together with the user or not at all.
	//
	// The hook must write through tx, not the project's own pool: writes
	// through the pool aren't part of the transaction and wouldn't be
	// undone. Keep it quick, since the transaction stays open while it
	// runs.
	OnUserCreated func(ctx context.Context, tx pgx.Tx, u User) error
}

// Auth serves the module's endpoints and protects the project's own.
// Create it with New.
type Auth struct {
	pool            *pgxpool.Pool
	q               *db.Queries
	sessions        *session.Manager
	tokens          *emailtoken.Manager
	sender          *sender.Sender
	trusted         []netip.Prefix
	hooks           Hooks
	log             *slog.Logger
	now             func() time.Time
	appURL          string
	appName         string
	allowUnverified bool
	emails          Emails
}

// New validates cfg and returns a ready Auth. It doesn't touch the
// database; call Migrate first.
func New(cfg Config) (*Auth, error) {
	if cfg.DB == nil {
		return nil, errors.New("auth: Config.DB is required")
	}
	if cfg.Mailer == nil {
		return nil, errors.New("auth: Config.Mailer is required")
	}
	if strings.TrimSpace(cfg.AppName) == "" {
		return nil, errors.New("auth: Config.AppName is required")
	}
	appURL, err := parseAppURL(cfg.AppURL)
	if err != nil {
		return nil, err
	}
	for _, p := range cfg.TrustedProxies {
		if !p.IsValid() {
			return nil, fmt.Errorf("auth: invalid trusted proxy prefix %v", p)
		}
	}
	a := &Auth{
		pool:            cfg.DB,
		q:               db.New(cfg.DB),
		trusted:         append([]netip.Prefix(nil), cfg.TrustedProxies...),
		hooks:           cfg.Hooks,
		log:             cfg.Logger,
		now:             cfg.Now,
		appURL:          appURL,
		appName:         cfg.AppName,
		allowUnverified: cfg.AllowUnverifiedLogin,
		emails:          cfg.Emails,
	}
	if a.log == nil {
		a.log = slog.Default()
	}
	if a.now == nil {
		a.now = time.Now
	}
	if a.emails.VerifyEmail == nil {
		a.emails.VerifyEmail = defaultVerifyEmail
	}
	if a.emails.SignUpAttempt == nil {
		a.emails.SignUpAttempt = defaultSignUpAttempt
	}
	a.sessions = session.NewManager(cfg.DB, a.now)
	a.tokens = emailtoken.NewManager(cfg.DB, a.now)
	a.sender = sender.New(cfg.Mailer, a.log)
	if _, ok := cfg.Mailer.(*mail.Writer); ok {
		a.log.Warn("auth: emails are printed by mail.Writer, not sent. Their links contain live tokens: never use mail.Writer in production")
	}
	return a, nil
}

// Close waits for emails that are still being sent, until ctx is done.
// Call it when the server shuts down, after it stops accepting requests.
func (a *Auth) Close(ctx context.Context) error {
	if err := a.sender.Close(ctx); err != nil {
		return fmt.Errorf("auth: closing: %w", err)
	}
	return nil
}

// User is a user account. It never contains password hashes or tokens.
type User struct {
	ID            uuid.UUID
	Email         string
	EmailVerified bool
	CreatedAt     time.Time
}

// Session is a login session. It never contains the session token.
type Session struct {
	ID uuid.UUID
	// Client is "web" or "mobile".
	Client    string
	ExpiresAt time.Time
	CreatedAt time.Time
}

func userFromRow(r db.AuthUser) User {
	return User{
		ID:            r.ID,
		Email:         r.Email,
		EmailVerified: r.EmailVerifiedAt != nil,
		CreatedAt:     r.CreatedAt.UTC(),
	}
}

func sessionFromInternal(s session.Session) Session {
	return Session{
		ID:        s.ID,
		Client:    string(s.Client),
		ExpiresAt: s.ExpiresAt,
		CreatedAt: s.CreatedAt,
	}
}
