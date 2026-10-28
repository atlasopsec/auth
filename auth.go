package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/atlasopsec/auth/internal/db"
	"github.com/atlasopsec/auth/internal/session"
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
	pool     *pgxpool.Pool
	q        *db.Queries
	sessions *session.Manager
	trusted  []netip.Prefix
	hooks    Hooks
	log      *slog.Logger
	now      func() time.Time
}

// New validates cfg and returns a ready Auth. It doesn't touch the
// database; call Migrate first.
func New(cfg Config) (*Auth, error) {
	if cfg.DB == nil {
		return nil, errors.New("auth: Config.DB is required")
	}
	for _, p := range cfg.TrustedProxies {
		if !p.IsValid() {
			return nil, fmt.Errorf("auth: invalid trusted proxy prefix %v", p)
		}
	}
	a := &Auth{
		pool:    cfg.DB,
		q:       db.New(cfg.DB),
		trusted: append([]netip.Prefix(nil), cfg.TrustedProxies...),
		hooks:   cfg.Hooks,
		log:     cfg.Logger,
		now:     cfg.Now,
	}
	if a.log == nil {
		a.log = slog.Default()
	}
	if a.now == nil {
		a.now = time.Now
	}
	a.sessions = session.NewManager(cfg.DB, a.now)
	return a, nil
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
