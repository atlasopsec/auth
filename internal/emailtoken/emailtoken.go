// Package emailtoken creates and checks the single-use tokens sent in
// emails: verification, password reset, and email change.
//
// Like session tokens, only a token's SHA-256 hash is stored. A token works
// once, for one kind of action, until it expires. Creating a token cancels
// the user's earlier unused tokens of the same kind, and a user gets at
// most one new token of each kind per Cooldown, which limits how many
// emails anyone can trigger until real rate limiting exists.
package emailtoken

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/atlasopsec/auth/internal/db"
	"github.com/atlasopsec/auth/internal/token"
)

// Kind is what a token is for.
type Kind string

// Token kinds.
const (
	VerifyEmail   Kind = "verify_email"
	ResetPassword Kind = "reset_password"
	ChangeEmail   Kind = "change_email"
)

// Lifetime returns how long a token of kind k works.
func (k Kind) Lifetime() time.Duration {
	switch k {
	case VerifyEmail:
		return 24 * time.Hour
	case ResetPassword:
		// The auth standard's limit for reset links.
		return 30 * time.Minute
	case ChangeEmail:
		return time.Hour
	}
	return 0
}

// Cooldown is the minimum time between two tokens of the same kind for one
// user.
const Cooldown = 60 * time.Second

// MaxFailedAttempts is how many wrong passwords can be entered with a token
// before it stops working, so a stolen link can't be used to guess a
// password.
const MaxFailedAttempts = 5

var (
	// ErrInvalid means a token is malformed, unknown, for a different kind
	// of action, used, expired, or locked by failed attempts. These cases
	// are deliberately indistinguishable to callers.
	ErrInvalid = errors.New("email token is invalid or expired")
	// ErrCooldown means the user was sent a token of this kind less than
	// Cooldown ago.
	ErrCooldown = errors.New("email token requested too soon")
)

// Token is a stored email token. It never contains the token itself.
type Token struct {
	ID     uuid.UUID
	UserID uuid.UUID
	Kind   Kind
	// NewEmail is the address being switched to, for ChangeEmail only.
	NewEmail  string
	ExpiresAt time.Time
}

// Conn is a database connection that can start a transaction: a pool, or a
// transaction (which starts a savepoint).
type Conn interface {
	db.DBTX
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Manager manages email tokens in the database.
type Manager struct {
	conn Conn
	q    *db.Queries
	now  func() time.Time
}

// NewManager returns a Manager using conn. now supplies the current time;
// pass time.Now outside tests.
func NewManager(conn Conn, now func() time.Time) *Manager {
	return &Manager{conn: conn, q: db.New(conn), now: now}
}

// Create makes a new token of kind for userID and returns it. The token is
// returned only here, to be put in an email. newEmail is required for
// ChangeEmail and must be empty otherwise. It returns ErrCooldown if the
// user got a token of this kind less than Cooldown ago.
func (m *Manager) Create(ctx context.Context, userID uuid.UUID, kind Kind, newEmail string) (string, Token, error) {
	if kind.Lifetime() == 0 {
		return "", Token{}, fmt.Errorf("emailtoken: unknown kind %q", kind)
	}
	if (kind == ChangeEmail) != (newEmail != "") {
		return "", Token{}, errors.New("emailtoken: new email must be given for change_email tokens only")
	}
	id, err := uuid.NewV7()
	if err != nil {
		return "", Token{}, fmt.Errorf("emailtoken: generating ID: %w", err)
	}

	tx, err := m.conn.Begin(ctx)
	if err != nil {
		return "", Token{}, fmt.Errorf("emailtoken: beginning: %w", err)
	}
	// After Commit this is a no-op.
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	q := m.q.WithTx(tx)

	if _, err := q.LockUser(ctx, userID); err != nil {
		return "", Token{}, fmt.Errorf("emailtoken: locking user: %w", err)
	}
	now := m.clock()
	last, err := q.LatestEmailTokenCreatedAt(ctx, db.LatestEmailTokenCreatedAtParams{UserID: userID, Kind: string(kind)})
	switch {
	case err == nil && now.Sub(last) < Cooldown:
		return "", Token{}, ErrCooldown
	case err != nil && !errors.Is(err, pgx.ErrNoRows):
		return "", Token{}, fmt.Errorf("emailtoken: checking cooldown: %w", err)
	}
	if err := q.DeleteUnusedEmailTokens(ctx, db.DeleteUnusedEmailTokensParams{UserID: userID, Kind: string(kind)}); err != nil {
		return "", Token{}, fmt.Errorf("emailtoken: cancelling earlier tokens: %w", err)
	}

	tok := token.New()
	var ne *string
	if newEmail != "" {
		ne = &newEmail
	}
	row, err := q.CreateEmailToken(ctx, db.CreateEmailTokenParams{
		ID:        id,
		UserID:    userID,
		Kind:      string(kind),
		TokenHash: token.Hash(tok),
		NewEmail:  ne,
		ExpiresAt: now.Add(kind.Lifetime()),
		Now:       now,
	})
	if err != nil {
		return "", Token{}, fmt.Errorf("emailtoken: creating: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", Token{}, fmt.Errorf("emailtoken: committing: %w", err)
	}
	return tok, fromRow(row), nil
}

// Lookup returns the token tok if it's usable for kind, without using it.
// Call Use to spend it.
func (m *Manager) Lookup(ctx context.Context, tok string, kind Kind) (Token, error) {
	if !token.Valid(tok) {
		return Token{}, ErrInvalid
	}
	row, err := m.q.GetEmailTokenByHash(ctx, db.GetEmailTokenByHashParams{TokenHash: token.Hash(tok), Kind: string(kind)})
	if errors.Is(err, pgx.ErrNoRows) {
		return Token{}, ErrInvalid
	}
	if err != nil {
		return Token{}, fmt.Errorf("emailtoken: looking up: %w", err)
	}
	if row.UsedAt != nil || !m.clock().Before(row.ExpiresAt) || row.FailedAttempts >= MaxFailedAttempts {
		return Token{}, ErrInvalid
	}
	return fromRow(row), nil
}

// RecordFailure counts a wrong password entered with token id. After
// MaxFailedAttempts the token stops working.
func (m *Manager) RecordFailure(ctx context.Context, id uuid.UUID) error {
	if err := m.q.RecordEmailTokenFailure(ctx, db.RecordEmailTokenFailureParams{ID: id, Now: m.clock()}); err != nil {
		return fmt.Errorf("emailtoken: recording failure: %w", err)
	}
	return nil
}

// Use spends token id so it can't be used again. It returns ErrInvalid if
// the token stopped being usable since Lookup, e.g. because a concurrent
// request used it first. Call it in the same transaction as the action the
// token authorizes, so the token is spent only if the action happens.
func (m *Manager) Use(ctx context.Context, id uuid.UUID) error {
	now := m.clock()
	n, err := m.q.UseEmailToken(ctx, db.UseEmailTokenParams{ID: id, Now: &now, MaxFailedAttempts: MaxFailedAttempts})
	if err != nil {
		return fmt.Errorf("emailtoken: using: %w", err)
	}
	if n == 0 {
		return ErrInvalid
	}
	return nil
}

// DeleteSpent removes used and expired tokens and returns how many were
// removed. Run it periodically; spent tokens are already rejected, so this
// only frees space.
func (m *Manager) DeleteSpent(ctx context.Context) (int64, error) {
	n, err := m.q.DeleteSpentEmailTokens(ctx, m.clock())
	if err != nil {
		return 0, fmt.Errorf("emailtoken: deleting spent tokens: %w", err)
	}
	return n, nil
}

// clock returns the current time in UTC, at Postgres' microsecond precision.
func (m *Manager) clock() time.Time {
	return m.now().UTC().Truncate(time.Microsecond)
}

func fromRow(r db.AuthEmailToken) Token {
	t := Token{ID: r.ID, UserID: r.UserID, Kind: Kind(r.Kind), ExpiresAt: r.ExpiresAt.UTC()}
	if r.NewEmail != nil {
		t.NewEmail = *r.NewEmail
	}
	return t
}
