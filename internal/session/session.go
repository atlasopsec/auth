// Package session creates, validates, extends, and revokes login sessions.
//
// A session is identified by a random token (see internal/token) that's
// given to the client once. Only the token's SHA-256 hash is stored, so a
// database leak doesn't expose working sessions.
//
// Expiry follows the auth standard (§4): a session ends after a period of
// inactivity (idle timeout) and, regardless of activity, after a maximum
// lifetime. Activity pushes the idle expiry forward, but only once per
// ExtendAfter interval, to avoid a database write on every request.
package session

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/atlasopsec/auth/internal/db"
	"github.com/atlasopsec/auth/internal/token"
)

var (
	// ErrInvalid means a token doesn't identify a usable session: it's
	// malformed, unknown, revoked, or expired. These cases are deliberately
	// indistinguishable to callers.
	ErrInvalid = errors.New("session is invalid or expired")
	// ErrNotFound means a session to revoke doesn't exist or doesn't belong
	// to the given user.
	ErrNotFound = errors.New("session not found")
)

// Client is the kind of client a session was created for.
type Client string

// Supported clients. Web sessions travel in a cookie set by Next.js; mobile
// sessions in an Authorization header.
const (
	ClientWeb    Client = "web"
	ClientMobile Client = "mobile"
)

// maxUserAgent matches the length limit on auth.sessions.user_agent.
const maxUserAgent = 512

// Policy sets how long a session lives.
type Policy struct {
	// IdleTimeout ends a session that hasn't been used for this long.
	IdleTimeout time.Duration
	// MaxLifetime ends a session this long after it was created, however
	// much it's used.
	MaxLifetime time.Duration
}

var (
	// Standard is for regular users: 30 days idle, 90 days at most.
	Standard = Policy{IdleTimeout: 30 * 24 * time.Hour, MaxLifetime: 90 * 24 * time.Hour}
	// Privileged is for users with admin or elevated roles: 12 hours.
	Privileged = Policy{IdleTimeout: 12 * time.Hour, MaxLifetime: 12 * time.Hour}
)

// ExtendAfter is how long after the last extension a session must be used
// before its idle expiry is pushed forward again.
const ExtendAfter = 24 * time.Hour

// Session is a login session. It never contains the token or its hash.
type Session struct {
	ID                uuid.UUID
	UserID            uuid.UUID
	Client            Client
	IP                *netip.Addr
	UserAgent         string
	LastUsedAt        time.Time
	ExpiresAt         time.Time
	AbsoluteExpiresAt time.Time
	CreatedAt         time.Time
}

// Meta describes the client a session is created for.
type Meta struct {
	Client    Client
	IP        *netip.Addr
	UserAgent string
}

// Manager manages sessions in the database.
type Manager struct {
	q   *db.Queries
	now func() time.Time
}

// NewManager returns a Manager using conn, which may be a pool or a
// transaction. now supplies the current time; pass time.Now outside tests.
func NewManager(conn db.DBTX, now func() time.Time) *Manager {
	return &Manager{q: db.New(conn), now: now}
}

// Create starts a new session for userID and returns its token. The token is
// returned only here and must be given to the client; it can't be recovered
// later.
func (m *Manager) Create(ctx context.Context, userID uuid.UUID, meta Meta, p Policy) (string, Session, error) {
	if meta.Client != ClientWeb && meta.Client != ClientMobile {
		return "", Session{}, fmt.Errorf("session: unknown client %q", meta.Client)
	}
	if p.IdleTimeout <= 0 || p.MaxLifetime <= 0 {
		return "", Session{}, errors.New("session: policy durations must be positive")
	}

	id, err := uuid.NewV7()
	if err != nil {
		return "", Session{}, fmt.Errorf("session: generating ID: %w", err)
	}
	tok := token.New()
	now := m.clock()
	absolute := now.Add(p.MaxLifetime)

	row, err := m.q.CreateSession(ctx, db.CreateSessionParams{
		ID:                id,
		UserID:            userID,
		TokenHash:         token.Hash(tok),
		Client:            string(meta.Client),
		Ip:                meta.IP,
		UserAgent:         truncateUserAgent(meta.UserAgent),
		Now:               now,
		ExpiresAt:         earliest(now.Add(p.IdleTimeout), absolute),
		AbsoluteExpiresAt: absolute,
	})
	if err != nil {
		return "", Session{}, fmt.Errorf("session: creating: %w", err)
	}
	return tok, fromRow(row), nil
}

// Validate returns the session for tok, extending its idle expiry if it's
// due. It returns ErrInvalid for any token that doesn't identify a usable
// session, and deletes sessions it finds expired.
func (m *Manager) Validate(ctx context.Context, tok string) (Session, error) {
	if !token.Valid(tok) {
		return Session{}, ErrInvalid
	}
	row, err := m.q.GetSessionByTokenHash(ctx, token.Hash(tok))
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, ErrInvalid
	}
	if err != nil {
		return Session{}, fmt.Errorf("session: looking up: %w", err)
	}

	now := m.clock()
	if !now.Before(row.ExpiresAt) || !now.Before(row.AbsoluteExpiresAt) {
		// Best effort: an expired session is useless either way, and
		// DeleteExpired cleans up anything missed here.
		if _, err := m.q.DeleteSession(ctx, db.DeleteSessionParams{ID: row.ID, UserID: row.UserID}); err != nil {
			return Session{}, fmt.Errorf("session: deleting expired: %w", err)
		}
		return Session{}, ErrInvalid
	}

	if now.Sub(row.LastUsedAt) >= ExtendAfter {
		expires := earliest(now.Add(Standard.IdleTimeout), row.AbsoluteExpiresAt)
		// Never shorten a session by "extending" it, e.g. a privileged one
		// whose idle expiry already equals its absolute expiry.
		if expires.Before(row.ExpiresAt) {
			expires = row.ExpiresAt
		}
		if err := m.q.ExtendSession(ctx, db.ExtendSessionParams{ID: row.ID, Now: now, ExpiresAt: expires}); err != nil {
			return Session{}, fmt.Errorf("session: extending: %w", err)
		}
		row.LastUsedAt = now
		row.ExpiresAt = expires
	}
	return fromRow(row), nil
}

// List returns userID's sessions that haven't expired, most recently used
// first.
func (m *Manager) List(ctx context.Context, userID uuid.UUID) ([]Session, error) {
	rows, err := m.q.ListActiveSessions(ctx, db.ListActiveSessionsParams{UserID: userID, Now: m.clock()})
	if err != nil {
		return nil, fmt.Errorf("session: listing: %w", err)
	}
	sessions := make([]Session, len(rows))
	for i, r := range rows {
		sessions[i] = fromRow(r)
	}
	return sessions, nil
}

// Revoke ends one of userID's sessions. It returns ErrNotFound if the
// session doesn't exist or belongs to someone else.
func (m *Manager) Revoke(ctx context.Context, userID, sessionID uuid.UUID) error {
	n, err := m.q.DeleteSession(ctx, db.DeleteSessionParams{ID: sessionID, UserID: userID})
	if err != nil {
		return fmt.Errorf("session: revoking: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// RevokeAll ends every session userID has ("log out everywhere"), and
// returns how many were ended.
func (m *Manager) RevokeAll(ctx context.Context, userID uuid.UUID) (int64, error) {
	n, err := m.q.DeleteUserSessions(ctx, userID)
	if err != nil {
		return 0, fmt.Errorf("session: revoking all: %w", err)
	}
	return n, nil
}

// RevokeOthers ends every session userID has except keepID, e.g. after a
// password change made from that session. It returns how many were ended.
func (m *Manager) RevokeOthers(ctx context.Context, userID, keepID uuid.UUID) (int64, error) {
	n, err := m.q.DeleteUserSessionsExcept(ctx, db.DeleteUserSessionsExceptParams{UserID: userID, KeepID: keepID})
	if err != nil {
		return 0, fmt.Errorf("session: revoking others: %w", err)
	}
	return n, nil
}

// DeleteExpired removes every expired session and returns how many were
// removed. Run it periodically; expired sessions are already rejected by
// Validate, so this only frees space.
func (m *Manager) DeleteExpired(ctx context.Context) (int64, error) {
	n, err := m.q.DeleteExpiredSessions(ctx, m.clock())
	if err != nil {
		return 0, fmt.Errorf("session: deleting expired: %w", err)
	}
	return n, nil
}

// clock returns the current time in UTC, at Postgres' microsecond precision,
// so times returned to callers equal the times stored.
func (m *Manager) clock() time.Time {
	return m.now().UTC().Truncate(time.Microsecond)
}

func earliest(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// truncateUserAgent cuts a user agent to the database limit without
// splitting a UTF-8 character, and stores empty ones as NULL.
func truncateUserAgent(ua string) *string {
	if ua == "" {
		return nil
	}
	ua = strings.ToValidUTF8(ua, "\uFFFD")
	if utf8.RuneCountInString(ua) > maxUserAgent {
		ua = string([]rune(ua)[:maxUserAgent])
	}
	return &ua
}

func fromRow(r db.AuthSession) Session {
	s := Session{
		ID:                r.ID,
		UserID:            r.UserID,
		Client:            Client(r.Client),
		IP:                r.Ip,
		LastUsedAt:        r.LastUsedAt.UTC(),
		ExpiresAt:         r.ExpiresAt.UTC(),
		AbsoluteExpiresAt: r.AbsoluteExpiresAt.UTC(),
		CreatedAt:         r.CreatedAt.UTC(),
	}
	if r.UserAgent != nil {
		s.UserAgent = *r.UserAgent
	}
	return s
}
