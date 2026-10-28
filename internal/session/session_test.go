package session

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/atlasopsec/auth/internal/testdb"
	"github.com/atlasopsec/auth/internal/token"
)

// clock is a fake time source tests move forward explicitly.
type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

const day = 24 * time.Hour

// cmpOpts lets cmp compare netip.Addr, which has unexported fields.
var cmpOpts = cmp.Comparer(func(a, b netip.Addr) bool { return a == b })

type fixture struct {
	pool  *pgxpool.Pool
	clock *clock
	m     *Manager
}

func setup(t *testing.T) fixture {
	t.Helper()
	pool := testdb.NewMigrated(t)
	c := &clock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	return fixture{pool: pool, clock: c, m: NewManager(pool, c.now)}
}

func (f fixture) newUser(t *testing.T) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	if _, err := f.pool.Exec(context.Background(),
		`INSERT INTO auth.users (id, email) VALUES ($1, $2)`, id, id.String()+"@example.com"); err != nil {
		t.Fatalf("creating user: %v", err)
	}
	return id
}

func (f fixture) create(t *testing.T, userID uuid.UUID, p Policy) (string, Session) {
	t.Helper()
	tok, s, err := f.m.Create(context.Background(), userID, Meta{Client: ClientWeb}, p)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	return tok, s
}

func TestCreate(t *testing.T) {
	t.Parallel()
	f := setup(t)
	ctx := context.Background()
	user := f.newUser(t)
	ip := netip.MustParseAddr("203.0.113.7")

	tok, s, err := f.m.Create(ctx, user, Meta{Client: ClientMobile, IP: &ip, UserAgent: "ExampleApp/1.0"}, Standard)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if !token.Valid(tok) {
		t.Errorf("Create() token %q isn't a valid token", tok)
	}

	start := f.clock.t
	want := Session{
		ID:                s.ID,
		UserID:            user,
		Client:            ClientMobile,
		IP:                &ip,
		UserAgent:         "ExampleApp/1.0",
		LastUsedAt:        start,
		ExpiresAt:         start.Add(30 * day),
		AbsoluteExpiresAt: start.Add(90 * day),
		CreatedAt:         start,
	}
	if diff := cmp.Diff(want, s, cmpOpts); diff != "" {
		t.Errorf("Create() session (-want +got):\n%s", diff)
	}
	if s.ID.Version() != 7 {
		t.Errorf("session ID version = %d, want UUIDv7", s.ID.Version())
	}
}

func TestCreateStoresOnlyTokenHash(t *testing.T) {
	t.Parallel()
	f := setup(t)
	ctx := context.Background()
	tok, s := f.create(t, f.newUser(t), Standard)

	var stored []byte
	if err := f.pool.QueryRow(ctx, `SELECT token_hash FROM auth.sessions WHERE id = $1`, s.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !token.Equal(stored, token.Hash(tok)) {
		t.Errorf("stored token_hash isn't the SHA-256 of the token")
	}
	if strings.Contains(string(stored), tok) {
		t.Errorf("the token itself is stored in the database")
	}
}

func TestCreateGivesEachSessionItsOwnToken(t *testing.T) {
	t.Parallel()
	f := setup(t)
	user := f.newUser(t)
	a, _ := f.create(t, user, Standard)
	b, _ := f.create(t, user, Standard)
	if a == b {
		t.Fatalf("two sessions for the same user got the same token")
	}
}

func TestCreateRejectsBadInput(t *testing.T) {
	t.Parallel()
	f := setup(t)
	ctx := context.Background()
	user := f.newUser(t)

	tests := []struct {
		name   string
		userID uuid.UUID
		meta   Meta
		p      Policy
	}{
		{"unknown client", user, Meta{Client: "desktop"}, Standard},
		{"empty client", user, Meta{}, Standard},
		{"nonexistent user", uuid.Must(uuid.NewV7()), Meta{Client: ClientWeb}, Standard},
		{"zero policy", user, Meta{Client: ClientWeb}, Policy{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok, _, err := f.m.Create(ctx, tt.userID, tt.meta, tt.p)
			if err == nil {
				t.Errorf("Create() error = nil, want an error")
			}
			if tok != "" {
				t.Errorf("Create() returned a token alongside an error")
			}
		})
	}
}

func TestCreateTruncatesUserAgent(t *testing.T) {
	t.Parallel()
	f := setup(t)
	ctx := context.Background()
	user := f.newUser(t)

	tests := []struct {
		name string
		ua   string
		want string
	}{
		{"empty", "", ""},
		{"normal", "Mozilla/5.0", "Mozilla/5.0"},
		{"long ASCII", strings.Repeat("a", 600), strings.Repeat("a", 512)},
		{"long multi-byte, not split mid-character", strings.Repeat("é", 600), strings.Repeat("é", 512)},
		{"invalid UTF-8 replaced", "bad\xffbyte", "bad�byte"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, s, err := f.m.Create(ctx, user, Meta{Client: ClientWeb, UserAgent: tt.ua}, Standard)
			if err != nil {
				t.Fatalf("Create() error = %v", err)
			}
			if s.UserAgent != tt.want {
				t.Errorf("UserAgent = %q (%d chars), want %q", s.UserAgent, len([]rune(s.UserAgent)), tt.want)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()
	f := setup(t)
	tok, created := f.create(t, f.newUser(t), Standard)

	got, err := f.m.Validate(context.Background(), tok)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if diff := cmp.Diff(created, got, cmpOpts); diff != "" {
		t.Errorf("Validate() session (-created +validated):\n%s", diff)
	}
}

func TestValidateRejects(t *testing.T) {
	t.Parallel()
	f := setup(t)
	ctx := context.Background()
	tok, _ := f.create(t, f.newUser(t), Standard)

	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"malformed", "not-a-token"},
		{"unknown but well-formed", token.New()},
		{"token with one character changed", changeLastChar(tok)},
		{"hash of the token instead of the token", string(token.Hash(tok))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := f.m.Validate(ctx, tt.token); !errors.Is(err, ErrInvalid) {
				t.Errorf("Validate() error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestIdleExpiry(t *testing.T) {
	t.Parallel()
	f := setup(t)
	ctx := context.Background()
	tok, _ := f.create(t, f.newUser(t), Standard)

	f.clock.advance(30*day - time.Microsecond)
	if _, err := f.m.Validate(ctx, tok); err != nil {
		t.Fatalf("Validate() just before idle expiry: error = %v", err)
	}

	// That use extended the session, so check the extended expiry exactly.
	f.clock.advance(30 * day)
	if _, err := f.m.Validate(ctx, tok); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Validate() exactly at idle expiry: error = %v, want ErrInvalid", err)
	}
}

func TestIdleExpiryWithoutUse(t *testing.T) {
	t.Parallel()
	f := setup(t)
	tok, _ := f.create(t, f.newUser(t), Standard)

	f.clock.advance(30 * day)
	if _, err := f.m.Validate(context.Background(), tok); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Validate() after 30 idle days: error = %v, want ErrInvalid", err)
	}
}

func TestAbsoluteExpiryDespiteDailyUse(t *testing.T) {
	t.Parallel()
	f := setup(t)
	ctx := context.Background()
	tok, _ := f.create(t, f.newUser(t), Standard)

	// Used every day, the session never idles out, but still ends at 90 days.
	for d := 1; d < 90; d++ {
		f.clock.advance(day)
		if _, err := f.m.Validate(ctx, tok); err != nil {
			t.Fatalf("Validate() on day %d: error = %v", d, err)
		}
	}
	f.clock.advance(day)
	if _, err := f.m.Validate(ctx, tok); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Validate() on day 90: error = %v, want ErrInvalid", err)
	}
}

func TestExtension(t *testing.T) {
	t.Parallel()
	f := setup(t)
	ctx := context.Background()
	tok, created := f.create(t, f.newUser(t), Standard)

	// Used again within a day: no extension, no write.
	f.clock.advance(23 * time.Hour)
	s, err := f.m.Validate(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	if !s.ExpiresAt.Equal(created.ExpiresAt) || !s.LastUsedAt.Equal(created.LastUsedAt) {
		t.Errorf("session extended after 23h: expires %v -> %v", created.ExpiresAt, s.ExpiresAt)
	}

	// Used after a day: idle expiry moves to 30 days from now.
	f.clock.advance(time.Hour)
	s, err = f.m.Validate(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	if want := f.clock.t.Add(30 * day); !s.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt after extension = %v, want %v", s.ExpiresAt, want)
	}
	if !s.LastUsedAt.Equal(f.clock.t) {
		t.Errorf("LastUsedAt = %v, want %v", s.LastUsedAt, f.clock.t)
	}

	// The extension was saved, not just returned.
	again, err := f.m.Validate(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	if !again.ExpiresAt.Equal(s.ExpiresAt) {
		t.Errorf("extension not persisted: %v, want %v", again.ExpiresAt, s.ExpiresAt)
	}
}

func TestExtensionNeverPassesAbsoluteExpiry(t *testing.T) {
	t.Parallel()
	f := setup(t)
	ctx := context.Background()
	tok, created := f.create(t, f.newUser(t), Standard)

	// Day 85: extending by 30 days would reach day 115, past the 90-day limit.
	var s Session
	for range 85 {
		f.clock.advance(day)
		var err error
		if s, err = f.m.Validate(ctx, tok); err != nil {
			t.Fatal(err)
		}
	}
	if !s.ExpiresAt.Equal(created.AbsoluteExpiresAt) {
		t.Errorf("ExpiresAt = %v, want capped at AbsoluteExpiresAt %v", s.ExpiresAt, created.AbsoluteExpiresAt)
	}
}

func TestPrivilegedPolicy(t *testing.T) {
	t.Parallel()
	f := setup(t)
	ctx := context.Background()
	tok, s := f.create(t, f.newUser(t), Privileged)

	if want := f.clock.t.Add(12 * time.Hour); !s.AbsoluteExpiresAt.Equal(want) || !s.ExpiresAt.Equal(want) {
		t.Fatalf("privileged session expires at %v / %v, want both %v", s.ExpiresAt, s.AbsoluteExpiresAt, want)
	}

	f.clock.advance(12*time.Hour - time.Microsecond)
	if _, err := f.m.Validate(ctx, tok); err != nil {
		t.Fatalf("Validate() just under 12h: error = %v", err)
	}
	f.clock.advance(time.Microsecond)
	if _, err := f.m.Validate(ctx, tok); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Validate() at 12h: error = %v, want ErrInvalid", err)
	}
}

func TestValidateDeletesExpiredSession(t *testing.T) {
	t.Parallel()
	f := setup(t)
	ctx := context.Background()
	tok, s := f.create(t, f.newUser(t), Standard)

	f.clock.advance(31 * day)
	if _, err := f.m.Validate(ctx, tok); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Validate() error = %v, want ErrInvalid", err)
	}
	var n int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM auth.sessions WHERE id = $1`, s.ID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("expired session still in the database after Validate()")
	}
}

func TestRevoke(t *testing.T) {
	t.Parallel()
	f := setup(t)
	ctx := context.Background()
	alice, bob := f.newUser(t), f.newUser(t)
	aliceTok, aliceSession := f.create(t, alice, Standard)

	// Bob can't revoke Alice's session, and learns nothing about it.
	if err := f.m.Revoke(ctx, bob, aliceSession.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("Revoke(other user's session) error = %v, want ErrNotFound", err)
	}
	if _, err := f.m.Validate(ctx, aliceTok); err != nil {
		t.Errorf("Alice's session stopped working after Bob's failed revoke: %v", err)
	}

	if err := f.m.Revoke(ctx, alice, aliceSession.ID); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if _, err := f.m.Validate(ctx, aliceTok); !errors.Is(err, ErrInvalid) {
		t.Errorf("Validate() after revoke: error = %v, want ErrInvalid", err)
	}
	if err := f.m.Revoke(ctx, alice, aliceSession.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("Revoke() twice: error = %v, want ErrNotFound", err)
	}
}

func TestRevokeAll(t *testing.T) {
	t.Parallel()
	f := setup(t)
	ctx := context.Background()
	alice, bob := f.newUser(t), f.newUser(t)
	a1, _ := f.create(t, alice, Standard)
	a2, _ := f.create(t, alice, Standard)
	b1, _ := f.create(t, bob, Standard)

	n, err := f.m.RevokeAll(ctx, alice)
	if err != nil || n != 2 {
		t.Fatalf("RevokeAll() = %d, %v; want 2, nil", n, err)
	}
	for _, tok := range []string{a1, a2} {
		if _, err := f.m.Validate(ctx, tok); !errors.Is(err, ErrInvalid) {
			t.Errorf("Alice's session still valid after RevokeAll: %v", err)
		}
	}
	if _, err := f.m.Validate(ctx, b1); err != nil {
		t.Errorf("Bob's session revoked by Alice's RevokeAll: %v", err)
	}
}

func TestRevokeOthers(t *testing.T) {
	t.Parallel()
	f := setup(t)
	ctx := context.Background()
	user := f.newUser(t)
	current, currentSession := f.create(t, user, Standard)
	other1, _ := f.create(t, user, Standard)
	other2, _ := f.create(t, user, Standard)

	n, err := f.m.RevokeOthers(ctx, user, currentSession.ID)
	if err != nil || n != 2 {
		t.Fatalf("RevokeOthers() = %d, %v; want 2, nil", n, err)
	}
	if _, err := f.m.Validate(ctx, current); err != nil {
		t.Errorf("the kept session was revoked: %v", err)
	}
	for _, tok := range []string{other1, other2} {
		if _, err := f.m.Validate(ctx, tok); !errors.Is(err, ErrInvalid) {
			t.Errorf("other session still valid: %v", err)
		}
	}
}

func TestList(t *testing.T) {
	t.Parallel()
	f := setup(t)
	ctx := context.Background()
	alice, bob := f.newUser(t), f.newUser(t)

	_, expired := f.create(t, alice, Privileged) // will expire after 12h
	f.clock.advance(time.Hour)
	_, older := f.create(t, alice, Standard)
	f.clock.advance(time.Hour)
	_, newer := f.create(t, alice, Standard)
	f.create(t, bob, Standard)
	f.clock.advance(11 * time.Hour)

	got, err := f.m.List(ctx, alice)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	var ids []uuid.UUID
	for _, s := range got {
		ids = append(ids, s.ID)
	}
	want := []uuid.UUID{newer.ID, older.ID}
	if diff := cmp.Diff(want, ids); diff != "" {
		t.Errorf("List() IDs (-want +got):\n%s\n(expired session %s should be excluded, Bob's too)", diff, expired.ID)
	}
}

func TestDeleteExpired(t *testing.T) {
	t.Parallel()
	f := setup(t)
	ctx := context.Background()
	user := f.newUser(t)
	f.create(t, user, Privileged)
	f.create(t, user, Privileged)
	live, _ := f.create(t, user, Standard)

	f.clock.advance(13 * time.Hour)
	n, err := f.m.DeleteExpired(ctx)
	if err != nil || n != 2 {
		t.Fatalf("DeleteExpired() = %d, %v; want 2, nil", n, err)
	}
	if _, err := f.m.Validate(ctx, live); err != nil {
		t.Errorf("DeleteExpired removed a live session: %v", err)
	}
}

func TestDeletingUserEndsSessions(t *testing.T) {
	t.Parallel()
	f := setup(t)
	ctx := context.Background()
	user := f.newUser(t)
	tok, _ := f.create(t, user, Standard)

	if _, err := f.pool.Exec(ctx, `DELETE FROM auth.users WHERE id = $1`, user); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.Validate(ctx, tok); !errors.Is(err, ErrInvalid) {
		t.Errorf("Validate() after the user was deleted: error = %v, want ErrInvalid", err)
	}
}

// changeLastChar returns tok with its last character swapped for a
// different valid one, so it's still well-formed but no longer matches.
func changeLastChar(tok string) string {
	last := byte('A')
	if tok[len(tok)-1] == 'A' {
		last = 'B'
	}
	return tok[:len(tok)-1] + string(last)
}
