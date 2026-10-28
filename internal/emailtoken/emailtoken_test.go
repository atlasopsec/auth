package emailtoken

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/atlasopsec/auth/internal/testdb"
	"github.com/atlasopsec/auth/internal/token"
)

// clock is a fake time source tests move forward explicitly.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

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

func (f fixture) create(t *testing.T, user uuid.UUID, kind Kind, newEmail string) (string, Token) {
	t.Helper()
	tok, tk, err := f.m.Create(context.Background(), user, kind, newEmail)
	if err != nil {
		t.Fatalf("Create(%s) error = %v", kind, err)
	}
	return tok, tk
}

func TestCreateAndLookup(t *testing.T) {
	t.Parallel()
	tests := []struct {
		kind     Kind
		newEmail string
		lifetime time.Duration
	}{
		{VerifyEmail, "", 24 * time.Hour},
		{ResetPassword, "", 30 * time.Minute},
		{ChangeEmail, "new@example.com", time.Hour},
	}
	for _, tt := range tests {
		t.Run(string(tt.kind), func(t *testing.T) {
			t.Parallel()
			f := setup(t)
			user := f.newUser(t)

			tok, created := f.create(t, user, tt.kind, tt.newEmail)
			if !token.Valid(tok) {
				t.Errorf("Create() token %q isn't a valid token", tok)
			}
			want := Token{ID: created.ID, UserID: user, Kind: tt.kind, NewEmail: tt.newEmail, ExpiresAt: f.clock.now().Add(tt.lifetime)}
			if diff := cmp.Diff(want, created); diff != "" {
				t.Errorf("Create() (-want +got):\n%s", diff)
			}

			got, err := f.m.Lookup(context.Background(), tok, tt.kind)
			if err != nil {
				t.Fatalf("Lookup() error = %v", err)
			}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("Lookup() (-want +got):\n%s", diff)
			}

			// Only the hash is stored.
			var stored []byte
			if err := f.pool.QueryRow(context.Background(), `SELECT token_hash FROM auth.email_tokens WHERE id = $1`, created.ID).Scan(&stored); err != nil {
				t.Fatal(err)
			}
			if !token.Equal(stored, token.Hash(tok)) {
				t.Error("stored value isn't the token's hash")
			}
		})
	}
}

func TestCreateRejectsBadInput(t *testing.T) {
	t.Parallel()
	f := setup(t)
	user := f.newUser(t)
	tests := []struct {
		name     string
		user     uuid.UUID
		kind     Kind
		newEmail string
	}{
		{"unknown kind", user, "login_link", ""},
		{"change_email without new email", user, ChangeEmail, ""},
		{"new email on another kind", user, ResetPassword, "new@example.com"},
		{"nonexistent user", uuid.Must(uuid.NewV7()), VerifyEmail, ""},
	}
	for _, tt := range tests {
		if _, _, err := f.m.Create(context.Background(), tt.user, tt.kind, tt.newEmail); err == nil {
			t.Errorf("%s: Create() error = nil, want an error", tt.name)
		}
	}
}

func TestLookupRejects(t *testing.T) {
	t.Parallel()
	f := setup(t)
	ctx := context.Background()
	user := f.newUser(t)
	tok, _ := f.create(t, user, ResetPassword, "")

	tests := []struct {
		name string
		tok  string
		kind Kind
	}{
		{"malformed token", "not-a-token", ResetPassword},
		{"unknown token", token.New(), ResetPassword},
		{"token for another kind", tok, VerifyEmail},
	}
	for _, tt := range tests {
		if _, err := f.m.Lookup(ctx, tt.tok, tt.kind); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Lookup() error = %v, want ErrInvalid", tt.name, err)
		}
	}
}

func TestExpiry(t *testing.T) {
	t.Parallel()
	for _, kind := range []Kind{VerifyEmail, ResetPassword, ChangeEmail} {
		t.Run(string(kind), func(t *testing.T) {
			t.Parallel()
			f := setup(t)
			ctx := context.Background()
			newEmail := ""
			if kind == ChangeEmail {
				newEmail = "new@example.com"
			}
			tok, tk := f.create(t, f.newUser(t), kind, newEmail)

			f.clock.advance(kind.Lifetime() - time.Microsecond)
			if _, err := f.m.Lookup(ctx, tok, kind); err != nil {
				t.Fatalf("just before expiry: Lookup() error = %v", err)
			}
			f.clock.advance(time.Microsecond)
			if _, err := f.m.Lookup(ctx, tok, kind); !errors.Is(err, ErrInvalid) {
				t.Errorf("at expiry: Lookup() error = %v, want ErrInvalid", err)
			}
			if err := f.m.Use(ctx, tk.ID); !errors.Is(err, ErrInvalid) {
				t.Errorf("at expiry: Use() error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestSingleUse(t *testing.T) {
	t.Parallel()
	f := setup(t)
	ctx := context.Background()
	tok, tk := f.create(t, f.newUser(t), ResetPassword, "")

	if err := f.m.Use(ctx, tk.ID); err != nil {
		t.Fatalf("first Use() error = %v", err)
	}
	if err := f.m.Use(ctx, tk.ID); !errors.Is(err, ErrInvalid) {
		t.Errorf("second Use() error = %v, want ErrInvalid", err)
	}
	if _, err := f.m.Lookup(ctx, tok, ResetPassword); !errors.Is(err, ErrInvalid) {
		t.Errorf("Lookup() after use: error = %v, want ErrInvalid", err)
	}
}

func TestConcurrentUse(t *testing.T) {
	t.Parallel()
	f := setup(t)
	_, tk := f.create(t, f.newUser(t), ResetPassword, "")

	const n = 5
	errs := make(chan error, n)
	for range n {
		go func() { errs <- f.m.Use(context.Background(), tk.ID) }()
	}
	succeeded := 0
	for range n {
		if err := <-errs; err == nil {
			succeeded++
		} else if !errors.Is(err, ErrInvalid) {
			t.Errorf("Use() error = %v", err)
		}
	}
	if succeeded != 1 {
		t.Errorf("%d concurrent uses succeeded, want 1", succeeded)
	}
}

func TestFailedAttemptsLockToken(t *testing.T) {
	t.Parallel()
	f := setup(t)
	ctx := context.Background()
	tok, tk := f.create(t, f.newUser(t), VerifyEmail, "")

	for i := range MaxFailedAttempts - 1 {
		if err := f.m.RecordFailure(ctx, tk.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.m.Lookup(ctx, tok, VerifyEmail); err != nil {
			t.Fatalf("after %d failures: Lookup() error = %v, want the token to still work", i+1, err)
		}
	}
	if err := f.m.RecordFailure(ctx, tk.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.Lookup(ctx, tok, VerifyEmail); !errors.Is(err, ErrInvalid) {
		t.Errorf("after %d failures: Lookup() error = %v, want ErrInvalid", MaxFailedAttempts, err)
	}
	if err := f.m.Use(ctx, tk.ID); !errors.Is(err, ErrInvalid) {
		t.Errorf("after %d failures: Use() error = %v, want ErrInvalid", MaxFailedAttempts, err)
	}
}

func TestCooldown(t *testing.T) {
	t.Parallel()
	f := setup(t)
	ctx := context.Background()
	user := f.newUser(t)
	first, _ := f.create(t, user, ResetPassword, "")

	f.clock.advance(Cooldown - time.Microsecond)
	if _, _, err := f.m.Create(ctx, user, ResetPassword, ""); !errors.Is(err, ErrCooldown) {
		t.Fatalf("within the cooldown: Create() error = %v, want ErrCooldown", err)
	}
	// The cooldown is per kind and per user.
	f.create(t, user, VerifyEmail, "")
	f.create(t, f.newUser(t), ResetPassword, "")

	f.clock.advance(time.Microsecond)
	second, _ := f.create(t, user, ResetPassword, "")

	// A new token cancels the earlier unused one.
	if _, err := f.m.Lookup(ctx, first, ResetPassword); !errors.Is(err, ErrInvalid) {
		t.Errorf("earlier token: Lookup() error = %v, want ErrInvalid", err)
	}
	if _, err := f.m.Lookup(ctx, second, ResetPassword); err != nil {
		t.Errorf("new token: Lookup() error = %v", err)
	}
}

func TestCooldownUnderConcurrency(t *testing.T) {
	t.Parallel()
	f := setup(t)
	user := f.newUser(t)

	const n = 5
	errs := make(chan error, n)
	for range n {
		go func() {
			_, _, err := f.m.Create(context.Background(), user, VerifyEmail, "")
			errs <- err
		}()
	}
	created := 0
	for range n {
		if err := <-errs; err == nil {
			created++
		} else if !errors.Is(err, ErrCooldown) {
			t.Errorf("Create() error = %v", err)
		}
	}
	if created != 1 {
		t.Errorf("%d concurrent creates succeeded, want 1", created)
	}
}

// TestCreateWaitsForConcurrentCreate checks the per-user lock directly: a
// second Create for the same user must wait for the first to commit, then
// see its token and hit the cooldown. Without the lock, both would pass the
// cooldown check and two emails would go out.
func TestCreateWaitsForConcurrentCreate(t *testing.T) {
	t.Parallel()
	f := setup(t)
	ctx := context.Background()
	user := f.newUser(t)

	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, _, err := NewManager(tx, f.clock.now).Create(ctx, user, VerifyEmail, ""); err != nil {
		t.Fatalf("first Create() error = %v", err)
	}

	result := make(chan error, 1)
	go func() {
		_, _, err := f.m.Create(ctx, user, VerifyEmail, "")
		result <- err
	}()

	// Wait until the second Create is blocked on a lock in Postgres.
	for waiting := false; !waiting; {
		select {
		case err := <-result:
			t.Fatalf("second Create() finished (error = %v) while the first was uncommitted; want it to wait", err)
		default:
		}
		if err := f.pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_stat_activity
				WHERE datname = current_database() AND wait_event_type = 'Lock'
			)`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, ErrCooldown) {
		t.Errorf("second Create() error = %v, want ErrCooldown", err)
	}
}

func TestCreateInsideTransaction(t *testing.T) {
	t.Parallel()
	f := setup(t)
	ctx := context.Background()
	user := f.newUser(t)

	// A token created in a transaction that rolls back doesn't exist.
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := NewManager(tx, f.clock.now).Create(ctx, user, VerifyEmail, "")
	if err != nil {
		t.Fatalf("Create() in a transaction: error = %v", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.Lookup(ctx, tok, VerifyEmail); !errors.Is(err, ErrInvalid) {
		t.Errorf("token from a rolled-back transaction: Lookup() error = %v, want ErrInvalid", err)
	}
}

func TestDeleteSpent(t *testing.T) {
	t.Parallel()
	f := setup(t)
	ctx := context.Background()
	user := f.newUser(t)

	_, used := f.create(t, user, ResetPassword, "")
	if err := f.m.Use(ctx, used.ID); err != nil {
		t.Fatal(err)
	}
	expiring, _ := f.create(t, user, ChangeEmail, "new@example.com")
	f.clock.advance(time.Hour)
	live, _ := f.create(t, user, VerifyEmail, "")

	n, err := f.m.DeleteSpent(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("DeleteSpent() = %d, want 2 (one used, one expired)", n)
	}
	if _, err := f.m.Lookup(ctx, live, VerifyEmail); err != nil {
		t.Errorf("live token after DeleteSpent: Lookup() error = %v", err)
	}
	if _, err := f.m.Lookup(ctx, expiring, ChangeEmail); !errors.Is(err, ErrInvalid) {
		t.Errorf("expired token: Lookup() error = %v, want ErrInvalid", err)
	}
}

func TestDeletingUserDeletesTokens(t *testing.T) {
	t.Parallel()
	f := setup(t)
	ctx := context.Background()
	user := f.newUser(t)
	f.create(t, user, VerifyEmail, "")
	if _, err := f.pool.Exec(ctx, `DELETE FROM auth.users WHERE id = $1`, user); err != nil {
		t.Fatalf("deleting user: %v", err)
	}
	var n int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM auth.email_tokens`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d tokens left after deleting their user, want 0", n)
	}
}

func TestSchemaRequiresNewEmailOnlyForChange(t *testing.T) {
	t.Parallel()
	f := setup(t)
	ctx := context.Background()
	user := f.newUser(t)
	insert := func(kind string, newEmail *string) error {
		_, err := f.pool.Exec(ctx, `
			INSERT INTO auth.email_tokens (id, user_id, kind, token_hash, new_email, expires_at)
			VALUES ($1, $2, $3, $4, $5, now())`,
			uuid.Must(uuid.NewV7()), user, kind, token.Hash(token.New()), newEmail)
		return err
	}
	addr := "new@example.com"
	if err := insert("change_email", nil); err == nil {
		t.Error("change_email without new_email: inserted, want a check violation")
	}
	if err := insert("verify_email", &addr); err == nil {
		t.Error("verify_email with new_email: inserted, want a check violation")
	}
	if err := insert("magic_link", nil); err == nil {
		t.Error("unknown kind: inserted, want a check violation")
	}
}
