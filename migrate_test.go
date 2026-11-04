package auth

import (
	"context"
	"errors"
	"io/fs"
	"sort"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/atlasopsec/auth/internal/migrate"
	"github.com/atlasopsec/auth/internal/migrations"
	"github.com/atlasopsec/auth/internal/testdb"
)

func tablesIn(t *testing.T, pool *pgxpool.Pool, schema string) []string {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT table_name FROM information_schema.tables WHERE table_schema = $1`, schema)
	if err != nil {
		t.Fatalf("listing tables in %s: %v", schema, err)
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	sort.Strings(names)
	return names
}

func TestMigrateCreatesTablesInAuthSchema(t *testing.T) {
	t.Parallel()
	pool := testdb.New(t)

	if err := Migrate(context.Background(), pool); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	want := []string{"auth_events", "email_tokens", "goose_db_version", "invitations", "login_failures", "memberships", "oauth_accounts", "oauth_flows", "organizations", "rate_limits", "recovery_codes", "sessions", "totp_secrets", "two_factor_challenges", "two_factor_failures", "used_apple_nonces", "user_roles", "users"}
	if diff := cmp.Diff(want, tablesIn(t, pool, "auth")); diff != "" {
		t.Errorf("tables in auth schema (-want +got):\n%s", diff)
	}
	if got := tablesIn(t, pool, "public"); len(got) != 0 {
		t.Errorf("Migrate() created tables in public: %v", got)
	}
}

func TestMigrateLeavesPoolUsable(t *testing.T) {
	t.Parallel()
	pool := testdb.New(t)
	ctx := context.Background()

	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	// Migrate must not close or drain the caller's pool.
	var one int
	if err := pool.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil || one != 1 {
		t.Fatalf("pool unusable after Migrate(): got %d, err = %v", one, err)
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	t.Parallel()
	pool := testdb.New(t)
	ctx := context.Background()

	for i := range 3 {
		if err := Migrate(ctx, pool); err != nil {
			t.Fatalf("Migrate() call %d error = %v", i+1, err)
		}
	}
}

func TestMigrateConcurrently(t *testing.T) {
	t.Parallel()
	pool := testdb.New(t)
	ctx := context.Background()

	// Several API instances starting at once must not fail or double-apply.
	const n = 5
	errs := make(chan error, n)
	for range n {
		go func() { errs <- Migrate(ctx, pool) }()
	}
	for range n {
		if err := <-errs; err != nil {
			t.Errorf("concurrent Migrate() error = %v", err)
		}
	}

	files, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	var applied, distinct int
	if err := pool.QueryRow(ctx,
		`SELECT count(*), count(DISTINCT version_id) FROM auth.goose_db_version WHERE version_id > 0`).Scan(&applied, &distinct); err != nil {
		t.Fatal(err)
	}
	if applied != distinct {
		t.Errorf("%d migrations recorded, but only %d distinct: some were applied twice", applied, distinct)
	}
	if distinct != len(files) {
		t.Errorf("%d migrations applied, want all %d", distinct, len(files))
	}
}

func TestMigrateLeavesProjectTablesAlone(t *testing.T) {
	t.Parallel()
	pool := testdb.New(t)
	ctx := context.Background()

	// A project that already has its own users, sessions, and goose tables.
	_, err := pool.Exec(ctx, `
		CREATE TABLE public.users (id int PRIMARY KEY, name text);
		CREATE TABLE public.sessions (id int PRIMARY KEY);
		CREATE TABLE public.goose_db_version (id int PRIMARY KEY, version_id bigint);
		INSERT INTO public.users VALUES (1, 'existing');
		INSERT INTO public.goose_db_version VALUES (1, 42);
	`)
	if err != nil {
		t.Fatal(err)
	}

	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	var name string
	if err := pool.QueryRow(ctx, `SELECT name FROM public.users WHERE id = 1`).Scan(&name); err != nil || name != "existing" {
		t.Errorf("public.users changed: name = %q, err = %v", name, err)
	}
	var version int64
	if err := pool.QueryRow(ctx, `SELECT version_id FROM public.goose_db_version`).Scan(&version); err != nil || version != 42 {
		t.Errorf("project's goose_db_version changed: version = %d, err = %v", version, err)
	}
}

// pgCode returns the Postgres error code of err, or "" if it isn't one.
func pgCode(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

const (
	uniqueViolation     = "23505"
	checkViolation      = "23514"
	notNullViolation    = "23502"
	foreignKeyViolation = "23503"
)

func TestSchemaConstraints(t *testing.T) {
	t.Parallel()
	pool := testdb.New(t)
	ctx := context.Background()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}

	const user1 = "0192d4e1-0000-7000-8000-000000000001"
	const user2 = "0192d4e1-0000-7000-8000-000000000002"
	if _, err := pool.Exec(ctx, `INSERT INTO auth.users (id, email) VALUES ($1, 'Alice@Example.com')`, user1); err != nil {
		t.Fatalf("inserting a valid user: %v", err)
	}

	hash := make([]byte, 32)
	now := time.Now()
	insertSession := func(id, userID string, tokenHash []byte, client string, expires, absolute time.Time) error {
		_, err := pool.Exec(ctx, `
			INSERT INTO auth.sessions (id, user_id, token_hash, client, expires_at, absolute_expires_at)
			VALUES ($1, $2, $3, $4, $5, $6)`, id, userID, tokenHash, client, expires, absolute)
		return err
	}
	if err := insertSession("0192d4e1-0000-7000-8000-0000000000a1", user1, hash, "web", now.Add(time.Hour), now.Add(2*time.Hour)); err != nil {
		t.Fatalf("inserting a valid session: %v", err)
	}

	tests := []struct {
		name     string
		exec     func() error
		wantCode string
	}{
		{
			name: "email unique regardless of case",
			exec: func() error {
				_, err := pool.Exec(ctx, `INSERT INTO auth.users (id, email) VALUES ($1, 'alice@example.COM')`, user2)
				return err
			},
			wantCode: uniqueViolation,
		},
		{
			name: "email required",
			exec: func() error {
				_, err := pool.Exec(ctx, `INSERT INTO auth.users (id, email) VALUES ($1, NULL)`, user2)
				return err
			},
			wantCode: notNullViolation,
		},
		{
			name: "email not blank",
			exec: func() error {
				_, err := pool.Exec(ctx, `INSERT INTO auth.users (id, email) VALUES ($1, '   ')`, user2)
				return err
			},
			wantCode: checkViolation,
		},
		{
			name: "session token hash must be 32 bytes",
			exec: func() error {
				return insertSession("0192d4e1-0000-7000-8000-0000000000a2", user1, make([]byte, 31), "web", now.Add(time.Hour), now.Add(2*time.Hour))
			},
			wantCode: checkViolation,
		},
		{
			name: "session token hash unique",
			exec: func() error {
				return insertSession("0192d4e1-0000-7000-8000-0000000000a3", user1, hash, "web", now.Add(time.Hour), now.Add(2*time.Hour))
			},
			wantCode: uniqueViolation,
		},
		{
			name: "session client must be web or mobile",
			exec: func() error {
				h := make([]byte, 32)
				h[0] = 1
				return insertSession("0192d4e1-0000-7000-8000-0000000000a4", user1, h, "desktop", now.Add(time.Hour), now.Add(2*time.Hour))
			},
			wantCode: checkViolation,
		},
		{
			name: "idle expiry can't be after absolute expiry",
			exec: func() error {
				h := make([]byte, 32)
				h[0] = 2
				return insertSession("0192d4e1-0000-7000-8000-0000000000a5", user1, h, "web", now.Add(3*time.Hour), now.Add(2*time.Hour))
			},
			wantCode: checkViolation,
		},
		{
			name: "session must belong to a real user",
			exec: func() error {
				h := make([]byte, 32)
				h[0] = 3
				return insertSession("0192d4e1-0000-7000-8000-0000000000a6", "0192d4e1-0000-7000-8000-00000000ffff", h, "web", now.Add(time.Hour), now.Add(2*time.Hour))
			},
			wantCode: foreignKeyViolation,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.exec()
			if got := pgCode(err); got != tt.wantCode {
				t.Errorf("error code = %q (err = %v), want %q", got, err, tt.wantCode)
			}
		})
	}
}

func TestDeletingUserDeletesSessions(t *testing.T) {
	t.Parallel()
	pool := testdb.New(t)
	ctx := context.Background()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}

	const userID = "0192d4e1-0000-7000-8000-000000000001"
	now := time.Now()
	_, err := pool.Exec(ctx, `
		INSERT INTO auth.users (id, email) VALUES ($1, 'bob@example.com');
	`, userID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO auth.sessions (id, user_id, token_hash, client, expires_at, absolute_expires_at)
		VALUES ('0192d4e1-0000-7000-8000-0000000000b1', $1, $2, 'mobile', $3, $4)`,
		userID, make([]byte, 32), now.Add(time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := pool.Exec(ctx, `DELETE FROM auth.users WHERE id = $1`, userID); err != nil {
		t.Fatalf("deleting user: %v", err)
	}
	var remaining int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM auth.sessions WHERE user_id = $1`, userID).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Errorf("%d sessions left after deleting their user, want 0", remaining)
	}
}

// TestEveryForeignKeyHasAnIndex checks each foreign key's column leads a
// full (not partial) index, so deleting the row it points at doesn't read
// the whole table.
func TestEveryForeignKeyHasAnIndex(t *testing.T) {
	t.Parallel()
	pool := testdb.New(t)
	ctx := context.Background()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	rows, err := pool.Query(ctx, `
		SELECT c.conrelid::regclass::text || '.' || a.attname
		FROM pg_constraint c
		JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
		WHERE c.contype = 'f' AND c.connamespace = 'auth'::regnamespace
		  AND NOT EXISTS (
		    SELECT 1 FROM pg_index i
		    WHERE i.indrelid = c.conrelid AND i.indkey[0] = c.conkey[1]
		      AND i.indpred IS NULL AND i.indisvalid)
		ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	missing, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Errorf("foreign keys without an index: %v", missing)
	}
}

// TestIndexMigrationRebuildsAnInvalidIndex checks that if building an index
// concurrently failed, leaving an invalid index behind, running Migrate
// again replaces it with a valid one rather than keeping it.
func TestIndexMigrationRebuildsAnInvalidIndex(t *testing.T) {
	t.Parallel()
	pool := testdb.New(t)
	ctx := context.Background()
	// As a failed concurrent build in migration 12 leaves things: the
	// index is there but invalid, and the migration isn't recorded.
	if err := migrate.UpTo(ctx, pool, 11); err != nil {
		t.Fatalf("UpTo(11) error = %v", err)
	}
	if _, err := pool.Exec(ctx, `
		CREATE INDEX idx_auth_events_actor_id ON auth.auth_events (actor_id);
		UPDATE pg_index SET indisvalid = false WHERE indexrelid = 'auth.idx_auth_events_actor_id'::regclass;`); err != nil {
		t.Fatal(err)
	}

	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate() again error = %v", err)
	}
	var valid bool
	if err := pool.QueryRow(ctx, `SELECT indisvalid FROM pg_index WHERE indexrelid = 'auth.idx_auth_events_actor_id'::regclass`).Scan(&valid); err != nil || !valid {
		t.Errorf("index valid = %v (%v), want true", valid, err)
	}
}

// TestIndexMigrationResetsLockTimeout checks the index migration, which
// runs outside a transaction on the project's pool, doesn't leave its
// lock_timeout on the pool's connections.
func TestIndexMigrationResetsLockTimeout(t *testing.T) {
	t.Parallel()
	pool := testdb.New(t)
	ctx := context.Background()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	for _, c := range pool.AcquireAllIdle(ctx) {
		var timeout string
		err := c.QueryRow(ctx, `SHOW lock_timeout`).Scan(&timeout)
		c.Release()
		if err != nil {
			t.Fatal(err)
		}
		if timeout != "0" {
			t.Errorf("a pool connection has lock_timeout %s, want 0", timeout)
		}
	}
}

// TestMigrationSettingsStayOffThePool checks a session setting a migration
// makes, such as the SET lock_timeout the database standard starts each
// one with, doesn't reach the project's pool. Migration 11 sets one and
// doesn't reset it, so the connection it ran on mustn't be the pool's.
func TestMigrationSettingsStayOffThePool(t *testing.T) {
	t.Parallel()
	pool := testdb.New(t)
	ctx := context.Background()
	if err := migrate.UpTo(ctx, pool, 11); err != nil {
		t.Fatalf("UpTo(11) error = %v", err)
	}
	for _, c := range pool.AcquireAllIdle(ctx) {
		var timeout string
		err := c.QueryRow(ctx, `SHOW lock_timeout`).Scan(&timeout)
		c.Release()
		if err != nil {
			t.Fatal(err)
		}
		if timeout != "0" {
			t.Errorf("a pool connection has lock_timeout %s, want 0", timeout)
		}
	}
}
