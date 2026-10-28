// Package testdb gives tests a fresh, empty Postgres database.
//
// If AUTH_TEST_DATABASE_URL is set (a connection URL for a user allowed to
// create databases), it's used directly. Otherwise a Postgres container is
// started with testcontainers, which needs Docker.
//
// Every call to New creates a separate database, dropped when the test ends,
// so tests can run in parallel without seeing each other's data.
package testdb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/atlasopsec/auth/internal/migrate"
)

// image is the Postgres version used in tests when no database URL is given.
const image = "postgres:17-alpine"

// server is shared by every test in a package run. Starting a container is
// slow, so it's done once and each test gets its own database inside it.
var server struct {
	once sync.Once
	url  string
	err  error
}

// New returns a pool connected to a new, empty database.
func New(t testing.TB) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()

	adminURL := adminURL(t)

	b := make([]byte, 8)
	_, _ = rand.Read(b)
	name := "test_" + hex.EncodeToString(b)

	admin, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		t.Fatalf("testdb: connecting: %v", err)
	}
	defer func() {
		if err := admin.Close(ctx); err != nil {
			t.Errorf("testdb: closing admin connection: %v", err)
		}
	}()

	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("testdb: creating database: %v", err)
	}

	dbURL, err := withDatabase(adminURL, name)
	if err != nil {
		t.Fatalf("testdb: %v", err)
	}
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Fatalf("testdb: connecting to %s: %v", name, err)
	}

	t.Cleanup(func() {
		pool.Close()
		conn, err := pgx.Connect(context.Background(), adminURL)
		if err != nil {
			t.Errorf("testdb: cleanup: connecting: %v", err)
			return
		}
		defer func() {
			if err := conn.Close(context.Background()); err != nil {
				t.Errorf("testdb: cleanup: closing connection: %v", err)
			}
		}()
		if _, err := conn.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
			t.Errorf("testdb: cleanup: dropping %s: %v", name, err)
		}
	})
	return pool
}

func adminURL(t testing.TB) string {
	t.Helper()
	if u := os.Getenv("AUTH_TEST_DATABASE_URL"); u != "" {
		return u
	}
	server.once.Do(func() {
		ctx := context.Background()
		// The container lives for the whole test run and is removed by
		// testcontainers' cleanup container (Ryuk) when the run ends.
		c, err := postgres.Run(ctx, image,
			postgres.WithDatabase("postgres"),
			postgres.WithUsername("postgres"),
			postgres.WithPassword("postgres"),
			postgres.BasicWaitStrategies(),
		)
		if err != nil {
			server.err = fmt.Errorf("starting postgres container (is Docker running? or set AUTH_TEST_DATABASE_URL): %w", err)
			return
		}
		server.url, server.err = c.ConnectionString(ctx, "sslmode=disable")
	})
	if server.err != nil {
		t.Fatalf("testdb: %v", server.err)
	}
	return server.url
}

// withDatabase returns url with its database name replaced.
func withDatabase(raw, name string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parsing database URL: %w", err)
	}
	u.Path = "/" + name
	return u.String(), nil
}

// NewMigrated returns a pool connected to a new database with the module's
// migrations applied.
func NewMigrated(t testing.TB) *pgxpool.Pool {
	t.Helper()
	pool := New(t)
	if err := migrate.Run(context.Background(), pool); err != nil {
		t.Fatalf("testdb: migrating: %v", err)
	}
	return pool
}
