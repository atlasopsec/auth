// Package migrate applies the module's embedded migrations. It's separate
// from the root package so internal packages and their tests can migrate a
// database without importing the root package (which would be a cycle).
package migrate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"github.com/atlasopsec/auth/internal/migrations"
)

// Schema is the Postgres schema that holds every table the module owns.
const Schema = "auth"

// versionTable is goose's bookkeeping table. It lives in the auth schema so
// it never clashes with the project's own goose_db_version table.
const versionTable = Schema + ".goose_db_version"

// migrateLockID is the Postgres advisory lock held while migrating, so
// several API instances starting at once apply migrations one at a time.
// It's distinct from goose's default lock ID, so the module's migrations
// and the project's own never block each other.
const migrateLockID int64 = 0x617574686d6967 // "authmig"

// Run creates the auth schema if needed and applies any pending migrations.
// It's idempotent and safe to call from several instances at once.
func Run(ctx context.Context, pool *pgxpool.Pool) error {
	return run(ctx, pool, func(p *goose.Provider) error {
		_, err := p.Up(ctx)
		return err
	})
}

// UpTo is Run, but applies migrations only up to version. It's for tests
// that need the database as an earlier version left it.
func UpTo(ctx context.Context, pool *pgxpool.Pool, version int64) error {
	return run(ctx, pool, func(p *goose.Provider) error {
		_, err := p.UpTo(ctx, version)
		return err
	})
}

func run(ctx context.Context, pool *pgxpool.Pool, up func(*goose.Provider) error) (err error) {
	if err := createSchema(ctx, pool); err != nil {
		return err
	}

	// Migrations get connections of their own, made from the pool's
	// settings, rather than ones borrowed from the pool. A session setting
	// a migration makes, such as the SET lock_timeout the database
	// standard starts each with, outlasts its transaction, and would
	// otherwise go back to the pool with the connection and apply to the
	// project's own queries. These are closed when Run returns; the
	// caller's pool is left as it was.
	db := stdlib.OpenDB(*pool.Config().ConnConfig.Copy())
	defer func() {
		if cerr := db.Close(); cerr != nil {
			err = errors.Join(err, fmt.Errorf("auth: closing migration connection: %w", cerr))
		}
	}()

	locker, err := lock.NewPostgresSessionLocker(lock.WithLockID(migrateLockID))
	if err != nil {
		return fmt.Errorf("auth: creating migration lock: %w", err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS,
		goose.WithTableName(versionTable),
		goose.WithSessionLocker(locker),
		// Only this module's embedded migrations, never ones registered
		// globally by the project.
		goose.WithDisableGlobalRegistry(true),
		// A library shouldn't print. Failures are returned as errors.
		goose.WithSlog(slog.New(slog.DiscardHandler)),
	)
	if err != nil {
		return fmt.Errorf("auth: loading migrations: %w", err)
	}
	defer func() {
		if cerr := provider.Close(); cerr != nil {
			err = errors.Join(err, fmt.Errorf("auth: closing migration provider: %w", cerr))
		}
	}()

	if err := up(provider); err != nil {
		return fmt.Errorf("auth: applying migrations: %w", err)
	}
	return nil
}

// createSchema creates the auth schema. CREATE SCHEMA IF NOT EXISTS isn't
// safe when run concurrently (two callers can both try to create it), so
// it's done under a transaction-level advisory lock.
func createSchema(ctx context.Context, pool *pgxpool.Pool) error {
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", migrateLockID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS "+Schema)
		return err
	})
	if err != nil {
		return fmt.Errorf("auth: creating schema: %w", err)
	}
	return nil
}
