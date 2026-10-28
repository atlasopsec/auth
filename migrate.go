package auth

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/atlasopsec/auth/internal/migrate"
)

// Schema is the Postgres schema that holds every table the module owns.
const Schema = migrate.Schema

// Migrate creates the auth schema if needed and applies any pending
// migrations for the module's tables. Call it before the project's own
// migrations, usually in the pre-deploy step. It's safe to call on every
// start and from several instances at once.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	return migrate.Run(ctx, pool)
}
