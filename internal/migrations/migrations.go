// Package migrations holds the module's SQL migrations, embedded into the
// binary. They're applied by auth.Migrate.
package migrations

import "embed"

// FS contains the goose migration files. Every table they create lives in
// the auth schema, never in public.
//
//go:embed *.sql
var FS embed.FS
