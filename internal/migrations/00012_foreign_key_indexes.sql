-- Indexes for the foreign keys that had none, so deleting a user or an
-- organization doesn't read the whole table to find the rows that point at
-- it (standards/database.md: every foreign key has an index). The existing
-- index on invitations.organization_id covers pending invitations only, so
-- a delete can't use it.
--
-- auth_events can be large, so the indexes are built CONCURRENTLY, which
-- can't run in a transaction. Two things follow from that:
--
-- - Migrate runs on the project's own pool, and goose runs this file on one
--   connection that goes back to that pool afterwards, so lock_timeout is
--   reset at the end rather than left on the app's connection. (If a
--   statement fails, Migrate returns the error and the app doesn't start.)
-- - A concurrent build that fails leaves an invalid index behind, and goose
--   records the migration only once every statement has succeeded. Dropping
--   each index first means running it again builds it properly, rather
--   than keeping the broken one.

-- +goose NO TRANSACTION

-- +goose Up
SET lock_timeout = '5s';

DROP INDEX CONCURRENTLY IF EXISTS auth.idx_auth_events_actor_id;
CREATE INDEX CONCURRENTLY idx_auth_events_actor_id ON auth.auth_events (actor_id);

DROP INDEX CONCURRENTLY IF EXISTS auth.idx_invitations_organization_id;
CREATE INDEX CONCURRENTLY idx_invitations_organization_id ON auth.invitations (organization_id);

DROP INDEX CONCURRENTLY IF EXISTS auth.idx_oauth_flows_user_id;
CREATE INDEX CONCURRENTLY idx_oauth_flows_user_id ON auth.oauth_flows (user_id);

RESET lock_timeout;

-- +goose Down
DROP INDEX CONCURRENTLY IF EXISTS auth.idx_oauth_flows_user_id;
DROP INDEX CONCURRENTLY IF EXISTS auth.idx_invitations_organization_id;
DROP INDEX CONCURRENTLY IF EXISTS auth.idx_auth_events_actor_id;
