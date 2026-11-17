-- Indexes the foreign key from auth.memberships to auth.organization_roles
-- (standards/database.md: every foreign key has an index), so deleting a
-- role doesn't read every membership. Built CONCURRENTLY, as in 00012, and
-- dropped first so a failed build is redone. Only memberships with a
-- custom role are indexed: the rest never match.

-- +goose NO TRANSACTION

-- +goose Up
SET lock_timeout = '5s';

DROP INDEX CONCURRENTLY IF EXISTS auth.idx_memberships_custom_role;
CREATE INDEX CONCURRENTLY idx_memberships_custom_role ON auth.memberships (organization_id, custom_role_id)
    WHERE custom_role_id IS NOT NULL;

RESET lock_timeout;

-- +goose Down
DROP INDEX CONCURRENTLY IF EXISTS auth.idx_memberships_custom_role;
