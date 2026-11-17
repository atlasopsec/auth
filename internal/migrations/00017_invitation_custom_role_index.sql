-- Indexes the foreign key from auth.invitations to auth.organization_roles,
-- as 00015 does for memberships, so deleting a role doesn't read every
-- invitation. Built CONCURRENTLY, and dropped first so a failed build is
-- redone.

-- +goose NO TRANSACTION

-- +goose Up
SET lock_timeout = '5s';

DROP INDEX CONCURRENTLY IF EXISTS auth.idx_invitations_custom_role;
CREATE INDEX CONCURRENTLY idx_invitations_custom_role ON auth.invitations (organization_id, custom_role_id)
    WHERE custom_role_id IS NOT NULL;

RESET lock_timeout;

-- +goose Down
DROP INDEX CONCURRENTLY IF EXISTS auth.idx_invitations_custom_role;
