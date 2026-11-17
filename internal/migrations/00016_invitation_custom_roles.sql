-- Invitations with a role the organization defined (docs/api.md §15), the
-- same way auth.memberships has them (00014): role "custom:<role id>" and
-- the role's ID in custom_role_id, kept in step by a check constraint.
--
-- The foreign key on (organization_id, custom_role_id) means an invitation
-- can only be for a role of its own organization. Deleting the role
-- deletes its invitations: a pending one is cancelled, rather than
-- stopping the role being deleted, and accepted or expired ones are
-- deleted by cleanup anyway.
--
-- Only a new nullable column: nothing existing changes. Code from before
-- this migration refuses a custom role's invitation when it's accepted,
-- as a role it doesn't know.

-- +goose Up
SET lock_timeout = '5s';

ALTER TABLE auth.invitations ADD COLUMN custom_role_id uuid;

ALTER TABLE auth.invitations DROP CONSTRAINT invitations_role_valid;
ALTER TABLE auth.invitations ADD CONSTRAINT invitations_role_valid CHECK (
    (custom_role_id IS NULL AND role ~ '^[a-z][a-z0-9_]*$')
    OR (custom_role_id IS NOT NULL AND role = 'custom:' || custom_role_id::text)
) NOT VALID;
ALTER TABLE auth.invitations VALIDATE CONSTRAINT invitations_role_valid;

ALTER TABLE auth.invitations ADD CONSTRAINT invitations_custom_role_fkey
    FOREIGN KEY (organization_id, custom_role_id)
    REFERENCES auth.organization_roles (organization_id, id) ON DELETE CASCADE NOT VALID;
ALTER TABLE auth.invitations VALIDATE CONSTRAINT invitations_custom_role_fkey;

RESET lock_timeout;

-- +goose Down
ALTER TABLE auth.invitations DROP CONSTRAINT invitations_custom_role_fkey;
DELETE FROM auth.invitations WHERE custom_role_id IS NOT NULL;
ALTER TABLE auth.invitations DROP CONSTRAINT invitations_role_valid;
ALTER TABLE auth.invitations DROP COLUMN custom_role_id;
ALTER TABLE auth.invitations ADD CONSTRAINT invitations_role_valid CHECK (role ~ '^[a-z][a-z0-9_]*$');
