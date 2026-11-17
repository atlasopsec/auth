-- Roles an organization defines itself, from the permissions the project
-- declares in Go. See docs/api.md §15.
--
-- A member with one has the role "custom:<role id>" in auth.memberships,
-- and the role's ID in custom_role_id. Role names in code can't contain a
-- colon, so the two kinds never clash, and code from before this
-- migration reads such a role as one that's no longer defined, which
-- grants nothing. The foreign key on (organization_id, custom_role_id)
-- means a member can only have a role of their own organization, and a
-- role can't be deleted while anyone has it.
--
-- Only new rows and a new nullable column: nothing existing changes, and
-- the constraints are added NOT VALID, then validated, so the table isn't
-- locked while existing rows are checked.

-- +goose Up
SET lock_timeout = '5s';

CREATE TABLE auth.organization_roles (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES auth.organizations (id) ON DELETE CASCADE,
    name            text NOT NULL,
    -- Permissions from Config.OrgRoles, never "*". A permission later
    -- removed from code stays here but grants nothing.
    permissions     text[] NOT NULL DEFAULT '{}',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    -- For the foreign key from auth.memberships. Its leading column also
    -- indexes the foreign key to auth.organizations.
    CONSTRAINT organization_roles_organization_id_id_key UNIQUE (organization_id, id),
    CONSTRAINT organization_roles_name_not_blank CHECK (length(btrim(name)) > 0),
    CONSTRAINT organization_roles_name_max_length CHECK (length(name) <= 100),
    CONSTRAINT organization_roles_permissions_max CHECK (cardinality(permissions) <= 100)
);

-- Names are unique in an organization regardless of case.
CREATE UNIQUE INDEX idx_organization_roles_name ON auth.organization_roles (organization_id, lower(name));

ALTER TABLE auth.memberships ADD COLUMN custom_role_id uuid;

ALTER TABLE auth.memberships DROP CONSTRAINT memberships_role_valid;
ALTER TABLE auth.memberships ADD CONSTRAINT memberships_role_valid CHECK (
    (custom_role_id IS NULL AND role ~ '^[a-z][a-z0-9_]*$')
    OR (custom_role_id IS NOT NULL AND role = 'custom:' || custom_role_id::text)
) NOT VALID;
ALTER TABLE auth.memberships VALIDATE CONSTRAINT memberships_role_valid;

-- NO ACTION rather than RESTRICT: it's checked at the end of the
-- statement, so deleting an organization, which cascades to both tables,
-- still works.
ALTER TABLE auth.memberships ADD CONSTRAINT memberships_custom_role_fkey
    FOREIGN KEY (organization_id, custom_role_id)
    REFERENCES auth.organization_roles (organization_id, id) NOT VALID;
ALTER TABLE auth.memberships VALIDATE CONSTRAINT memberships_custom_role_fkey;

RESET lock_timeout;

-- +goose Down
ALTER TABLE auth.memberships DROP CONSTRAINT memberships_custom_role_fkey;
DELETE FROM auth.memberships WHERE custom_role_id IS NOT NULL;
ALTER TABLE auth.memberships DROP CONSTRAINT memberships_role_valid;
ALTER TABLE auth.memberships DROP COLUMN custom_role_id;
ALTER TABLE auth.memberships ADD CONSTRAINT memberships_role_valid CHECK (role ~ '^[a-z][a-z0-9_]*$');
DROP TABLE auth.organization_roles;
