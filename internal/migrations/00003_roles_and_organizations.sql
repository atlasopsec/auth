-- Organizations, their members' roles, and app-wide roles. See docs/api.md
-- §7 and standards/auth.md §7. Roles and permissions are defined in Go;
-- these tables only record who has which role.

-- +goose Up
CREATE TABLE auth.organizations (
    id         uuid PRIMARY KEY,
    name       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT organizations_name_not_blank CHECK (length(btrim(name)) > 0),
    CONSTRAINT organizations_name_max_length CHECK (length(name) <= 200)
);

CREATE TABLE auth.memberships (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES auth.organizations (id) ON DELETE CASCADE,
    user_id         uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
    role            text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT memberships_organization_user_key UNIQUE (organization_id, user_id),
    CONSTRAINT memberships_role_valid CHECK (role ~ '^[a-z][a-z0-9_]*$')
);

-- For listing a user's organizations.
CREATE INDEX idx_memberships_user_id ON auth.memberships (user_id);

-- A user's role across the whole app. At most one per user.
CREATE TABLE auth.user_roles (
    user_id    uuid PRIMARY KEY REFERENCES auth.users (id) ON DELETE CASCADE,
    role       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT user_roles_role_valid CHECK (role ~ '^[a-z][a-z0-9_]*$')
);

-- +goose Down
DROP TABLE auth.user_roles;
DROP TABLE auth.memberships;
DROP TABLE auth.organizations;
