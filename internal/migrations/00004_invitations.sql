-- Invitations to join an organization, accepted by a logged-in user whose
-- verified email matches. See docs/api.md §7.

-- +goose Up
CREATE TABLE auth.invitations (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES auth.organizations (id) ON DELETE CASCADE,
    email           text NOT NULL,
    role            text NOT NULL,
    -- SHA-256 of the token in the invitation link. The token itself is never stored.
    token_hash      bytea NOT NULL,
    invited_by      uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
    expires_at      timestamptz NOT NULL,
    accepted_at     timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT invitations_token_hash_key UNIQUE (token_hash),
    CONSTRAINT invitations_token_hash_length CHECK (octet_length(token_hash) = 32),
    CONSTRAINT invitations_email_not_blank CHECK (length(btrim(email)) > 0),
    CONSTRAINT invitations_email_max_length CHECK (length(email) <= 254),
    CONSTRAINT invitations_role_valid CHECK (role ~ '^[a-z][a-z0-9_]*$')
);

-- At most one pending invitation per organization and address; inviting
-- again replaces it.
CREATE UNIQUE INDEX idx_invitations_pending ON auth.invitations (organization_id, lower(email))
    WHERE accepted_at IS NULL;
CREATE INDEX idx_invitations_invited_by ON auth.invitations (invited_by);

-- +goose Down
DROP TABLE auth.invitations;
