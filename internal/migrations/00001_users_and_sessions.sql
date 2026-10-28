-- Users and sessions. See docs/design.md §4 and standards/auth.md §4.
-- IDs are UUIDv7, generated in Go, so no Postgres-version-specific defaults.

-- +goose Up
CREATE TABLE auth.users (
    id                  uuid PRIMARY KEY,
    email               text NOT NULL,
    email_verified_at   timestamptz,
    -- NULL for users who only sign in with OAuth.
    password_hash       text,
    two_factor_required boolean NOT NULL DEFAULT false,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT users_email_not_blank CHECK (length(btrim(email)) > 0),
    CONSTRAINT users_email_max_length CHECK (length(email) <= 254)
);

-- Emails are unique regardless of case.
CREATE UNIQUE INDEX idx_users_email ON auth.users (lower(email));

CREATE TABLE auth.sessions (
    id                  uuid PRIMARY KEY,
    user_id             uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
    -- SHA-256 of the session token. The token itself is never stored.
    token_hash          bytea NOT NULL,
    client              text NOT NULL,
    ip                  inet,
    user_agent          text,
    last_used_at        timestamptz NOT NULL DEFAULT now(),
    -- Idle expiry, pushed forward as the session is used.
    expires_at          timestamptz NOT NULL,
    -- Hard limit, never extended.
    absolute_expires_at timestamptz NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT sessions_token_hash_key UNIQUE (token_hash),
    CONSTRAINT sessions_token_hash_length CHECK (octet_length(token_hash) = 32),
    CONSTRAINT sessions_client_valid CHECK (client IN ('web', 'mobile')),
    CONSTRAINT sessions_user_agent_max_length CHECK (length(user_agent) <= 512),
    CONSTRAINT sessions_expiry_order CHECK (expires_at <= absolute_expires_at)
);

CREATE INDEX idx_sessions_user_id ON auth.sessions (user_id);
-- For cleaning up expired sessions.
CREATE INDEX idx_sessions_absolute_expires_at ON auth.sessions (absolute_expires_at);

-- +goose Down
DROP TABLE auth.sessions;
DROP TABLE auth.users;
