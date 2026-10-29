-- The security event log: logins, logouts, and changes to passwords, 2FA,
-- linked providers, email, and roles. See docs/api.md §10 and
-- standards/auth.md §10. It holds IDs only: never passwords, tokens, codes,
-- or email addresses.

-- +goose Up
CREATE TABLE auth.auth_events (
    id         uuid PRIMARY KEY,
    -- Who it happened to. NULL for failed logins with an unknown email, and
    -- once the user is deleted.
    user_id    uuid REFERENCES auth.users (id) ON DELETE SET NULL,
    -- Who did it, when that's someone else, such as an admin changing a
    -- role.
    actor_id   uuid REFERENCES auth.users (id) ON DELETE SET NULL,
    event      text NOT NULL,
    ip         inet,
    user_agent text,
    metadata   jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT auth_events_event_valid CHECK (event ~ '^[a-z][a-z0-9_]*$'),
    CONSTRAINT auth_events_user_agent_max_length CHECK (length(user_agent) <= 512)
);

CREATE INDEX idx_auth_events_user_id_created_at ON auth.auth_events (user_id, created_at);
-- For deleting events older than a year.
CREATE INDEX idx_auth_events_created_at ON auth.auth_events (created_at);

-- +goose Down
DROP TABLE auth.auth_events;
