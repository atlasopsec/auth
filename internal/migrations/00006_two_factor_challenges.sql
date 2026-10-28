-- Logging in with 2FA: the challenge a correct password starts, and the
-- wrong codes counted toward the guessing limit. See docs/api.md §8.

-- +goose Up
CREATE TABLE auth.two_factor_challenges (
    id              uuid PRIMARY KEY,
    user_id         uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
    -- SHA-256 of the challenge token. The token itself is never stored.
    token_hash      bytea NOT NULL,
    -- The client the session will be for, from the login request.
    client          text NOT NULL,
    -- Wrong codes entered for this challenge; it stops working at a limit.
    failed_attempts integer NOT NULL DEFAULT 0,
    expires_at      timestamptz NOT NULL,
    used_at         timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT two_factor_challenges_token_hash_key UNIQUE (token_hash),
    CONSTRAINT two_factor_challenges_token_hash_length CHECK (octet_length(token_hash) = 32),
    CONSTRAINT two_factor_challenges_client_valid CHECK (client IN ('web', 'mobile')),
    CONSTRAINT two_factor_challenges_failed_attempts_not_negative CHECK (failed_attempts >= 0)
);

CREATE INDEX idx_two_factor_challenges_user_id ON auth.two_factor_challenges (user_id);
-- For cleaning up expired challenges.
CREATE INDEX idx_two_factor_challenges_expires_at ON auth.two_factor_challenges (expires_at);

-- One row per wrong code entered while logging in or resetting a password,
-- across all of a user's challenges. Rows older than the limit's window are
-- deleted as new ones are added.
CREATE TABLE auth.two_factor_failures (
    id         uuid PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_two_factor_failures_user_id_created_at ON auth.two_factor_failures (user_id, created_at DESC);

-- +goose Down
DROP TABLE auth.two_factor_failures;
DROP TABLE auth.two_factor_challenges;
