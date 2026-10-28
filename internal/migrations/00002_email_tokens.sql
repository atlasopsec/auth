-- Single-use tokens sent by email: verification, password reset, and email
-- change. See docs/api.md §6 and standards/auth.md §3.

-- +goose Up
CREATE TABLE auth.email_tokens (
    id              uuid PRIMARY KEY,
    user_id         uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
    kind            text NOT NULL,
    -- SHA-256 of the token. The token itself is never stored.
    token_hash      bytea NOT NULL,
    -- The address being switched to. Only for change_email.
    new_email       text,
    -- Wrong passwords entered with this token; it stops working at a limit.
    failed_attempts integer NOT NULL DEFAULT 0,
    expires_at      timestamptz NOT NULL,
    used_at         timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT email_tokens_token_hash_key UNIQUE (token_hash),
    CONSTRAINT email_tokens_token_hash_length CHECK (octet_length(token_hash) = 32),
    CONSTRAINT email_tokens_kind_valid CHECK (kind IN ('verify_email', 'reset_password', 'change_email')),
    CONSTRAINT email_tokens_new_email_only_for_change CHECK ((kind = 'change_email') = (new_email IS NOT NULL)),
    CONSTRAINT email_tokens_new_email_max_length CHECK (length(new_email) <= 254),
    CONSTRAINT email_tokens_failed_attempts_not_negative CHECK (failed_attempts >= 0)
);

-- For the per-user cooldown and for cancelling a user's earlier tokens.
CREATE INDEX idx_email_tokens_user_id_kind ON auth.email_tokens (user_id, kind, created_at DESC);
-- For cleaning up expired tokens.
CREATE INDEX idx_email_tokens_expires_at ON auth.email_tokens (expires_at);

-- +goose Down
DROP TABLE auth.email_tokens;
