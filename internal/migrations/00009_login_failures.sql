-- Failed logins, for the growing delays that slow down password guessing
-- without locking anyone out. See docs/api.md §10 and standards/auth.md §9.

-- +goose Up
CREATE TABLE auth.login_failures (
    id              uuid PRIMARY KEY,
    -- "account:<email hash>" or "account-ip:<email hash>:<ip>". Email
    -- addresses appear only as SHA-256 hashes, and the account need not
    -- exist, so the delays don't reveal which do.
    key             text NOT NULL,
    failures        integer NOT NULL,
    last_failed_at  timestamptz NOT NULL,
    -- No attempt is checked before this.
    next_allowed_at timestamptz NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT login_failures_key_key UNIQUE (key),
    CONSTRAINT login_failures_key_max_length CHECK (length(key) <= 200),
    CONSTRAINT login_failures_failures_positive CHECK (failures > 0)
);

-- For clearing out old rows.
CREATE INDEX idx_login_failures_last_failed_at ON auth.login_failures (last_failed_at);

-- +goose Down
DROP TABLE auth.login_failures;
