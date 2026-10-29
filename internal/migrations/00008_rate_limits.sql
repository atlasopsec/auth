-- Rate limiting: one counter per limit key and fixed time window. See
-- docs/api.md §10 and standards/auth.md §9.

-- +goose Up
CREATE TABLE auth.rate_limits (
    id           uuid PRIMARY KEY,
    -- What's limited and for whom, e.g. "login:ip:203.0.113.7". Email
    -- addresses appear only as SHA-256 hashes.
    key          text NOT NULL,
    window_start timestamptz NOT NULL,
    -- When the window ends; the row is deleted after that.
    expires_at   timestamptz NOT NULL,
    count        integer NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT rate_limits_key_window_key UNIQUE (key, window_start),
    CONSTRAINT rate_limits_key_max_length CHECK (length(key) <= 200),
    CONSTRAINT rate_limits_count_positive CHECK (count > 0)
);

-- For clearing out ended windows.
CREATE INDEX idx_rate_limits_expires_at ON auth.rate_limits (expires_at);

-- +goose Down
DROP TABLE auth.rate_limits;
