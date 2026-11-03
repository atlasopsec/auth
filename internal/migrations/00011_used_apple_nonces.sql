-- The nonces of Apple identity tokens that have signed someone in, kept
-- until the token expires, so a captured token and nonce can't be sent
-- again. See docs/api.md §9.

-- +goose Up
SET lock_timeout = '5s';

CREATE TABLE auth.used_apple_nonces (
    id         uuid PRIMARY KEY,
    -- SHA-256 of the nonce the app sent. The nonce itself is never stored.
    nonce_hash bytea NOT NULL,
    -- When the token that used it expires. After that the token is refused
    -- anyway, so the row is only kept until then.
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT used_apple_nonces_nonce_hash_key UNIQUE (nonce_hash),
    CONSTRAINT used_apple_nonces_nonce_hash_length CHECK (octet_length(nonce_hash) = 32)
);

-- For clearing out expired nonces.
CREATE INDEX idx_used_apple_nonces_expires_at ON auth.used_apple_nonces (expires_at);

-- +goose Down
DROP TABLE auth.used_apple_nonces;
