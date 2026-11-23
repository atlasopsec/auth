-- API keys, for machines that call a project's API. See docs/api.md §18.
--
-- A key belongs to one user and acts as them, narrowed to its own
-- permissions. Only the SHA-256 of the key is stored; the key itself is
-- shown once, when it's created.
--
-- A new table only: nothing existing changes. Code from before this
-- migration never reads it, and answers a key with 401 like any token that
-- isn't a session's. The table is new and empty, so its index is built
-- here rather than CONCURRENTLY.

-- +goose Up
SET lock_timeout = '5s';

CREATE TABLE auth.api_keys (
    id                    uuid PRIMARY KEY,
    user_id               uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
    name                  text NOT NULL,
    -- SHA-256 of the whole key, prefix included.
    key_hash              bytea NOT NULL,
    -- The first characters of the key's secret part, so a list can tell
    -- keys apart. Too short to help anyone guess the rest.
    hint                  text NOT NULL,
    -- From Config.APIKeyPermissions, never "*". A permission later
    -- removed from there stays here but grants nothing.
    permissions           text[] NOT NULL,
    expires_at            timestamptz NOT NULL,
    last_used_at          timestamptz,
    last_used_ip          inet,
    -- When the owner was told the key expires soon, so they're told once.
    expiry_notice_sent_at timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT api_keys_key_hash_key UNIQUE (key_hash),
    CONSTRAINT api_keys_key_hash_length CHECK (octet_length(key_hash) = 32),
    CONSTRAINT api_keys_name_not_blank CHECK (length(btrim(name)) > 0),
    CONSTRAINT api_keys_name_max_length CHECK (length(name) <= 100),
    CONSTRAINT api_keys_hint_length CHECK (length(hint) = 6),
    CONSTRAINT api_keys_permissions_count CHECK (cardinality(permissions) BETWEEN 1 AND 100),
    CONSTRAINT api_keys_expiry_after_creation CHECK (expires_at > created_at)
);

-- Indexes the foreign key to auth.users, and serves a user's list of keys.
CREATE INDEX idx_api_keys_user ON auth.api_keys (user_id, created_at DESC);

RESET lock_timeout;

-- +goose Down
DROP TABLE auth.api_keys;
