-- Two-factor authentication: each user's TOTP secret, encrypted, and their
-- recovery codes, hashed. See docs/api.md §8 and standards/auth.md §6.

-- +goose Up
CREATE TABLE auth.totp_secrets (
    user_id          uuid PRIMARY KEY REFERENCES auth.users (id) ON DELETE CASCADE,
    -- AES-256-GCM with the user's ID as associated data; see internal/secretbox.
    secret_encrypted bytea NOT NULL,
    -- The last time step a code was accepted for. Codes for it or earlier
    -- steps are refused, so a code can't be used twice.
    last_used_step   bigint NOT NULL DEFAULT 0,
    -- NULL while setup is pending; 2FA is on once it's set.
    confirmed_at     timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE auth.recovery_codes (
    id         uuid PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
    -- SHA-256 of the normalized code; see internal/recoverycode.
    code_hash  bytea NOT NULL,
    used_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT recovery_codes_user_code_key UNIQUE (user_id, code_hash),
    CONSTRAINT recovery_codes_code_hash_length CHECK (octet_length(code_hash) = 32)
);

-- +goose Down
DROP TABLE auth.recovery_codes;
DROP TABLE auth.totp_secrets;
