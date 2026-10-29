-- Sign in with Google, GitHub, and Apple: each user's linked provider
-- accounts, and the short-lived state of a sign-in in progress. See
-- docs/api.md §9 and standards/auth.md §5.

-- +goose Up
CREATE TABLE auth.oauth_accounts (
    id               uuid PRIMARY KEY,
    user_id          uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
    provider         text NOT NULL,
    -- The provider's ID for the user. Users are matched by this, never by
    -- email.
    provider_user_id text NOT NULL,
    -- The provider's address when the account was linked, for display only.
    email            text NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT oauth_accounts_provider_user_key UNIQUE (provider, provider_user_id),
    CONSTRAINT oauth_accounts_user_provider_key UNIQUE (user_id, provider),
    CONSTRAINT oauth_accounts_provider_valid CHECK (provider IN ('google', 'github', 'apple')),
    CONSTRAINT oauth_accounts_provider_user_id_max_length CHECK (length(provider_user_id) <= 255),
    CONSTRAINT oauth_accounts_email_max_length CHECK (length(email) <= 254)
);

CREATE TABLE auth.oauth_flows (
    id                      uuid PRIMARY KEY,
    -- SHA-256 of the state sent to the provider. The state itself is never
    -- stored.
    state_hash              bytea NOT NULL,
    provider                text NOT NULL,
    purpose                 text NOT NULL,
    -- The user linking a provider, for link flows only.
    user_id                 uuid REFERENCES auth.users (id) ON DELETE CASCADE,
    client                  text NOT NULL,
    -- SHA-256 of the client verifier held by the device that started the
    -- flow; finishing it takes the verifier.
    client_challenge        bytea NOT NULL,
    -- The PKCE verifier, encrypted with Config.EncryptionKey.
    pkce_verifier_encrypted bytea NOT NULL,
    -- Checked against the ID token, for providers that return one.
    nonce                   text NOT NULL,
    expires_at              timestamptz NOT NULL,
    used_at                 timestamptz,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT oauth_flows_state_hash_key UNIQUE (state_hash),
    CONSTRAINT oauth_flows_state_hash_length CHECK (octet_length(state_hash) = 32),
    CONSTRAINT oauth_flows_client_challenge_length CHECK (octet_length(client_challenge) = 32),
    CONSTRAINT oauth_flows_provider_valid CHECK (provider IN ('google', 'github', 'apple')),
    CONSTRAINT oauth_flows_purpose_valid CHECK (purpose IN ('login', 'link')),
    CONSTRAINT oauth_flows_user_only_for_link CHECK ((purpose = 'link') = (user_id IS NOT NULL)),
    CONSTRAINT oauth_flows_client_valid CHECK (client IN ('web', 'mobile'))
);

-- For clearing out expired flows.
CREATE INDEX idx_oauth_flows_expires_at ON auth.oauth_flows (expires_at);

-- +goose Down
DROP TABLE auth.oauth_flows;
DROP TABLE auth.oauth_accounts;
