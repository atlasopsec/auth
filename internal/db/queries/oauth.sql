-- name: DeleteSpentOAuthFlows :execrows
DELETE FROM auth.oauth_flows WHERE used_at IS NOT NULL OR expires_at <= @now;

-- name: CreateOAuthFlow :exec
INSERT INTO auth.oauth_flows (
    id, state_hash, provider, purpose, user_id, client, client_challenge,
    pkce_verifier_encrypted, nonce, expires_at, created_at, updated_at
) VALUES (
    @id, @state_hash, @provider, @purpose, @user_id, @client, @client_challenge,
    @pkce_verifier_encrypted, @nonce, @expires_at, @now, @now
);

-- Locks the flow, so two requests can't both finish it.
-- name: GetOAuthFlowForUpdate :one
SELECT * FROM auth.oauth_flows WHERE state_hash = @state_hash FOR UPDATE;

-- name: UseOAuthFlow :exec
UPDATE auth.oauth_flows SET used_at = @now, updated_at = @now WHERE id = @id;

-- name: GetOAuthAccount :one
SELECT * FROM auth.oauth_accounts WHERE provider = @provider AND provider_user_id = @provider_user_id;

-- name: CreateOAuthAccount :exec
INSERT INTO auth.oauth_accounts (id, user_id, provider, provider_user_id, email, created_at, updated_at)
VALUES (@id, @user_id, @provider, @provider_user_id, @email, @now, @now);

-- Locks the user, so a concurrent sign-in or sign-up with the same email
-- waits.
-- name: GetUserByEmailForUpdate :one
SELECT * FROM auth.users WHERE lower(email) = lower(@email) FOR UPDATE;

-- name: ClearPassword :exec
UPDATE auth.users SET password_hash = NULL, updated_at = @now WHERE id = @id;

-- name: ListOAuthAccounts :many
SELECT * FROM auth.oauth_accounts WHERE user_id = @user_id ORDER BY created_at, id;

-- name: UserHasOAuthProvider :one
SELECT EXISTS (SELECT 1 FROM auth.oauth_accounts WHERE user_id = @user_id AND provider = @provider);

-- name: DeleteOAuthAccount :one
DELETE FROM auth.oauth_accounts WHERE id = @id AND user_id = @user_id RETURNING provider;

-- name: CountOAuthAccounts :one
SELECT count(*) FROM auth.oauth_accounts WHERE user_id = @user_id;
