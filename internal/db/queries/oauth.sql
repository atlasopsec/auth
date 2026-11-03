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

-- name: DeleteUserOAuthAccounts :exec
DELETE FROM auth.oauth_accounts WHERE user_id = @user_id;

-- Records that an Apple identity token with this nonce signed someone in.
-- It affects no rows if a token that hasn't expired already used the
-- nonce: that's a replay. An expired one's row is reused, since its token
-- is refused anyway. The row has to have expired before @now, which is
-- taken before the token's expiry was checked, so the same token can't
-- slip through at the moment it expires.
-- name: UseAppleNonce :execrows
INSERT INTO auth.used_apple_nonces AS u (id, nonce_hash, expires_at, created_at, updated_at)
VALUES (@id, @nonce_hash, @expires_at, @now, @now)
ON CONFLICT (nonce_hash) DO UPDATE
    SET id = EXCLUDED.id, expires_at = EXCLUDED.expires_at, updated_at = EXCLUDED.updated_at
    WHERE u.expires_at < @now;

-- name: DeleteExpiredAppleNonces :execrows
DELETE FROM auth.used_apple_nonces WHERE expires_at < @now;
