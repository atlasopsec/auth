-- name: CreateAPIKey :one
INSERT INTO auth.api_keys (
    id, user_id, name, key_hash, hint, permissions, expires_at, created_at, updated_at
) VALUES (
    @id, @user_id, @name, @key_hash, @hint, @permissions, @expires_at, @now, @now
)
RETURNING *;

-- name: GetAPIKeyByHash :one
SELECT * FROM auth.api_keys WHERE key_hash = @key_hash;

-- name: CountActiveUserAPIKeys :one
SELECT count(*) FROM auth.api_keys WHERE user_id = @user_id AND expires_at > @now;

-- name: ListUserAPIKeys :many
SELECT * FROM auth.api_keys
WHERE user_id = @user_id
ORDER BY created_at DESC, id DESC
LIMIT @max_rows;

-- Records a use, at most once per interval: the condition skips the write
-- when the key was used since @used_before.
-- name: TouchAPIKey :exec
UPDATE auth.api_keys
SET last_used_at = @now, last_used_ip = @ip, updated_at = @now
WHERE id = @id AND (last_used_at IS NULL OR last_used_at <= @used_before);

-- name: DeleteAPIKey :one
DELETE FROM auth.api_keys WHERE id = @id AND user_id = @user_id
RETURNING id, name;

-- name: DeleteUserAPIKeys :many
DELETE FROM auth.api_keys WHERE user_id = @user_id
RETURNING id, name;

-- name: DeleteExpiredAPIKeys :execrows
DELETE FROM auth.api_keys WHERE expires_at <= @now;
