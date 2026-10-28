-- name: CreateSession :one
INSERT INTO auth.sessions (
    id, user_id, token_hash, client, ip, user_agent,
    last_used_at, expires_at, absolute_expires_at, created_at, updated_at
) VALUES (
    @id, @user_id, @token_hash, @client, @ip, @user_agent,
    @now, @expires_at, @absolute_expires_at, @now, @now
)
RETURNING *;

-- name: GetSessionByTokenHash :one
SELECT * FROM auth.sessions WHERE token_hash = @token_hash;

-- name: ExtendSession :exec
UPDATE auth.sessions
SET last_used_at = @now, expires_at = @expires_at, updated_at = @now
WHERE id = @id;

-- name: ListActiveSessions :many
SELECT * FROM auth.sessions
WHERE user_id = @user_id AND expires_at > @now AND absolute_expires_at > @now
ORDER BY last_used_at DESC, id DESC;

-- name: DeleteSession :execrows
DELETE FROM auth.sessions WHERE id = @id AND user_id = @user_id;

-- name: DeleteUserSessions :execrows
DELETE FROM auth.sessions WHERE user_id = @user_id;

-- name: DeleteUserSessionsExcept :execrows
DELETE FROM auth.sessions WHERE user_id = @user_id AND id <> @keep_id;

-- name: DeleteExpiredSessions :execrows
DELETE FROM auth.sessions WHERE expires_at <= @now OR absolute_expires_at <= @now;
