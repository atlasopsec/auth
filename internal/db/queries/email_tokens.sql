-- Serializes token creation per user, so concurrent requests can't both
-- pass the cooldown check.
-- name: LockUser :one
SELECT id FROM auth.users WHERE id = @id FOR UPDATE;

-- name: LatestEmailTokenCreatedAt :one
SELECT created_at FROM auth.email_tokens
WHERE user_id = @user_id AND kind = @kind
ORDER BY created_at DESC
LIMIT 1;

-- name: DeleteUnusedEmailTokens :exec
DELETE FROM auth.email_tokens
WHERE user_id = @user_id AND kind = @kind AND used_at IS NULL;

-- name: CreateEmailToken :one
INSERT INTO auth.email_tokens (
    id, user_id, kind, token_hash, new_email, expires_at, created_at, updated_at
) VALUES (
    @id, @user_id, @kind, @token_hash, @new_email, @expires_at, @now, @now
)
RETURNING *;

-- name: GetEmailTokenByHash :one
SELECT * FROM auth.email_tokens WHERE token_hash = @token_hash AND kind = @kind;

-- name: RecordEmailTokenFailure :exec
UPDATE auth.email_tokens
SET failed_attempts = failed_attempts + 1, updated_at = @now
WHERE id = @id;

-- Marks a token used, only if it's still usable. Checking again here, not
-- just at lookup, means two requests racing with the same token can't
-- both use it.
-- name: UseEmailToken :execrows
UPDATE auth.email_tokens
SET used_at = @now, updated_at = @now
WHERE id = @id
  AND used_at IS NULL
  AND expires_at > @now
  AND failed_attempts < @max_failed_attempts;

-- name: DeleteSpentEmailTokens :execrows
DELETE FROM auth.email_tokens WHERE expires_at <= @now OR used_at IS NOT NULL;

-- name: DeleteUnusedUserEmailTokens :exec
DELETE FROM auth.email_tokens WHERE user_id = @user_id AND used_at IS NULL;
