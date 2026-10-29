-- name: GetLoginWaits :many
SELECT next_allowed_at FROM auth.login_failures WHERE key = ANY (@keys::text[]);

-- Counts one more failure, starting over if the last was before
-- @reset_before, and returns the count.
-- name: RecordLoginFailure :one
INSERT INTO auth.login_failures (id, key, failures, last_failed_at, next_allowed_at, created_at, updated_at)
VALUES (@id, @key, 1, @now, @now, @now, @now)
ON CONFLICT (key) DO UPDATE
SET failures = CASE WHEN auth.login_failures.last_failed_at <= @reset_before THEN 1 ELSE auth.login_failures.failures + 1 END,
    last_failed_at = excluded.last_failed_at,
    updated_at = excluded.updated_at
RETURNING failures;

-- name: SetLoginNextAllowed :exec
UPDATE auth.login_failures SET next_allowed_at = @next_allowed_at, updated_at = @now WHERE key = @key;

-- name: DeleteLoginFailures :exec
DELETE FROM auth.login_failures WHERE key = @key;

-- name: DeleteOldLoginFailures :execrows
DELETE FROM auth.login_failures WHERE last_failed_at <= @reset_before AND next_allowed_at <= @now;
