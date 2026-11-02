-- Counts one more hit in the window, atomically, and returns the total.
-- name: HitRateLimit :one
INSERT INTO auth.rate_limits (id, key, window_start, expires_at, count, created_at, updated_at)
VALUES (@id, @key, @window_start, @expires_at, 1, @now, @now)
ON CONFLICT (key, window_start) DO UPDATE
SET count = auth.rate_limits.count + 1, updated_at = excluded.updated_at
RETURNING count;

-- name: GetRateLimitCount :one
SELECT count FROM auth.rate_limits WHERE key = @key AND window_start = @window_start;

-- name: DeleteEndedRateLimits :execrows
DELETE FROM auth.rate_limits WHERE expires_at <= @now;

-- Takes back one hit. A window's row only exists with a count of at least
-- one, so the last hit is taken back by deleting it.
-- name: UndoRateLimitHit :exec
WITH deleted AS (
    DELETE FROM auth.rate_limits d
    WHERE d.key = @key AND d.window_start = @window_start AND d.count = 1
)
UPDATE auth.rate_limits u
SET count = u.count - 1, updated_at = @now
WHERE u.key = @key AND u.window_start = @window_start AND u.count > 1;
