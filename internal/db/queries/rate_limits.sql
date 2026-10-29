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
