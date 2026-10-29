-- name: CreateAuthEvent :exec
INSERT INTO auth.auth_events (id, user_id, actor_id, event, ip, user_agent, metadata, created_at, updated_at)
VALUES (@id, @user_id, @actor_id, @event, @ip, @user_agent, @metadata, @now, @now);

-- A page of a user's events, newest first. IDs are UUIDv7, so they sort by
-- time; @before is the last ID of the previous page.
-- name: ListAuthEvents :many
SELECT * FROM auth.auth_events
WHERE user_id = @user_id AND (sqlc.narg('before')::uuid IS NULL OR id < sqlc.narg('before')::uuid)
ORDER BY id DESC
LIMIT @page_size;

-- name: DeleteAuthEventsBefore :execrows
DELETE FROM auth.auth_events WHERE created_at <= @before;

-- Whether a user has logged in before at all, and whether they have since
-- @since from this user agent and network (@ip masked to @bits).
-- name: GetLoginHistory :one
SELECT
    EXISTS (
        SELECT 1 FROM auth.auth_events e
        WHERE e.user_id = @user_id AND e.event = 'login_succeeded'
    ) AS any_login,
    EXISTS (
        SELECT 1 FROM auth.auth_events e
        WHERE e.user_id = @user_id AND e.event = 'login_succeeded' AND e.created_at >= @since
          AND e.user_agent IS NOT DISTINCT FROM sqlc.narg('user_agent')
          AND e.ip << network(set_masklen(@ip::inet, @bits::int))
    ) AS seen;
