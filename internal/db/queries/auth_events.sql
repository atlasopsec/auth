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
