-- name: GetMembershipRole :one
SELECT role FROM auth.memberships WHERE organization_id = @organization_id AND user_id = @user_id;

-- name: GetUserRole :one
SELECT role FROM auth.user_roles WHERE user_id = @user_id;

-- name: SetUserRole :exec
INSERT INTO auth.user_roles (user_id, role, created_at, updated_at)
VALUES (@user_id, @role, @now, @now)
ON CONFLICT (user_id) DO UPDATE SET role = excluded.role, updated_at = excluded.updated_at;

-- name: DeleteUserRole :exec
DELETE FROM auth.user_roles WHERE user_id = @user_id;
