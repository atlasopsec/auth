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

-- A member's role in an organization and, for a role the organization
-- defined, its permissions (NULL for roles defined in code).
-- name: GetMembershipAccess :one
SELECT m.role, r.permissions AS custom_permissions
FROM auth.memberships m
LEFT JOIN auth.organization_roles r ON r.organization_id = m.organization_id AND r.id = m.custom_role_id
WHERE m.organization_id = @organization_id AND m.user_id = @user_id;
