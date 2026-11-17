-- name: CreateOrganizationRole :one
INSERT INTO auth.organization_roles (id, organization_id, name, permissions, created_at, updated_at)
VALUES (@id, @organization_id, @name, @permissions, @now, @now)
RETURNING *;

-- Always filtered by organization, so a role ID from another organization
-- is never found.
-- name: GetOrganizationRole :one
SELECT * FROM auth.organization_roles WHERE organization_id = @organization_id AND id = @id;

-- name: ListOrganizationRoles :many
SELECT * FROM auth.organization_roles WHERE organization_id = @organization_id
ORDER BY id
LIMIT @max_rows;

-- name: CountOrganizationRoles :one
SELECT count(*) FROM auth.organization_roles WHERE organization_id = @organization_id;

-- name: UpdateOrganizationRole :one
UPDATE auth.organization_roles SET name = @name, permissions = @permissions, updated_at = @now
WHERE organization_id = @organization_id AND id = @id
RETURNING *;

-- name: DeleteOrganizationRole :execrows
DELETE FROM auth.organization_roles WHERE organization_id = @organization_id AND id = @id;

-- name: CountRoleMembers :one
SELECT count(*) FROM auth.memberships WHERE organization_id = @organization_id AND custom_role_id = @custom_role_id;
