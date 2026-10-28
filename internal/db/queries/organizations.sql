-- name: CreateOrganization :one
INSERT INTO auth.organizations (id, name, created_at, updated_at)
VALUES (@id, @name, @now, @now)
RETURNING *;

-- name: CreateMembership :exec
INSERT INTO auth.memberships (id, organization_id, user_id, role, created_at, updated_at)
VALUES (@id, @organization_id, @user_id, @role, @now, @now);

-- name: GetMemberOrganization :one
SELECT o.id, o.name, o.created_at, o.updated_at, m.role
FROM auth.organizations o
JOIN auth.memberships m ON m.organization_id = o.id
WHERE o.id = @organization_id AND m.user_id = @user_id;

-- name: ListUserOrganizations :many
SELECT o.id, o.name, o.created_at, o.updated_at, m.role
FROM auth.organizations o
JOIN auth.memberships m ON m.organization_id = o.id
WHERE m.user_id = @user_id
ORDER BY o.created_at, o.id;

-- name: RenameOrganization :one
UPDATE auth.organizations SET name = @name, updated_at = @now
WHERE id = @id
RETURNING *;

-- Membership IDs are UUIDv7, so ordering by ID lists members in the order
-- they joined, and the last ID on a page is the cursor for the next.
-- name: ListMembers :many
SELECT m.id, m.user_id, u.email, m.role, m.created_at
FROM auth.memberships m
JOIN auth.users u ON u.id = m.user_id
WHERE m.organization_id = @organization_id
  AND (sqlc.narg(after)::uuid IS NULL OR m.id > sqlc.narg(after)::uuid)
ORDER BY m.id
LIMIT @max_rows;

-- Serializes changes to an organization's members, so two owners demoting
-- each other at once can't leave it with none.
-- name: LockOrganization :one
SELECT id FROM auth.organizations WHERE id = @id FOR UPDATE;

-- name: CountOwners :one
SELECT count(*) FROM auth.memberships WHERE organization_id = @organization_id AND role = @owner_role;

-- name: GetMembership :one
SELECT * FROM auth.memberships WHERE organization_id = @organization_id AND user_id = @user_id;

-- name: SetMembershipRole :exec
UPDATE auth.memberships SET role = @role, updated_at = @now
WHERE organization_id = @organization_id AND user_id = @user_id;

-- name: DeleteMembership :exec
DELETE FROM auth.memberships WHERE organization_id = @organization_id AND user_id = @user_id;
