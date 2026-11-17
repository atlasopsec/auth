-- name: DeleteUser :execrows
DELETE FROM auth.users WHERE id = @id;

-- The organizations where a user is an owner, in ID order so that locking
-- them can't deadlock with another lock taken in the same order.
-- name: ListOwnedOrganizationIDs :many
SELECT organization_id FROM auth.memberships
WHERE user_id = @user_id AND role = @owner_role
ORDER BY organization_id;

-- name: UpsertMembership :exec
INSERT INTO auth.memberships (id, organization_id, user_id, role, created_at, updated_at)
VALUES (@id, @organization_id, @user_id, @role, @now, @now)
ON CONFLICT (organization_id, user_id) DO UPDATE SET role = excluded.role, updated_at = excluded.updated_at;
