-- name: GetPendingInvitationForEmail :one
SELECT * FROM auth.invitations
WHERE organization_id = @organization_id AND lower(email) = lower(@email) AND accepted_at IS NULL;

-- name: DeleteInvitation :exec
DELETE FROM auth.invitations WHERE id = @id;

-- name: CreateInvitation :one
INSERT INTO auth.invitations (
    id, organization_id, email, role, token_hash, invited_by, expires_at, created_at, updated_at
) VALUES (
    @id, @organization_id, @email, @role, @token_hash, @invited_by, @expires_at, @now, @now
)
RETURNING *;

-- name: IsMemberByEmail :one
SELECT EXISTS (
    SELECT 1 FROM auth.memberships m
    JOIN auth.users u ON u.id = m.user_id
    WHERE m.organization_id = @organization_id AND lower(u.email) = lower(@email)
);

-- Invitation IDs are UUIDv7, so ordering by ID lists them oldest first, and
-- the last ID on a page is the cursor for the next.
-- name: ListPendingInvitations :many
SELECT * FROM auth.invitations
WHERE organization_id = @organization_id
  AND accepted_at IS NULL
  AND expires_at > @now
  AND (sqlc.narg(after)::uuid IS NULL OR id > sqlc.narg(after)::uuid)
ORDER BY id
LIMIT @max_rows;

-- name: GetPendingInvitationInOrganization :one
SELECT * FROM auth.invitations
WHERE organization_id = @organization_id AND id = @id AND accepted_at IS NULL;

-- name: GetInvitationByTokenHash :one
SELECT * FROM auth.invitations WHERE token_hash = @token_hash;

-- Marks an invitation accepted only if it still is pending and unexpired,
-- so two requests with the same link can't both use it.
-- name: AcceptInvitation :execrows
UPDATE auth.invitations SET accepted_at = @now, updated_at = @now
WHERE id = @id AND accepted_at IS NULL AND expires_at > @now;
