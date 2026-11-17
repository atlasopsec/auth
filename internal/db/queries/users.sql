-- name: CreateUser :one
INSERT INTO auth.users (id, email, password_hash, created_at, updated_at)
VALUES (@id, @email, @password_hash, @now, @now)
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM auth.users WHERE id = @id;

-- Matches idx_users_email, so emails are found regardless of case.
-- name: GetUserByEmail :one
SELECT * FROM auth.users WHERE lower(email) = lower(@email);

-- name: UpdatePasswordHash :exec
UPDATE auth.users SET password_hash = @password_hash, updated_at = @now WHERE id = @id;

-- Keeps the original verification time if the email was already verified.
-- name: MarkEmailVerified :exec
UPDATE auth.users
SET email_verified_at = coalesce(email_verified_at, @now), updated_at = @now
WHERE id = @id;

-- name: UpdateUserEmail :exec
UPDATE auth.users
SET email = @email, email_verified_at = @now, updated_at = @now
WHERE id = @id;

-- The user, with what decides their 2FA rules: whether they hold one of
-- @roles (Config.TwoFactorRoles) as an app role or in any organization, or
-- a role an organization defined with any of @privileged_permissions, and
-- whether they have 2FA on.
-- name: GetUserWithTwoFactor :one
SELECT sqlc.embed(u),
    (EXISTS (SELECT 1 FROM auth.user_roles r WHERE r.user_id = u.id AND r.role = ANY (@roles::text[]))
        OR EXISTS (SELECT 1 FROM auth.memberships m WHERE m.user_id = u.id AND m.role = ANY (@roles::text[]))
        OR EXISTS (SELECT 1 FROM auth.memberships m
            JOIN auth.organization_roles r ON r.organization_id = m.organization_id AND r.id = m.custom_role_id
            WHERE m.user_id = u.id AND r.permissions && @privileged_permissions::text[]))::boolean AS privileged,
    EXISTS (SELECT 1 FROM auth.totp_secrets t WHERE t.user_id = u.id AND t.confirmed_at IS NOT NULL)::boolean AS two_factor_enabled
FROM auth.users u
WHERE u.id = @id;

-- name: SetTwoFactorRequired :execrows
UPDATE auth.users SET two_factor_required = @required, updated_at = @now WHERE id = @id;

-- Replaces a hash only if it's still the one the password was checked
-- against, so an upgrade at login can't undo a change made meanwhile.
-- name: RehashPassword :execrows
UPDATE auth.users SET password_hash = @new_hash, updated_at = @now
WHERE id = @id AND password_hash = @old_hash;
