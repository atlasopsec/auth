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
