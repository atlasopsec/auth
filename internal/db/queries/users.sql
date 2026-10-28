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
