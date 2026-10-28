-- Starts (or restarts) setup. An already confirmed secret is left alone.
-- name: UpsertPendingTOTPSecret :execrows
INSERT INTO auth.totp_secrets (user_id, secret_encrypted, created_at, updated_at)
VALUES (@user_id, @secret_encrypted, @now, @now)
ON CONFLICT (user_id) DO UPDATE
SET secret_encrypted = excluded.secret_encrypted, last_used_step = 0, created_at = excluded.created_at, updated_at = excluded.updated_at
WHERE auth.totp_secrets.confirmed_at IS NULL;

-- Locks the row, so two requests with the same code can't both use it.
-- name: GetTOTPSecretForUpdate :one
SELECT * FROM auth.totp_secrets WHERE user_id = @user_id FOR UPDATE;

-- name: GetTOTPSecret :one
SELECT * FROM auth.totp_secrets WHERE user_id = @user_id;

-- name: RecordTOTPStep :exec
UPDATE auth.totp_secrets SET last_used_step = @step, updated_at = @now WHERE user_id = @user_id;

-- name: ConfirmTOTPSecret :exec
UPDATE auth.totp_secrets SET confirmed_at = @now, last_used_step = @step, updated_at = @now WHERE user_id = @user_id;

-- name: DeleteTOTPSecret :exec
DELETE FROM auth.totp_secrets WHERE user_id = @user_id;

-- name: DeleteRecoveryCodes :exec
DELETE FROM auth.recovery_codes WHERE user_id = @user_id;

-- name: CreateRecoveryCode :exec
INSERT INTO auth.recovery_codes (id, user_id, code_hash, created_at, updated_at)
VALUES (@id, @user_id, @code_hash, @now, @now);

-- Spends a recovery code, only if it's unused.
-- name: UseRecoveryCode :execrows
UPDATE auth.recovery_codes SET used_at = @now, updated_at = @now
WHERE user_id = @user_id AND code_hash = @code_hash AND used_at IS NULL;

-- name: CountUnusedRecoveryCodes :one
SELECT count(*) FROM auth.recovery_codes WHERE user_id = @user_id AND used_at IS NULL;
