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

-- Also clears out the user's challenges that can no longer be used.
-- name: DeleteSpentTwoFactorChallenges :exec
DELETE FROM auth.two_factor_challenges
WHERE user_id = @user_id
  AND (used_at IS NOT NULL OR expires_at <= @now OR failed_attempts >= @max_failed_attempts);

-- name: CreateTwoFactorChallenge :exec
INSERT INTO auth.two_factor_challenges (id, user_id, token_hash, client, expires_at, created_at, updated_at)
VALUES (@id, @user_id, @token_hash, @client, @expires_at, @now, @now);

-- Locks the challenge, so concurrent requests count wrong codes and use it
-- one at a time.
-- name: GetTwoFactorChallengeForUpdate :one
SELECT * FROM auth.two_factor_challenges WHERE token_hash = @token_hash FOR UPDATE;

-- name: RecordTwoFactorChallengeFailure :exec
UPDATE auth.two_factor_challenges
SET failed_attempts = failed_attempts + 1, updated_at = @now
WHERE id = @id;

-- name: UseTwoFactorChallenge :exec
UPDATE auth.two_factor_challenges SET used_at = @now, updated_at = @now WHERE id = @id;

-- name: DeleteTwoFactorChallenges :exec
DELETE FROM auth.two_factor_challenges WHERE user_id = @user_id;

-- name: CreateTwoFactorFailure :exec
INSERT INTO auth.two_factor_failures (id, user_id, created_at, updated_at)
VALUES (@id, @user_id, @now, @now);

-- name: DeleteOldTwoFactorFailures :exec
DELETE FROM auth.two_factor_failures WHERE user_id = @user_id AND created_at <= @since;

-- Returns the time of the user's nth most recent wrong code since @since
-- (counting from 0), if there are that many.
-- name: NthRecentTwoFactorFailure :one
SELECT created_at FROM auth.two_factor_failures
WHERE user_id = @user_id AND created_at > @since
ORDER BY created_at DESC
OFFSET @n LIMIT 1;

-- name: DeleteEndedTwoFactorChallenges :execrows
DELETE FROM auth.two_factor_challenges
WHERE used_at IS NOT NULL OR expires_at <= @now OR failed_attempts >= @max_failed_attempts;

-- name: DeleteTwoFactorFailuresBefore :execrows
DELETE FROM auth.two_factor_failures WHERE created_at <= @before;
