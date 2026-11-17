package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/atlasopsec/auth/internal/db"
	"github.com/atlasopsec/auth/internal/session"
	"github.com/atlasopsec/auth/internal/totp"
)

var (
	// ErrInvalidTwoFactorSecret means a secret given to ImportTwoFactor
	// isn't base32, or is shorter than 128 bits or longer than 512. The
	// error never contains the secret.
	ErrInvalidTwoFactorSecret = errors.New("auth: invalid two-factor secret")
	// ErrEmailNotVerified means the change needs a user whose email is
	// verified.
	ErrEmailNotVerified = errors.New("auth: email address not verified")
)

// ImportTwoFactor turns on a user's 2FA with a TOTP secret made elsewhere,
// such as by the system they're moving from, so their authenticator app
// keeps working. secret is base32, as authenticator apps show it, for
// 6-digit codes every 30 seconds with SHA-1, the settings nearly every app
// uses. The module encrypts it with Config.EncryptionKey. It replaces any
// secret the user had, and ends their sessions and logins waiting for a 2FA
// code, as turning 2FA on does. The same secret again changes nothing.
//
// No recovery codes are made: the user makes them from their settings.
// The user's email must be verified, as for setting 2FA up. No email is
// sent. It's for code that moves accounts, and admin tooling; there's no
// endpoint for it. by is who's making the change, for the security event
// log.
func (a *Auth) ImportTwoFactor(ctx context.Context, userID uuid.UUID, secret string, by Actor) error {
	raw, err := totp.DecodeSecret(secret)
	if err != nil {
		return ErrInvalidTwoFactorSecret
	}
	changed := false
	err = a.withTx(ctx, func(tx pgx.Tx) error {
		q := db.New(tx)
		if _, err := q.LockUser(ctx, userID); err != nil {
			return fmt.Errorf("locking user: %w", err)
		}
		user, err := q.GetUserByID(ctx, userID)
		if err != nil {
			return fmt.Errorf("reading user: %w", err)
		}
		if user.EmailVerifiedAt == nil {
			return ErrEmailNotVerified
		}
		old, err := q.GetTOTPSecretForUpdate(ctx, userID)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			return fmt.Errorf("reading 2FA: %w", err)
		case old.ConfirmedAt != nil:
			// An old secret that won't decrypt is simply replaced.
			if s, err := a.box.Open(old.SecretEncrypted, userID[:]); err == nil && subtle.ConstantTimeCompare(s, raw) == 1 {
				return nil
			}
		}
		now := a.now().UTC().Truncate(time.Microsecond)
		if err := q.ImportTOTPSecret(ctx, db.ImportTOTPSecretParams{
			UserID: userID, SecretEncrypted: a.box.Seal(raw, userID[:]), Now: &now,
		}); err != nil {
			return fmt.Errorf("saving 2FA secret: %w", err)
		}
		if err := q.DeleteTwoFactorChallenges(ctx, userID); err != nil {
			return fmt.Errorf("deleting 2FA challenges: %w", err)
		}
		if _, err := session.NewManager(tx, a.now).RevokeAll(ctx, userID); err != nil {
			return err
		}
		changed = true
		return nil
	})
	if errors.Is(err, ErrEmailNotVerified) {
		return fmt.Errorf("auth: importing 2FA: %w", ErrEmailNotVerified)
	}
	if err != nil {
		return accountError("importing 2FA", err)
	}
	if changed {
		a.log.InfoContext(ctx, "auth: two-factor imported", slog.String("user_id", userID.String()))
		a.adminEvent(ctx, by, Event{Type: EventTwoFactorEnabled, UserID: &userID})
	}
	return nil
}
