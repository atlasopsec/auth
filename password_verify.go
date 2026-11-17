package auth

import (
	"context"
	"log/slog"

	"github.com/google/uuid"

	"github.com/atlasopsec/auth/internal/httpapi"
	"github.com/atlasopsec/auth/internal/password"
)

// defaultBcryptCost is bcrypt's own default, and the most common cost.
const defaultBcryptCost = 10

// verifyPassword checks pw against a user's stored hash. A nil hash, for
// an unknown email or an account without a password, does the same work
// and returns false, so the time a check takes doesn't show whether an
// account exists.
//
// With Config.AllowBcryptHashes, every check does one argon2id and one
// bcrypt check's worth of work, real or not, so accounts with either kind
// of hash, and none, look alike. Without it, nothing changes from before
// bcrypt was supported: one argon2id check.
func (a *Auth) verifyPassword(ctx context.Context, userID uuid.UUID, pw string, hash *string) (bool, error) {
	switch {
	case hash == nil:
		password.SimulateVerify(pw)
		a.simulateBcrypt(pw)
		return false, nil
	case password.IsBcrypt(*hash):
		password.SimulateVerify(pw)
		if a.bcryptDummy == nil {
			// Left from before the setting was turned off. Answered like a
			// wrong password, not a 500, so the account can still be
			// recovered with a password reset.
			a.log.WarnContext(ctx, "auth: a user's password hash is bcrypt, but Config.AllowBcryptHashes is off",
				slog.String("request_id", httpapi.RequestIDFrom(ctx)),
				slog.String("user_id", userID.String()))
			return false, nil
		}
		return password.VerifyBcrypt(pw, *hash)
	default:
		ok, err := password.Verify(pw, *hash)
		a.simulateBcrypt(pw)
		return ok, err
	}
}

func (a *Auth) simulateBcrypt(pw string) {
	if a.bcryptDummy != nil {
		a.bcryptDummy.SimulateBcrypt(pw)
	}
}

// needsRehash reports whether a stored hash should be replaced with a new
// argon2id one, now that the password is known: a bcrypt hash, or argon2id
// with other settings than the module's.
func needsRehash(hash string) bool {
	if password.IsBcrypt(hash) {
		return true
	}
	needs, err := password.NeedsRehash(hash, password.DefaultParams)
	return err == nil && needs
}
