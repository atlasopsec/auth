package auth

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/atlasopsec/auth/internal/db"
	"github.com/atlasopsec/auth/internal/session"
)

// twoFactorState is what decides a user's 2FA rules.
type twoFactorState struct {
	// enabled means the user has confirmed 2FA.
	enabled bool
	// required means they must have it: SetTwoFactorRequired marked them,
	// or they're privileged.
	required bool
	// privileged means they hold one of Config.TwoFactorRoles, so their
	// sessions last at most 12 hours.
	privileged bool
}

// userWithTwoFactor reads a user and their 2FA rules. It returns
// pgx.ErrNoRows, wrapped, if the user doesn't exist.
func (a *Auth) userWithTwoFactor(ctx context.Context, q *db.Queries, userID uuid.UUID) (db.AuthUser, twoFactorState, error) {
	row, err := q.GetUserWithTwoFactor(ctx, db.GetUserWithTwoFactorParams{ID: userID, Roles: a.twoFactorRoles})
	if err != nil {
		return db.AuthUser{}, twoFactorState{}, fmt.Errorf("reading user: %w", err)
	}
	return row.AuthUser, twoFactorState{
		enabled:    row.TwoFactorEnabled,
		required:   row.AuthUser.TwoFactorRequired || row.Privileged,
		privileged: row.Privileged,
	}, nil
}

// sessionPolicy is how long a new session lasts for a user.
func sessionPolicy(tf twoFactorState) session.Policy {
	if tf.privileged {
		return session.Privileged
	}
	return session.Standard
}

// SetTwoFactorRequired sets whether a user must have 2FA even without one
// of Config.TwoFactorRoles. It's for admin tooling, for individual users
// an admin marks. Until they set 2FA up, they can only set it up, read
// GET /v1/users/me, and log out. It takes effect on their next request.
// by is who's making the change, for the security event log.
func (a *Auth) SetTwoFactorRequired(ctx context.Context, userID uuid.UUID, required bool, by Actor) error {
	n, err := a.q.SetTwoFactorRequired(ctx, db.SetTwoFactorRequiredParams{
		ID:       userID,
		Required: required,
		Now:      a.now().UTC().Truncate(time.Microsecond),
	})
	if err != nil {
		return fmt.Errorf("auth: setting 2FA required: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("auth: setting 2FA required: no user %s", userID)
	}
	a.adminEvent(ctx, by, Event{Type: EventTwoFactorRequiredChanged, UserID: &userID, Metadata: map[string]string{"required": strconv.FormatBool(required)}})
	return nil
}
