package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/atlasopsec/auth/internal/db"
)

// SetAppRole gives a user an app role from Config.AppRoles, replacing any
// role they had. An empty role removes it. It's for seed scripts and admin
// tooling; there's no endpoint for it.
func (a *Auth) SetAppRole(ctx context.Context, userID uuid.UUID, role string) error {
	if role == "" {
		if err := a.q.DeleteUserRole(ctx, userID); err != nil {
			return fmt.Errorf("auth: removing app role: %w", err)
		}
		return nil
	}
	if !a.appRoles.Defines(role) {
		return fmt.Errorf("auth: %q isn't a role in Config.AppRoles", role)
	}
	err := a.q.SetUserRole(ctx, db.SetUserRoleParams{UserID: userID, Role: role, Now: a.now().UTC().Truncate(time.Microsecond)})
	if err != nil {
		return fmt.Errorf("auth: setting app role: %w", err)
	}
	return nil
}
