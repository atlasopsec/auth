package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/atlasopsec/auth/internal/db"
	"github.com/atlasopsec/auth/internal/password"
	"github.com/atlasopsec/auth/internal/session"
)

// Errors from the account management methods (CreateUser, UpdateUser,
// DeleteUser, EndSessions, SetMemberRole, and RemoveMember).
var (
	// ErrInvalidEmail means an email address isn't a single plain address
	// of at most 254 characters, such as ada@example.com.
	ErrInvalidEmail = errors.New("auth: invalid email address")
	// ErrEmailTaken means another user already has the email address,
	// compared regardless of case.
	ErrEmailTaken = errors.New("auth: email address already has an account")
	// ErrInvalidPasswordHash means a password hash isn't one the module
	// can verify. The error never contains the hash.
	ErrInvalidPasswordHash = errors.New("auth: unsupported or malformed password hash")
	// ErrUserNotFound means there's no user with the ID.
	ErrUserNotFound = errors.New("auth: no such user")
	// ErrOrganizationNotFound means there's no organization with the ID.
	ErrOrganizationNotFound = errors.New("auth: no such organization")
	// ErrUnknownRole means a role isn't one of Config.OrgRoles or, for a
	// role key from CustomRoleKey, one of the organization's own roles.
	ErrUnknownRole = errors.New("auth: unknown organization role")
	// ErrLastOwner means a change would leave an organization without an
	// owner. Make someone else an owner first.
	ErrLastOwner = errors.New("auth: an organization must keep at least one owner")
)

// NewUser is an account CreateUser creates.
type NewUser struct {
	// Email is the user's address. The caller vouches for it, so it counts
	// as verified.
	Email string
	// PasswordHash is the user's existing password hash, such as one from
	// the system they're moving from, in the encoded form the module
	// stores: "$argon2id$v=19$m=…,t=…,p=…$<salt>$<hash>", or, with
	// Config.AllowBcryptHashes, a bcrypt hash ("$2a$", "$2b$", or "$2y$").
	// Either is replaced with an argon2id hash with the module's settings
	// at the user's next login. Leave
	// it empty for a user without a password, who signs in with a provider
	// or sets one with a password reset.
	PasswordHash string
}

// UserChanges are the changes UpdateUser makes. Nil fields stay as they
// are.
type UserChanges struct {
	// Email replaces the user's address. The caller vouches for it, so it
	// counts as verified.
	Email *string
	// PasswordHash replaces the user's password hash, in the form
	// NewUser.PasswordHash takes. An empty string removes the password.
	PasswordHash *string
}

// CreateUser creates a user from code, with a verified email and an
// optional existing password hash. It's for projects moving their accounts
// from another system, and for admin tooling; there's no endpoint for it.
// Hooks.OnUserCreated runs in the same transaction, as at sign-up; if it
// fails, nothing is created and its error is returned. No email is sent.
// by is who's making the change, for the security event log.
func (a *Auth) CreateUser(ctx context.Context, u NewUser, by Actor) (User, error) {
	email := strings.TrimSpace(u.Email)
	if !validStoredEmail(email) {
		return User{}, ErrInvalidEmail
	}
	var hash *string
	if u.PasswordHash != "" {
		if err := a.checkStoredHash(u.PasswordHash); err != nil {
			return User{}, err
		}
		hash = &u.PasswordHash
	}
	id, err := uuid.NewV7()
	if err != nil {
		return User{}, fmt.Errorf("auth: generating user ID: %w", err)
	}

	var created User
	err = a.withTx(ctx, func(tx pgx.Tx) error {
		q := db.New(tx)
		now := a.now().UTC().Truncate(time.Microsecond)
		row, err := q.CreateUser(ctx, db.CreateUserParams{ID: id, Email: email, PasswordHash: hash, Now: now})
		if isEmailTaken(err) {
			return ErrEmailTaken
		}
		if err != nil {
			return fmt.Errorf("creating user: %w", err)
		}
		if err := q.MarkEmailVerified(ctx, db.MarkEmailVerifiedParams{ID: id, Now: now}); err != nil {
			return fmt.Errorf("marking email verified: %w", err)
		}
		row.EmailVerifiedAt = &now
		created = userFromRow(row)
		if a.hooks.OnUserCreated != nil {
			if err := a.hooks.OnUserCreated(ctx, tx, created); err != nil {
				return fmt.Errorf("OnUserCreated hook: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return User{}, accountError("creating user", err)
	}
	a.log.InfoContext(ctx, "auth: user created from code", slog.String("user_id", id.String()))
	a.adminEvent(ctx, by, Event{Type: EventUserCreated, UserID: &id})
	return created, nil
}

// UpdateUser changes a user's email or password hash from code, such as
// when a project copies changes from the system it's moving from. A
// change to either ends the user's sessions and cancels the links already
// emailed to them, as the module's own email and password changes do.
// Fields that are nil, or already hold the given value, change nothing.
// No email is sent. by is who's making the change, for the security event
// log.
//
// The module upgrades password hashes when users log in, so the stored
// hash may differ from the one a project last gave. Pass a hash only when
// it has changed at the source, or the user's sessions end each time.
func (a *Auth) UpdateUser(ctx context.Context, userID uuid.UUID, c UserChanges, by Actor) (User, error) {
	var email string
	if c.Email != nil {
		email = strings.TrimSpace(*c.Email)
		if !validStoredEmail(email) {
			return User{}, ErrInvalidEmail
		}
	}
	if c.PasswordHash != nil && *c.PasswordHash != "" {
		if err := a.checkStoredHash(*c.PasswordHash); err != nil {
			return User{}, err
		}
	}

	var (
		updated                       User
		emailChanged, passwordChanged bool
	)
	err := a.withTx(ctx, func(tx pgx.Tx) error {
		q := db.New(tx)
		if _, err := q.LockUser(ctx, userID); err != nil {
			return fmt.Errorf("locking user: %w", err)
		}
		row, err := q.GetUserByID(ctx, userID)
		if err != nil {
			return fmt.Errorf("reading user: %w", err)
		}
		now := a.now().UTC().Truncate(time.Microsecond)
		if c.Email != nil && (email != row.Email || row.EmailVerifiedAt == nil) {
			err := q.UpdateUserEmail(ctx, db.UpdateUserEmailParams{ID: userID, Email: email, Now: &now})
			if isEmailTaken(err) {
				return ErrEmailTaken
			}
			if err != nil {
				return fmt.Errorf("changing email: %w", err)
			}
			emailChanged = email != row.Email
			row.Email, row.EmailVerifiedAt = email, &now
		}
		if c.PasswordHash != nil && *c.PasswordHash != storedHash(row.PasswordHash) {
			var hash *string
			if *c.PasswordHash != "" {
				hash = c.PasswordHash
			}
			if err := q.UpdatePasswordHash(ctx, db.UpdatePasswordHashParams{ID: userID, PasswordHash: hash, Now: now}); err != nil {
				return fmt.Errorf("setting password: %w", err)
			}
			passwordChanged = true
		}
		if emailChanged || passwordChanged {
			if err := a.endAccess(ctx, tx, userID); err != nil {
				return err
			}
		}
		updated = userFromRow(row)
		return nil
	})
	if err != nil {
		return User{}, accountError("updating user", err)
	}
	if emailChanged {
		a.adminEvent(ctx, by, Event{Type: EventEmailChanged, UserID: &userID})
	}
	if passwordChanged {
		a.adminEvent(ctx, by, Event{Type: EventPasswordChanged, UserID: &userID})
	}
	return updated, nil
}

// DeleteUser deletes a user and everything the module keeps about them:
// sessions, memberships, app role, 2FA, linked providers, and the
// invitations they sent. Their security events are kept, without the link
// to them. Project tables that reference auth.users(id) with ON DELETE
// CASCADE lose the user's rows too. It returns ErrLastOwner if the user is
// the only owner of an organization. No email is sent. by is who's
// deleting them, for the security event log.
func (a *Auth) DeleteUser(ctx context.Context, userID uuid.UUID, by Actor) error {
	err := a.withTx(ctx, func(tx pgx.Tx) error {
		q := db.New(tx)
		// Holding the user's row stops anyone adding a membership for them
		// until this commits.
		if _, err := q.LockUser(ctx, userID); err != nil {
			return fmt.Errorf("locking user: %w", err)
		}
		orgs, err := q.ListOwnedOrganizationIDs(ctx, db.ListOwnedOrganizationIDsParams{UserID: userID, OwnerRole: OwnerRole})
		if err != nil {
			return fmt.Errorf("listing owned organizations: %w", err)
		}
		for _, orgID := range orgs {
			if _, err := q.LockOrganization(ctx, orgID); err != nil {
				return fmt.Errorf("locking organization: %w", err)
			}
			if err := lastOwnerCheck(ctx, q, orgID); err != nil {
				return err
			}
		}
		if _, err := q.DeleteUser(ctx, userID); err != nil {
			return fmt.Errorf("deleting user: %w", err)
		}
		return nil
	})
	if err != nil {
		return accountError("deleting user", err)
	}
	a.log.InfoContext(ctx, "auth: user deleted from code", slog.String("user_id", userID.String()))
	// The event can't point at a user who no longer exists.
	a.adminEvent(ctx, by, Event{Type: EventUserDeleted, Metadata: map[string]string{"user_id": userID.String()}})
	return nil
}

// EndSessions logs a user out everywhere, from code: it ends all their
// sessions and any login waiting for a 2FA code. It's for admin tooling and
// support, such as when an account may be compromised. by is who's ending
// them, for the security event log.
func (a *Auth) EndSessions(ctx context.Context, userID uuid.UUID, by Actor) error {
	err := a.withTx(ctx, func(tx pgx.Tx) error {
		if _, err := db.New(tx).LockUser(ctx, userID); err != nil {
			return fmt.Errorf("locking user: %w", err)
		}
		if _, err := session.NewManager(tx, a.now).RevokeAll(ctx, userID); err != nil {
			return err
		}
		if err := db.New(tx).DeleteTwoFactorChallenges(ctx, userID); err != nil {
			return fmt.Errorf("deleting 2FA challenges: %w", err)
		}
		return nil
	})
	if err != nil {
		return accountError("ending sessions", err)
	}
	a.adminEvent(ctx, by, Event{Type: EventLogoutEverywhere, UserID: &userID})
	return nil
}

// SetMemberRole makes a user a member of an organization with role, or
// changes the role of a member, from code. role is one of Config.OrgRoles,
// or the Key of one of the organization's own roles (CustomRoleKey). It's for projects moving memberships from another
// system, and for admin tooling: unlike the members endpoints, it doesn't
// check what the caller may grant, so never pass it a role straight from a
// user's request. Demoting the last owner returns ErrLastOwner. Setting
// the role a member already has changes nothing. by is who's making the
// change, for the security event log.
func (a *Auth) SetMemberRole(ctx context.Context, orgID, userID uuid.UUID, role string, by Actor) error {
	if a.orgRoles == nil {
		return errors.New("auth: SetMemberRole needs Config.OrgRoles")
	}
	if _, custom := customRoleID(role); !custom && !a.orgRoles.Defines(role) {
		return ErrUnknownRole
	}
	var oldRole string
	err := a.withOrgLock(ctx, orgID, func(q *db.Queries) error {
		next, err := a.roleByKey(ctx, q, orgID, role)
		if err != nil {
			return err
		}
		if !next.defined {
			// Another organization's role, or one that doesn't exist.
			return ErrUnknownRole
		}
		m, err := q.GetMembership(ctx, db.GetMembershipParams{OrganizationID: orgID, UserID: userID})
		switch {
		case errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			return fmt.Errorf("reading membership: %w", err)
		default:
			oldRole = m.Role
		}
		if oldRole == role {
			return nil
		}
		if oldRole == OwnerRole {
			if err := lastOwnerCheck(ctx, q, orgID); err != nil {
				return err
			}
		}
		id, err := uuid.NewV7()
		if err != nil {
			return fmt.Errorf("generating membership ID: %w", err)
		}
		err = q.UpsertMembership(ctx, db.UpsertMembershipParams{
			ID: id, OrganizationID: orgID, UserID: userID, Role: role, CustomRoleID: customRoleIDOf(next), Now: a.now().UTC().Truncate(time.Microsecond),
		})
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.ConstraintName == "memberships_user_id_fkey" {
			return ErrUserNotFound
		}
		if err != nil {
			return fmt.Errorf("saving membership: %w", err)
		}
		return nil
	})
	if err != nil {
		return accountError("setting member role", err)
	}
	meta := map[string]string{"organization_id": orgID.String(), "role": role}
	switch oldRole {
	case role:
	case "":
		a.adminEvent(ctx, by, Event{Type: EventMemberAdded, UserID: &userID, Metadata: meta})
	default:
		a.adminEvent(ctx, by, Event{Type: EventOrgRoleChanged, UserID: &userID, Metadata: meta})
	}
	return nil
}

// RemoveMember removes a user from an organization, from code. Removing
// the last owner returns ErrLastOwner. Removing someone who isn't a member
// changes nothing. by is who's removing them, for the security event log.
func (a *Auth) RemoveMember(ctx context.Context, orgID, userID uuid.UUID, by Actor) error {
	if a.orgRoles == nil {
		return errors.New("auth: RemoveMember needs Config.OrgRoles")
	}
	removed := false
	err := a.withOrgLock(ctx, orgID, func(q *db.Queries) error {
		m, err := q.GetMembership(ctx, db.GetMembershipParams{OrganizationID: orgID, UserID: userID})
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading membership: %w", err)
		}
		if m.Role == OwnerRole {
			if err := lastOwnerCheck(ctx, q, orgID); err != nil {
				return err
			}
		}
		if err := q.DeleteMembership(ctx, db.DeleteMembershipParams{OrganizationID: orgID, UserID: userID}); err != nil {
			return fmt.Errorf("removing membership: %w", err)
		}
		removed = true
		return nil
	})
	if err != nil {
		return accountError("removing member", err)
	}
	if removed {
		a.adminEvent(ctx, by, Event{Type: EventMemberRemoved, UserID: &userID, Metadata: map[string]string{"organization_id": orgID.String()}})
	}
	return nil
}

// withOrgLock runs f in a transaction holding the organization's lock, the
// same one the members endpoints take, so no change can leave it without
// an owner. It returns ErrOrganizationNotFound if there's no such
// organization.
func (a *Auth) withOrgLock(ctx context.Context, orgID uuid.UUID, f func(q *db.Queries) error) error {
	return a.withTx(ctx, func(tx pgx.Tx) error {
		q := db.New(tx)
		_, err := q.LockOrganization(ctx, orgID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrOrganizationNotFound
		}
		if err != nil {
			return fmt.Errorf("locking organization: %w", err)
		}
		return f(q)
	})
}

// endAccess ends a user's sessions, logins waiting for a 2FA code, and
// unused email links, after their email or password changed.
func (a *Auth) endAccess(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
	q := db.New(tx)
	if err := q.DeleteTwoFactorChallenges(ctx, userID); err != nil {
		return fmt.Errorf("deleting 2FA challenges: %w", err)
	}
	if err := q.DeleteUnusedUserEmailTokens(ctx, userID); err != nil {
		return fmt.Errorf("cancelling email tokens: %w", err)
	}
	_, err := session.NewManager(tx, a.now).RevokeAll(ctx, userID)
	return err
}

// checkStoredHash checks a password hash given to CreateUser or
// UpdateUser is one the module can verify.
func (a *Auth) checkStoredHash(hash string) error {
	if password.IsBcrypt(hash) {
		if a.bcryptDummy == nil || password.CheckBcrypt(hash) != nil {
			return ErrInvalidPasswordHash
		}
		return nil
	}
	if password.CheckHash(hash) != nil {
		return ErrInvalidPasswordHash
	}
	return nil
}

// accountError wraps an error from an account management method. The
// exported errors pass through as they are, and a missing user (from a
// lock or read that found no row) becomes ErrUserNotFound.
func accountError(doing string, err error) error {
	for _, known := range []error{ErrEmailTaken, ErrUserNotFound, ErrOrganizationNotFound, ErrLastOwner, ErrSignUpNotAllowed, ErrUnknownRole} {
		if errors.Is(err, known) {
			return fmt.Errorf("auth: %s: %w", doing, known)
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("auth: %s: %w", doing, ErrUserNotFound)
	}
	return fmt.Errorf("auth: %s: %w", doing, err)
}

func isEmailTaken(err error) bool {
	pgErr, ok := errors.AsType[*pgconn.PgError](err)
	return ok && pgErr.Code == "23505" && pgErr.ConstraintName == "idx_users_email"
}

// validStoredEmail reports whether email is one the module would accept at
// sign-up.
func validStoredEmail(email string) bool {
	_, ok := checkEmail(email)
	return ok
}

func storedHash(h *string) string {
	if h == nil {
		return ""
	}
	return *h
}
