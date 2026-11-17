package auth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/atlasopsec/auth/internal/db"
	"github.com/atlasopsec/auth/rbac"
)

// customRolePrefix starts the role key of a role an organization defined:
// "custom:<role ID>". Role names in code can't contain a colon, so the two
// kinds never clash.
const customRolePrefix = "custom:"

// CustomRoleKey returns the role key for a role an organization defined,
// as it appears in a member's role: "custom:<role ID>". Pass it to
// SetMemberRole, or as the role in PATCH /v1/organizations/{id}/members/
// {user_id}, to give a member the role.
func CustomRoleKey(roleID uuid.UUID) string {
	return customRolePrefix + roleID.String()
}

// customRoleID returns the role ID in a custom role key. A key that's not
// exactly what CustomRoleKey returns isn't one.
func customRoleID(key string) (uuid.UUID, bool) {
	s, ok := strings.CutPrefix(key, customRolePrefix)
	if !ok {
		return uuid.Nil, false
	}
	id, err := uuid.Parse(s)
	if err != nil || CustomRoleKey(id) != key {
		return uuid.Nil, false
	}
	return id, true
}

// orgRole is a role in one organization, with what it grants. It's the
// only thing organization permission checks look at.
type orgRole struct {
	key string
	// defined is false for a role that's no longer defined in code, or a
	// custom role that doesn't exist (in this organization). It grants
	// nothing.
	defined bool
	// all is true for owners, and code roles with rbac.All.
	all   bool
	perms []rbac.Permission
}

func (r orgRole) can(p rbac.Permission) bool {
	return r.defined && (r.all || slices.Contains(r.perms, p))
}

// codeRole is a role from Config.OrgRoles. Owners always have every
// permission, whatever the definition says, so an organization can't be
// locked out of its own settings.
func (a *Auth) codeRole(key string) orgRole {
	perms, ok := a.orgRoles[key]
	return orgRole{key: key, defined: ok, all: key == OwnerRole || slices.Contains(perms, rbac.All), perms: perms}
}

// customRole is a role an organization defined, from its stored
// permissions. Only permissions some role in code still lists count, so
// removing a permission from code takes it from custom roles too, and
// rbac.All never counts.
func (a *Auth) customRole(key string, stored []string) orgRole {
	r := orgRole{key: key, defined: true}
	for _, s := range stored {
		if p := rbac.Permission(s); a.declared(p) {
			r.perms = append(r.perms, p)
		}
	}
	return r
}

// declared reports whether p is a permission the project declares: one
// that a role in Config.OrgRoles lists by name.
func (a *Auth) declared(p rbac.Permission) bool {
	return p != rbac.All && a.orgRoles.Mentions(p)
}

// roleFromAccess is the role a GetMembershipAccess row describes.
func (a *Auth) roleFromAccess(row db.GetMembershipAccessRow) orgRole {
	if _, ok := customRoleID(row.Role); ok {
		if row.CustomPermissions == nil {
			return orgRole{key: row.Role}
		}
		return a.customRole(row.Role, row.CustomPermissions)
	}
	return a.codeRole(row.Role)
}

// memberRole loads a member's role in an organization. It returns
// pgx.ErrNoRows, wrapped, if they aren't a member.
func (a *Auth) memberRole(ctx context.Context, q *db.Queries, orgID, userID uuid.UUID) (orgRole, error) {
	row, err := q.GetMembershipAccess(ctx, db.GetMembershipAccessParams{OrganizationID: orgID, UserID: userID})
	if err != nil {
		return orgRole{}, fmt.Errorf("reading membership: %w", err)
	}
	return a.roleFromAccess(row), nil
}

// roleByKey loads the role a key names in an organization: a code role,
// or one of the organization's own. A custom role of another organization
// isn't found, and comes back undefined.
func (a *Auth) roleByKey(ctx context.Context, q *db.Queries, orgID uuid.UUID, key string) (orgRole, error) {
	id, ok := customRoleID(key)
	if !ok {
		return a.codeRole(key), nil
	}
	row, err := q.GetOrganizationRole(ctx, db.GetOrganizationRoleParams{OrganizationID: orgID, ID: id})
	if errors.Is(err, pgx.ErrNoRows) {
		return orgRole{key: key}, nil
	}
	if err != nil {
		return orgRole{}, fmt.Errorf("reading role: %w", err)
	}
	return a.customRole(key, row.Permissions), nil
}

// roleName is how a role is shown: a custom role's name, or the role
// itself for one defined in code. A custom role that no longer exists
// shows as its key.
func (a *Auth) roleName(ctx context.Context, q *db.Queries, orgID uuid.UUID, key string) (string, error) {
	id, ok := customRoleID(key)
	if !ok {
		return key, nil
	}
	row, err := q.GetOrganizationRole(ctx, db.GetOrganizationRoleParams{OrganizationID: orgID, ID: id})
	if errors.Is(err, pgx.ErrNoRows) {
		return key, nil
	}
	if err != nil {
		return "", fmt.Errorf("reading role: %w", err)
	}
	return row.Name, nil
}

// customRoleIDOf is the custom_role_id stored with a membership in role.
func customRoleIDOf(r orgRole) *uuid.UUID {
	if id, ok := customRoleID(r.key); ok {
		return &id
	}
	return nil
}

// mayAssign reports whether someone with role actor may give a member
// role, or change the role of a member who has it: only owners may touch
// owners, and anyone else must already have every permission role grants.
// A role that's no longer defined grants nothing, so it's always covered.
func mayAssign(actor, role orgRole) bool {
	if actor.key == OwnerRole {
		return true
	}
	if role.key == OwnerRole || role.defined && role.all {
		return false
	}
	return holdsAll(actor, role.perms)
}

// holdsAll reports whether actor has every one of perms.
func holdsAll(actor orgRole, perms []rbac.Permission) bool {
	for _, p := range perms {
		if p == rbac.All || !actor.can(p) {
			return false
		}
	}
	return true
}

// privilegedPermissions are the permissions that make a custom role
// privileged under Config.TwoFactorRoles: those that some privileged
// organization role has and no other organization role, owners aside,
// does. A custom
// role with any of them needs 2FA and 12-hour sessions, so copying a
// privileged role's permissions into a custom one doesn't avoid 2FA.
func privilegedPermissions(orgRoles rbac.Roles, twoFactorRoles []string) []string {
	privileged := map[string]bool{}
	for _, r := range twoFactorRoles {
		if orgRoles.Defines(r) {
			privileged[r] = true
		}
	}
	if len(privileged) == 0 {
		return nil
	}
	ordinary := map[rbac.Permission]bool{}
	for role, perms := range orgRoles {
		// Owners have everything by rule, not by definition, so they
		// say nothing about which permissions are ordinary.
		if privileged[role] || role == OwnerRole {
			continue
		}
		for _, p := range perms {
			if p == rbac.All {
				// Some ordinary role already has everything.
				return nil
			}
			ordinary[p] = true
		}
	}
	var out []string
	seen := map[rbac.Permission]bool{}
	for _, perms := range orgRoles {
		for _, p := range perms {
			if p != rbac.All && !ordinary[p] && !seen[p] {
				seen[p] = true
				out = append(out, string(p))
			}
		}
	}
	slices.Sort(out)
	return out
}
