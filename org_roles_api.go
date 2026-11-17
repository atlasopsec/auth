package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/atlasopsec/auth/internal/db"
	"github.com/atlasopsec/auth/internal/httpapi"
	"github.com/atlasopsec/auth/rbac"
)

// PermRolesManage lets a member create, change, and delete the roles their
// organization defines. Projects give it to roles like any other
// permission; owners always have it.
const PermRolesManage rbac.Permission = "roles:manage"

// Limits on the roles an organization defines.
const (
	maxOrgRoles         = 50
	maxOrgRoleName      = 100
	maxRolePermissions  = 100
	orgRoleListCapacity = maxOrgRoles + 1
)

// Errors from the organization role methods and endpoints.
var (
	// ErrRoleNotFound means the organization has no role with the ID.
	// Roles of other organizations are never found.
	ErrRoleNotFound = errors.New("auth: no such role in the organization")
	// ErrRoleInUse means a role can't be deleted while members have it.
	// Give them another role first.
	ErrRoleInUse = errors.New("auth: role is in use")
	// ErrInvalidRoleName means a role name is blank, over 100 characters,
	// or the name of a role in Config.OrgRoles.
	ErrInvalidRoleName = errors.New("auth: role name must be 1 to 100 characters and not a role defined in code")
	// ErrRoleNameTaken means the organization has another role with the
	// name, compared regardless of case.
	ErrRoleNameTaken = errors.New("auth: the organization already has a role with this name")
	// ErrUndeclaredPermission means a permission isn't one the project
	// declares: one some role in Config.OrgRoles lists by name. "*" never
	// is.
	ErrUndeclaredPermission = errors.New("auth: permission isn't one the project declares")
	// ErrTooManyRoles means the organization already has 50 roles of its
	// own, or a role would have over 100 permissions.
	ErrTooManyRoles = errors.New("auth: too many roles or permissions")
)

// OrgRole is a role an organization defined itself, from permissions the
// project declares in Config.OrgRoles.
type OrgRole struct {
	ID             uuid.UUID
	OrganizationID uuid.UUID
	// Key is the role as members have it: "custom:<ID>". Give it to a
	// member with SetMemberRole, or PATCH .../members/{user_id}.
	Key  string
	Name string
	// Permissions are what the role grants: those it was given that a role
	// in code still lists.
	Permissions []rbac.Permission
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// OrgRoleChanges are the changes UpdateOrgRole makes. Nil fields stay as
// they are; an empty, non-nil Permissions removes every permission.
type OrgRoleChanges struct {
	Name        *string
	Permissions []rbac.Permission
}

func (a *Auth) orgRoleFromRow(r db.AuthOrganizationRole) OrgRole {
	key := CustomRoleKey(r.ID)
	perms := a.customRole(key, r.Permissions).perms
	if perms == nil {
		perms = []rbac.Permission{}
	}
	return OrgRole{
		ID: r.ID, OrganizationID: r.OrganizationID, Key: key, Name: r.Name,
		Permissions: perms, CreatedAt: r.CreatedAt.UTC(), UpdatedAt: r.UpdatedAt.UTC(),
	}
}

// roleGuard checks, under the organization's lock, that a change to a
// role is allowed: old is the role as it is (nil when creating one), and
// perms what it will grant. The Go methods have none: the caller is the
// project's own code.
type roleGuard func(old *orgRole, perms []rbac.Permission) error

// actorGuard is the endpoints' roleGuard: nobody creates, changes, or
// deletes a role unless they have every permission it grants, before and
// after, so nobody can grant what they don't hold.
func actorGuard(actor orgRole) roleGuard {
	return func(old *orgRole, perms []rbac.Permission) error {
		if old != nil && !holdsAll(actor, old.perms) || !holdsAll(actor, perms) {
			return errForbidden
		}
		return nil
	}
}

// cleanRoleName trims a role name and checks it.
func (a *Auth) cleanRoleName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > maxOrgRoleName {
		return "", ErrInvalidRoleName
	}
	// A custom "Owner" or "admin" would look like the real one.
	for code := range a.orgRoles {
		if strings.EqualFold(code, name) {
			return "", ErrInvalidRoleName
		}
	}
	return name, nil
}

// cleanPermissions checks every permission is declared, and returns them
// sorted, without duplicates.
func (a *Auth) cleanPermissions(perms []rbac.Permission) ([]rbac.Permission, error) {
	out := make([]rbac.Permission, 0, len(perms))
	for _, p := range perms {
		if !a.declared(p) {
			return nil, ErrUndeclaredPermission
		}
		out = append(out, p)
	}
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) > maxRolePermissions {
		return nil, ErrTooManyRoles
	}
	return out, nil
}

func permStrings(perms []rbac.Permission) []string {
	out := make([]string, len(perms))
	for i, p := range perms {
		out[i] = string(p)
	}
	return out
}

func roleEventMetadata(orgID uuid.UUID, key string, perms []rbac.Permission) map[string]string {
	m := map[string]string{"organization_id": orgID.String(), "role": key}
	if perms != nil {
		m["permissions"] = strings.Join(permStrings(perms), ",")
	}
	return m
}

func isRoleNameTaken(err error) bool {
	pgErr, ok := errors.AsType[*pgconn.PgError](err)
	return ok && pgErr.Code == "23505" && pgErr.ConstraintName == "idx_organization_roles_name"
}

func (a *Auth) createRole(ctx context.Context, q *db.Queries, orgID uuid.UUID, name string, perms []rbac.Permission, guard roleGuard) (OrgRole, error) {
	name, err := a.cleanRoleName(name)
	if err != nil {
		return OrgRole{}, err
	}
	if perms, err = a.cleanPermissions(perms); err != nil {
		return OrgRole{}, err
	}
	if guard != nil {
		if err := guard(nil, perms); err != nil {
			return OrgRole{}, err
		}
	}
	n, err := q.CountOrganizationRoles(ctx, orgID)
	if err != nil {
		return OrgRole{}, fmt.Errorf("counting roles: %w", err)
	}
	if n >= maxOrgRoles {
		return OrgRole{}, ErrTooManyRoles
	}
	id, err := uuid.NewV7()
	if err != nil {
		return OrgRole{}, fmt.Errorf("generating role ID: %w", err)
	}
	row, err := q.CreateOrganizationRole(ctx, db.CreateOrganizationRoleParams{
		ID: id, OrganizationID: orgID, Name: name, Permissions: permStrings(perms), Now: a.now().UTC().Truncate(time.Microsecond),
	})
	if isRoleNameTaken(err) {
		return OrgRole{}, ErrRoleNameTaken
	}
	if err != nil {
		return OrgRole{}, fmt.Errorf("creating role: %w", err)
	}
	return a.orgRoleFromRow(row), nil
}

func (a *Auth) updateRole(ctx context.Context, q *db.Queries, orgID, roleID uuid.UUID, c OrgRoleChanges, guard roleGuard) (OrgRole, error) {
	row, err := q.GetOrganizationRole(ctx, db.GetOrganizationRoleParams{OrganizationID: orgID, ID: roleID})
	if errors.Is(err, pgx.ErrNoRows) {
		return OrgRole{}, ErrRoleNotFound
	}
	if err != nil {
		return OrgRole{}, fmt.Errorf("reading role: %w", err)
	}
	old := a.customRole(CustomRoleKey(roleID), row.Permissions)
	name, perms := row.Name, old.perms
	if c.Name != nil {
		if name, err = a.cleanRoleName(*c.Name); err != nil {
			return OrgRole{}, err
		}
	}
	if c.Permissions != nil {
		if perms, err = a.cleanPermissions(c.Permissions); err != nil {
			return OrgRole{}, err
		}
	}
	if guard != nil {
		if err := guard(&old, perms); err != nil {
			return OrgRole{}, err
		}
	}
	stored := row.Permissions
	if c.Permissions != nil {
		stored = permStrings(perms)
	}
	updated, err := q.UpdateOrganizationRole(ctx, db.UpdateOrganizationRoleParams{
		OrganizationID: orgID, ID: roleID, Name: name, Permissions: stored, Now: a.now().UTC().Truncate(time.Microsecond),
	})
	if isRoleNameTaken(err) {
		return OrgRole{}, ErrRoleNameTaken
	}
	if err != nil {
		return OrgRole{}, fmt.Errorf("updating role: %w", err)
	}
	return a.orgRoleFromRow(updated), nil
}

func (a *Auth) deleteRole(ctx context.Context, q *db.Queries, orgID, roleID uuid.UUID, guard roleGuard) error {
	row, err := q.GetOrganizationRole(ctx, db.GetOrganizationRoleParams{OrganizationID: orgID, ID: roleID})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrRoleNotFound
	}
	if err != nil {
		return fmt.Errorf("reading role: %w", err)
	}
	if guard != nil {
		old := a.customRole(CustomRoleKey(roleID), row.Permissions)
		if err := guard(&old, nil); err != nil {
			return err
		}
	}
	n, err := q.CountRoleMembers(ctx, db.CountRoleMembersParams{OrganizationID: orgID, CustomRoleID: &roleID})
	if err != nil {
		return fmt.Errorf("counting role members: %w", err)
	}
	if n > 0 {
		return ErrRoleInUse
	}
	if _, err := q.DeleteOrganizationRole(ctx, db.DeleteOrganizationRoleParams{OrganizationID: orgID, ID: roleID}); err != nil {
		return fmt.Errorf("deleting role: %w", err)
	}
	return nil
}

// orgRoleError wraps an error from the Go role methods, letting the
// exported ones through.
func orgRoleError(doing string, err error) error {
	for _, known := range []error{ErrOrganizationNotFound, ErrRoleNotFound, ErrRoleInUse, ErrInvalidRoleName, ErrRoleNameTaken, ErrUndeclaredPermission, ErrTooManyRoles} {
		if errors.Is(err, known) {
			return fmt.Errorf("auth: %s: %w", doing, known)
		}
	}
	return fmt.Errorf("auth: %s: %w", doing, err)
}

// CreateOrgRole creates a role in an organization from permissions the
// project declares in Config.OrgRoles. It's for admin tooling and seed
// scripts: unlike POST /v1/organizations/{id}/roles it doesn't check what
// the caller may grant. by is who's making the change, for the security
// event log.
func (a *Auth) CreateOrgRole(ctx context.Context, orgID uuid.UUID, name string, perms []rbac.Permission, by Actor) (OrgRole, error) {
	if a.orgRoles == nil {
		return OrgRole{}, errors.New("auth: CreateOrgRole needs Config.OrgRoles")
	}
	var role OrgRole
	err := a.withOrgLock(ctx, orgID, func(q *db.Queries) error {
		var err error
		role, err = a.createRole(ctx, q, orgID, name, perms, nil)
		return err
	})
	if err != nil {
		return OrgRole{}, orgRoleError("creating role", err)
	}
	a.adminEvent(ctx, by, Event{Type: EventOrgRoleCreated, Metadata: roleEventMetadata(orgID, role.Key, role.Permissions)})
	return role, nil
}

// UpdateOrgRole renames a role an organization defined, or replaces its
// permissions. Members with the role have the new permissions from their
// next request. Like CreateOrgRole, it doesn't check what the caller may
// grant. by is who's making the change, for the security event log.
func (a *Auth) UpdateOrgRole(ctx context.Context, orgID, roleID uuid.UUID, c OrgRoleChanges, by Actor) (OrgRole, error) {
	if a.orgRoles == nil {
		return OrgRole{}, errors.New("auth: UpdateOrgRole needs Config.OrgRoles")
	}
	var role OrgRole
	err := a.withOrgLock(ctx, orgID, func(q *db.Queries) error {
		var err error
		role, err = a.updateRole(ctx, q, orgID, roleID, c, nil)
		return err
	})
	if err != nil {
		return OrgRole{}, orgRoleError("updating role", err)
	}
	a.adminEvent(ctx, by, Event{Type: EventOrgRoleUpdated, Metadata: roleEventMetadata(orgID, role.Key, role.Permissions)})
	return role, nil
}

// DeleteOrgRole deletes a role an organization defined. It returns
// ErrRoleInUse while any member has it. by is who's deleting it, for the
// security event log.
func (a *Auth) DeleteOrgRole(ctx context.Context, orgID, roleID uuid.UUID, by Actor) error {
	if a.orgRoles == nil {
		return errors.New("auth: DeleteOrgRole needs Config.OrgRoles")
	}
	err := a.withOrgLock(ctx, orgID, func(q *db.Queries) error {
		return a.deleteRole(ctx, q, orgID, roleID, nil)
	})
	if err != nil {
		return orgRoleError("deleting role", err)
	}
	a.adminEvent(ctx, by, Event{Type: EventOrgRoleDeleted, Metadata: roleEventMetadata(orgID, CustomRoleKey(roleID), nil)})
	return nil
}

// ListOrgRoles returns the roles an organization defined, oldest first. An
// organization has at most 50.
func (a *Auth) ListOrgRoles(ctx context.Context, orgID uuid.UUID) ([]OrgRole, error) {
	rows, err := a.q.ListOrganizationRoles(ctx, db.ListOrganizationRolesParams{OrganizationID: orgID, MaxRows: orgRoleListCapacity})
	if err != nil {
		return nil, fmt.Errorf("auth: listing roles: %w", err)
	}
	out := make([]OrgRole, len(rows))
	for i, row := range rows {
		out[i] = a.orgRoleFromRow(row)
	}
	return out, nil
}

// The endpoints.

func (a *Auth) registerOrgRoles(mux *http.ServeMux) {
	mux.Handle("GET /v1/organizations/{id}/roles", endpoint(a.orgRoute(PermMembersRead, orgFromPath, http.HandlerFunc(a.listOrgRoles))))
	if a.managedElsewhere {
		return
	}
	mux.Handle("POST /v1/organizations/{id}/roles", endpoint(a.orgRoute(PermRolesManage, orgFromPath, http.HandlerFunc(a.createOrgRole))))
	mux.Handle("PATCH /v1/organizations/{id}/roles/{role_id}", endpoint(a.orgRoute(PermRolesManage, orgFromPath, http.HandlerFunc(a.updateOrgRole))))
	mux.Handle("DELETE /v1/organizations/{id}/roles/{role_id}", endpoint(a.orgRoute(PermRolesManage, orgFromPath, http.HandlerFunc(a.deleteOrgRole))))
}

type orgRoleJSON struct {
	ID          uuid.UUID `json:"id"`
	Key         string    `json:"key"`
	Name        string    `json:"name"`
	Permissions []string  `json:"permissions"`
	CreatedAt   timestamp `json:"created_at"`
	UpdatedAt   timestamp `json:"updated_at"`
}

func toOrgRoleJSON(r OrgRole) orgRoleJSON {
	return orgRoleJSON{ID: r.ID, Key: r.Key, Name: r.Name, Permissions: permStrings(r.Permissions), CreatedAt: timestamp(r.CreatedAt), UpdatedAt: timestamp(r.UpdatedAt)}
}

type orgRoleList struct {
	Data       []orgRoleJSON `json:"data"`
	NextCursor *string       `json:"next_cursor"`
}

// listOrgRoles lists the organization's own roles. There are at most 50,
// so it isn't paginated, but it keeps the standard list shape.
func (a *Auth) listOrgRoles(w http.ResponseWriter, r *http.Request) {
	c, _ := currentFrom(r.Context())
	roles, err := a.ListOrgRoles(r.Context(), c.org.ID)
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	list := orgRoleList{Data: make([]orgRoleJSON, len(roles))}
	for i, role := range roles {
		list.Data[i] = toOrgRoleJSON(role)
	}
	httpapi.WriteJSON(w, r, http.StatusOK, list)
}

type orgRoleRequest struct {
	Name        *string            `json:"name"`
	Permissions *[]rbac.Permission `json:"permissions"`
}

func (a *Auth) createOrgRole(w http.ResponseWriter, r *http.Request) {
	c, _ := currentFrom(r.Context())
	var req orgRoleRequest
	if err := httpapi.Decode(w, r, &req); err != nil {
		httpapi.WriteDecodeError(w, r, err)
		return
	}
	var details []httpapi.FieldError
	if req.Name == nil {
		details = append(details, httpapi.FieldError{Field: "name", Code: "required", Message: "Enter a name."})
	}
	if req.Permissions == nil {
		details = append(details, httpapi.FieldError{Field: "permissions", Code: "required", Message: "List the role's permissions."})
	}
	if details != nil {
		writeValidationFailed(w, r, details)
		return
	}
	var role OrgRole
	err := a.changeMembers(r.Context(), c.org.ID, func(q *db.Queries, actor orgRole) error {
		var err error
		role, err = a.createRole(r.Context(), q, c.org.ID, *req.Name, *req.Permissions, actorGuard(actor))
		return err
	}, c.user.ID, PermRolesManage)
	if a.writeOrgRoleError(w, r, err) {
		return
	}
	a.logEvent(r, "auth: organization role created", c.user.ID)
	a.event(r, EventOrgRoleCreated, nil, &c.user.ID, roleEventMetadata(c.org.ID, role.Key, role.Permissions))
	httpapi.WriteJSON(w, r, http.StatusCreated, toOrgRoleJSON(role))
}

func (a *Auth) updateOrgRole(w http.ResponseWriter, r *http.Request) {
	c, _ := currentFrom(r.Context())
	roleID, err := uuid.Parse(r.PathValue("role_id"))
	if err != nil {
		writeNotFound(w, r)
		return
	}
	var req orgRoleRequest
	if err := httpapi.Decode(w, r, &req); err != nil {
		httpapi.WriteDecodeError(w, r, err)
		return
	}
	changes := OrgRoleChanges{Name: req.Name}
	if req.Permissions != nil {
		changes.Permissions = *req.Permissions
		if changes.Permissions == nil {
			changes.Permissions = []rbac.Permission{}
		}
	}
	var role OrgRole
	err = a.changeMembers(r.Context(), c.org.ID, func(q *db.Queries, actor orgRole) error {
		var err error
		role, err = a.updateRole(r.Context(), q, c.org.ID, roleID, changes, actorGuard(actor))
		return err
	}, c.user.ID, PermRolesManage)
	if a.writeOrgRoleError(w, r, err) {
		return
	}
	a.logEvent(r, "auth: organization role changed", c.user.ID)
	a.event(r, EventOrgRoleUpdated, nil, &c.user.ID, roleEventMetadata(c.org.ID, role.Key, role.Permissions))
	httpapi.WriteJSON(w, r, http.StatusOK, toOrgRoleJSON(role))
}

func (a *Auth) deleteOrgRole(w http.ResponseWriter, r *http.Request) {
	c, _ := currentFrom(r.Context())
	roleID, err := uuid.Parse(r.PathValue("role_id"))
	if err != nil {
		writeNotFound(w, r)
		return
	}
	err = a.changeMembers(r.Context(), c.org.ID, func(q *db.Queries, actor orgRole) error {
		return a.deleteRole(r.Context(), q, c.org.ID, roleID, actorGuard(actor))
	}, c.user.ID, PermRolesManage)
	if a.writeOrgRoleError(w, r, err) {
		return
	}
	a.logEvent(r, "auth: organization role deleted", c.user.ID)
	a.event(r, EventOrgRoleDeleted, nil, &c.user.ID, roleEventMetadata(c.org.ID, CustomRoleKey(roleID), nil))
	w.WriteHeader(http.StatusNoContent)
}

// writeOrgRoleError writes the response for an error from a role
// endpoint, and reports whether there was one.
func (a *Auth) writeOrgRoleError(w http.ResponseWriter, r *http.Request, err error) bool {
	field := func(name, code, msg string) {
		writeValidationFailed(w, r, []httpapi.FieldError{{Field: name, Code: code, Message: msg}})
	}
	switch {
	case err == nil:
		return false
	case errors.Is(err, ErrRoleNotFound):
		writeNotFound(w, r)
	case errors.Is(err, ErrInvalidRoleName):
		field("name", "invalid_value", "Use 1 to 100 characters, and not the name of a built-in role.")
	case errors.Is(err, ErrRoleNameTaken):
		field("name", "taken", "This organization already has a role with this name.")
	case errors.Is(err, ErrUndeclaredPermission):
		field("permissions", "invalid_value", "Use only this app's permissions.")
	case errors.Is(err, ErrTooManyRoles):
		httpapi.WriteError(w, r, http.StatusConflict, "too_many_roles",
			"An organization can have at most 50 roles of its own, each with at most 100 permissions.", nil)
	case errors.Is(err, ErrRoleInUse):
		httpapi.WriteError(w, r, http.StatusConflict, "role_in_use",
			"Members have this role. Give them another role first.", nil)
	default:
		return a.writeMemberChangeError(w, r, err)
	}
	return true
}
