package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/atlasopsec/auth/internal/db"
	"github.com/atlasopsec/auth/internal/httpapi"
	"github.com/atlasopsec/auth/rbac"
)

// Permissions the module's own organization endpoints use. Projects give
// them to roles like any other permission; owners always have them.
const (
	PermOrganizationUpdate rbac.Permission = "organization:update"
	PermMembersRead        rbac.Permission = "members:read"
	PermMembersManage      rbac.Permission = "members:manage"
)

// maxOrgName matches the limit on auth.organizations.name.
const maxOrgName = 200

// Pagination limits, from the API design standard.
const (
	defaultPageSize = 20
	maxPageSize     = 100
)

// Organization is an organization. Projects keep their own data about it
// in their own tables, referencing auth.organizations(id).
type Organization struct {
	ID        uuid.UUID
	Name      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ErrInvalidOrgName is returned by CreateOrganization for a blank name, or
// one over 200 characters.
var ErrInvalidOrgName = errors.New("auth: organization name must be 1 to 200 characters")

// CreateOrganization creates an organization with ownerID as its owner.
// It's for apps that create organizations themselves, e.g. when a client
// signs up, typically with Config.DisableOrganizationCreation set.
func (a *Auth) CreateOrganization(ctx context.Context, name string, ownerID uuid.UUID) (Organization, error) {
	o, err := a.createOrg(ctx, name, ownerID)
	if err == nil {
		a.recordEvent(ctx, Event{Type: EventMemberAdded, UserID: &ownerID, Metadata: map[string]string{"organization_id": o.ID.String(), "role": OwnerRole}})
	}
	return o, err
}

func (a *Auth) createOrg(ctx context.Context, name string, ownerID uuid.UUID) (Organization, error) {
	if a.orgRoles == nil {
		return Organization{}, errors.New("auth: CreateOrganization needs Config.OrgRoles")
	}
	name = strings.TrimSpace(name)
	if !validOrgName(name) {
		return Organization{}, ErrInvalidOrgName
	}
	orgID, err := uuid.NewV7()
	if err != nil {
		return Organization{}, fmt.Errorf("auth: generating organization ID: %w", err)
	}
	membershipID, err := uuid.NewV7()
	if err != nil {
		return Organization{}, fmt.Errorf("auth: generating membership ID: %w", err)
	}

	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return Organization{}, fmt.Errorf("auth: beginning: %w", err)
	}
	// After Commit this is a no-op.
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	q := db.New(tx)
	now := a.now().UTC().Truncate(time.Microsecond)

	row, err := q.CreateOrganization(ctx, db.CreateOrganizationParams{ID: orgID, Name: name, Now: now})
	if err != nil {
		return Organization{}, fmt.Errorf("auth: creating organization: %w", err)
	}
	if err := q.CreateMembership(ctx, db.CreateMembershipParams{
		ID: membershipID, OrganizationID: orgID, UserID: ownerID, Role: OwnerRole, Now: now,
	}); err != nil {
		return Organization{}, fmt.Errorf("auth: adding owner: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Organization{}, fmt.Errorf("auth: committing: %w", err)
	}
	return orgFromRow(row), nil
}

func validOrgName(name string) bool {
	return name != "" && utf8.RuneCountInString(name) <= maxOrgName
}

func orgFromRow(r db.AuthOrganization) Organization {
	return Organization{ID: r.ID, Name: r.Name, CreatedAt: r.CreatedAt.UTC(), UpdatedAt: r.UpdatedAt.UTC()}
}

// registerOrganizations adds the organization endpoints. Apps without
// Config.OrgRoles don't get them.
func (a *Auth) registerOrganizations(mux *http.ServeMux) {
	if a.orgRoles == nil {
		return
	}
	if !a.disableOrgCreation {
		mux.Handle("POST /v1/organizations", endpoint(a.Authenticated(http.HandlerFunc(a.createOrganization))))
	}
	mux.Handle("GET /v1/organizations", endpoint(a.Authenticated(http.HandlerFunc(a.listOrganizations))))
	mux.Handle("GET /v1/organizations/{id}", endpoint(a.orgRoute("", orgFromPath, http.HandlerFunc(a.getOrganization))))
	mux.Handle("PATCH /v1/organizations/{id}", endpoint(a.orgRoute(PermOrganizationUpdate, orgFromPath, http.HandlerFunc(a.renameOrganization))))
	mux.Handle("GET /v1/organizations/{id}/members", endpoint(a.orgRoute(PermMembersRead, orgFromPath, http.HandlerFunc(a.listMembers))))
	mux.Handle("PATCH /v1/organizations/{id}/members/{user_id}", endpoint(a.orgRoute(PermMembersManage, orgFromPath, http.HandlerFunc(a.changeMemberRole))))
	// Leaving needs no permission, so this checks it in the handler.
	mux.Handle("DELETE /v1/organizations/{id}/members/{user_id}", endpoint(a.orgRoute("", orgFromPath, http.HandlerFunc(a.removeMember))))
	a.registerInvitations(mux)
}

type orgJSON struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	CreatedAt timestamp `json:"created_at"`
	UpdatedAt timestamp `json:"updated_at"`
}

func toOrgJSON(o Organization, role string) orgJSON {
	return orgJSON{ID: o.ID, Name: o.Name, Role: role, CreatedAt: timestamp(o.CreatedAt), UpdatedAt: timestamp(o.UpdatedAt)}
}

type orgNameRequest struct {
	Name string `json:"name"`
}

// decodeOrgName reads and checks an organization name, writing the error
// response if it's invalid.
func decodeOrgName(w http.ResponseWriter, r *http.Request) (string, bool) {
	var req orgNameRequest
	if err := httpapi.Decode(w, r, &req); err != nil {
		httpapi.WriteDecodeError(w, r, err)
		return "", false
	}
	name := strings.TrimSpace(req.Name)
	switch {
	case name == "":
		writeValidationFailed(w, r, []httpapi.FieldError{{Field: "name", Code: "required", Message: "Enter a name."}})
		return "", false
	case !validOrgName(name):
		writeValidationFailed(w, r, []httpapi.FieldError{{Field: "name", Code: "too_long", Message: "Names can be at most 200 characters."}})
		return "", false
	}
	return name, true
}

func (a *Auth) createOrganization(w http.ResponseWriter, r *http.Request) {
	c, _ := currentFrom(r.Context())
	name, ok := decodeOrgName(w, r)
	if !ok {
		return
	}
	if !c.user.EmailVerified {
		writeEmailNotVerified(w, r)
		return
	}
	o, err := a.createOrg(r.Context(), name, c.user.ID)
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	a.logEvent(r, "auth: organization created", c.user.ID)
	a.event(r, EventMemberAdded, &c.user.ID, nil, map[string]string{"organization_id": o.ID.String(), "role": OwnerRole})
	httpapi.WriteJSON(w, r, http.StatusCreated, toOrgJSON(o, OwnerRole))
}

type orgList struct {
	Data       []orgJSON `json:"data"`
	NextCursor *string   `json:"next_cursor"`
}

// listOrganizations lists the user's organizations. A user belongs to a
// handful, so it isn't paginated, but it keeps the standard list shape.
func (a *Auth) listOrganizations(w http.ResponseWriter, r *http.Request) {
	c, _ := currentFrom(r.Context())
	rows, err := a.q.ListUserOrganizations(r.Context(), c.user.ID)
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	list := orgList{Data: make([]orgJSON, len(rows))}
	for i, row := range rows {
		list.Data[i] = toOrgJSON(Organization{ID: row.ID, Name: row.Name, CreatedAt: row.CreatedAt.UTC(), UpdatedAt: row.UpdatedAt.UTC()}, row.Role)
	}
	httpapi.WriteJSON(w, r, http.StatusOK, list)
}

func (a *Auth) getOrganization(w http.ResponseWriter, r *http.Request) {
	c, _ := currentFrom(r.Context())
	row, err := a.q.GetMemberOrganization(r.Context(), db.GetMemberOrganizationParams{OrganizationID: c.org.ID, UserID: c.user.ID})
	if errors.Is(err, pgx.ErrNoRows) {
		// Removed since the membership check.
		writeNotFound(w, r)
		return
	}
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	o := Organization{ID: row.ID, Name: row.Name, CreatedAt: row.CreatedAt.UTC(), UpdatedAt: row.UpdatedAt.UTC()}
	httpapi.WriteJSON(w, r, http.StatusOK, toOrgJSON(o, row.Role))
}

func (a *Auth) renameOrganization(w http.ResponseWriter, r *http.Request) {
	c, _ := currentFrom(r.Context())
	name, ok := decodeOrgName(w, r)
	if !ok {
		return
	}
	row, err := a.q.RenameOrganization(r.Context(), db.RenameOrganizationParams{ID: c.org.ID, Name: name, Now: a.now().UTC().Truncate(time.Microsecond)})
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	httpapi.WriteJSON(w, r, http.StatusOK, toOrgJSON(orgFromRow(row), c.org.Role))
}

type memberJSON struct {
	UserID   uuid.UUID `json:"user_id"`
	Email    string    `json:"email"`
	Role     string    `json:"role"`
	JoinedAt timestamp `json:"joined_at"`
}

type memberList struct {
	Data       []memberJSON `json:"data"`
	NextCursor *string      `json:"next_cursor"`
}

func (a *Auth) listMembers(w http.ResponseWriter, r *http.Request) {
	c, _ := currentFrom(r.Context())
	limit, after, ok := pageParams(w, r)
	if !ok {
		return
	}
	rows, err := a.q.ListMembers(r.Context(), db.ListMembersParams{OrganizationID: c.org.ID, After: after, MaxRows: limit + 1})
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	list := memberList{Data: []memberJSON{}}
	for i, row := range rows {
		if i == int(limit) {
			next := base64.RawURLEncoding.EncodeToString(rows[i-1].ID[:])
			list.NextCursor = &next
			break
		}
		list.Data = append(list.Data, memberJSON{UserID: row.UserID, Email: row.Email, Role: row.Role, JoinedAt: timestamp(row.CreatedAt)})
	}
	httpapi.WriteJSON(w, r, http.StatusOK, list)
}

// pageParams reads the limit and cursor query parameters, writing the
// error response if they're invalid. The cursor is opaque to clients; it's
// the ID of the last item on the previous page.
func pageParams(w http.ResponseWriter, r *http.Request) (limit int32, after *uuid.UUID, ok bool) {
	limit = defaultPageSize
	var details []httpapi.FieldError
	if s := r.URL.Query().Get("limit"); s != "" {
		n, err := strconv.ParseInt(s, 10, 32)
		if err != nil || n < 1 || n > maxPageSize {
			details = append(details, httpapi.FieldError{Field: "limit", Code: "invalid_value", Message: "Use a limit from 1 to 100."})
		}
		limit = int32(n)
	}
	if s := r.URL.Query().Get("cursor"); s != "" {
		b, err := base64.RawURLEncoding.DecodeString(s)
		id, idErr := uuid.FromBytes(b)
		if err != nil || idErr != nil {
			details = append(details, httpapi.FieldError{Field: "cursor", Code: "invalid_value", Message: "Use the next_cursor from the previous page."})
		} else {
			after = &id
		}
	}
	if details != nil {
		writeValidationFailed(w, r, details)
		return 0, nil, false
	}
	return limit, after, true
}

type roleRequest struct {
	Role string `json:"role"`
}

// errLastOwner means a change would leave an organization without an
// owner.
var errLastOwner = errors.New("last owner")

// changeMemberRole changes a member's role. Nobody can grant a role with
// permissions they don't have themselves, change the role of someone with
// permissions they don't have, or make or unmake an owner unless they're
// an owner. Otherwise anyone with members:manage could promote themselves.
func (a *Auth) changeMemberRole(w http.ResponseWriter, r *http.Request) {
	c, _ := currentFrom(r.Context())
	target, err := uuid.Parse(r.PathValue("user_id"))
	if err != nil {
		writeNotFound(w, r)
		return
	}
	var req roleRequest
	if err := httpapi.Decode(w, r, &req); err != nil {
		httpapi.WriteDecodeError(w, r, err)
		return
	}
	if !a.orgRoles.Defines(req.Role) {
		writeValidationFailed(w, r, []httpapi.FieldError{{Field: "role", Code: "invalid_value", Message: "That isn't one of this app's roles."}})
		return
	}

	err = a.changeMembers(r.Context(), c.org.ID, func(q *db.Queries, actorRole string) error {
		m, err := q.GetMembership(r.Context(), db.GetMembershipParams{OrganizationID: c.org.ID, UserID: target})
		if err != nil {
			return err
		}
		if m.Role == req.Role {
			return nil
		}
		if !a.mayAssign(actorRole, m.Role) || !a.mayAssign(actorRole, req.Role) {
			return errForbidden
		}
		if m.Role == OwnerRole {
			if err := lastOwnerCheck(r.Context(), q, c.org.ID); err != nil {
				return err
			}
		}
		return q.SetMembershipRole(r.Context(), db.SetMembershipRoleParams{
			OrganizationID: c.org.ID, UserID: target, Role: req.Role, Now: a.now().UTC().Truncate(time.Microsecond),
		})
	}, c.user.ID)
	if a.writeMemberChangeError(w, r, err) {
		return
	}

	row, err := a.memberRow(r.Context(), c.org.ID, target)
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	a.logEvent(r, "auth: member role changed", c.user.ID)
	a.event(r, EventOrgRoleChanged, &target, &c.user.ID, map[string]string{"organization_id": c.org.ID.String(), "role": req.Role})
	httpapi.WriteJSON(w, r, http.StatusOK, row)
}

// removeMember removes a member, or lets a user leave with their own ID.
// Removing someone else needs members:manage and the same rules as
// changing their role.
func (a *Auth) removeMember(w http.ResponseWriter, r *http.Request) {
	c, _ := currentFrom(r.Context())
	target, err := uuid.Parse(r.PathValue("user_id"))
	if err != nil {
		writeNotFound(w, r)
		return
	}
	self := target == c.user.ID
	if !self && !Can(r.Context(), PermMembersManage) {
		writeForbidden(w, r)
		return
	}

	err = a.changeMembers(r.Context(), c.org.ID, func(q *db.Queries, actorRole string) error {
		m, err := q.GetMembership(r.Context(), db.GetMembershipParams{OrganizationID: c.org.ID, UserID: target})
		if err != nil {
			return err
		}
		if !self && !a.mayAssign(actorRole, m.Role) {
			return errForbidden
		}
		if m.Role == OwnerRole {
			if err := lastOwnerCheck(r.Context(), q, c.org.ID); err != nil {
				return err
			}
		}
		return q.DeleteMembership(r.Context(), db.DeleteMembershipParams{OrganizationID: c.org.ID, UserID: target})
	}, c.user.ID)
	if a.writeMemberChangeError(w, r, err) {
		return
	}
	a.logEvent(r, "auth: member removed", c.user.ID)
	a.event(r, EventMemberRemoved, &target, &c.user.ID, map[string]string{"organization_id": c.org.ID.String()})
	w.WriteHeader(http.StatusNoContent)
}

var errForbidden = errors.New("forbidden")

// changeMembers runs change in a transaction that holds the organization's
// lock, so concurrent changes can't leave it without an owner. change gets
// the actor's role as it is now, inside the lock.
func (a *Auth) changeMembers(ctx context.Context, orgID uuid.UUID, change func(q *db.Queries, actorRole string) error, actorID uuid.UUID) error {
	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning member change: %w", err)
	}
	// After Commit this is a no-op.
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	q := db.New(tx)
	if _, err := q.LockOrganization(ctx, orgID); err != nil {
		return err
	}
	actorRole, err := q.GetMembershipRole(ctx, db.GetMembershipRoleParams{OrganizationID: orgID, UserID: actorID})
	if err != nil {
		return err
	}
	if err := change(q, actorRole); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing member change: %w", err)
	}
	return nil
}

// writeMemberChangeError writes the response for an error from
// changeMembers, and reports whether there was one.
func (a *Auth) writeMemberChangeError(w http.ResponseWriter, r *http.Request, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, pgx.ErrNoRows):
		// The target isn't a member, or the organization or the actor's
		// membership went away meanwhile.
		writeNotFound(w, r)
	case errors.Is(err, errForbidden):
		writeForbidden(w, r)
	case errors.Is(err, errLastOwner):
		httpapi.WriteError(w, r, http.StatusConflict, "last_owner",
			"An organization needs at least one owner. Make someone else an owner first.", nil)
	default:
		httpapi.WriteInternalError(w, r, a.log, err)
	}
	return true
}

// lastOwnerCheck returns errLastOwner if the organization has only one
// owner. Call it under the organization's lock, before removing or
// demoting an owner.
func lastOwnerCheck(ctx context.Context, q *db.Queries, orgID uuid.UUID) error {
	n, err := q.CountOwners(ctx, db.CountOwnersParams{OrganizationID: orgID, OwnerRole: OwnerRole})
	if err != nil {
		return fmt.Errorf("counting owners: %w", err)
	}
	if n <= 1 {
		return errLastOwner
	}
	return nil
}

// mayAssign reports whether someone with actorRole may give a member
// role, or change the role of a member who has it: only owners may touch
// owners, and anyone else must already have every permission role grants.
// A role no longer defined in code grants nothing, so it's always covered.
func (a *Auth) mayAssign(actorRole, role string) bool {
	if actorRole == OwnerRole {
		return true
	}
	if role == OwnerRole {
		return false
	}
	for _, p := range a.orgRoles[role] {
		if p == rbac.All || !a.orgCan(actorRole, p) {
			return false
		}
	}
	return true
}

func (a *Auth) memberRow(ctx context.Context, orgID, userID uuid.UUID) (memberJSON, error) {
	m, err := a.q.GetMembership(ctx, db.GetMembershipParams{OrganizationID: orgID, UserID: userID})
	if err != nil {
		return memberJSON{}, fmt.Errorf("reading membership: %w", err)
	}
	u, err := a.q.GetUserByID(ctx, userID)
	if err != nil {
		return memberJSON{}, fmt.Errorf("reading member: %w", err)
	}
	return memberJSON{UserID: userID, Email: u.Email, Role: m.Role, JoinedAt: timestamp(m.CreatedAt)}, nil
}
