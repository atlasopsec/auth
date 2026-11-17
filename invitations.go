package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/atlasopsec/auth/internal/db"
	"github.com/atlasopsec/auth/internal/emailtoken"
	"github.com/atlasopsec/auth/internal/httpapi"
	"github.com/atlasopsec/auth/internal/token"
)

// InvitationLifetime is how long an invitation link works.
const InvitationLifetime = 7 * 24 * time.Hour

func (a *Auth) registerInvitations(mux *http.ServeMux) {
	mux.Handle("POST /v1/organizations/{id}/invitations", endpoint(a.orgRoute(PermMembersManage, orgFromPath, a.limitIP(limitEmailIP, http.HandlerFunc(a.invite)))))
	mux.Handle("GET /v1/organizations/{id}/invitations", endpoint(a.orgRoute(PermMembersManage, orgFromPath, http.HandlerFunc(a.listInvitations))))
	mux.Handle("DELETE /v1/organizations/{id}/invitations/{invitation_id}", endpoint(a.orgRoute(PermMembersManage, orgFromPath, http.HandlerFunc(a.cancelInvitation))))
	mux.Handle("POST /v1/invitations/accept", endpoint(a.Authenticated(http.HandlerFunc(a.acceptInvitation))))
}

type invitationJSON struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	RoleName  string    `json:"role_name"`
	InvitedBy uuid.UUID `json:"invited_by"`
	ExpiresAt timestamp `json:"expires_at"`
	CreatedAt timestamp `json:"created_at"`
}

func toInvitationJSON(r db.AuthInvitation, roleName string) invitationJSON {
	return invitationJSON{ID: r.ID, Email: r.Email, Role: r.Role, RoleName: roleName, InvitedBy: r.InvitedBy, ExpiresAt: timestamp(r.ExpiresAt), CreatedAt: timestamp(r.CreatedAt)}
}

type inviteRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

// invite emails an invitation to join the organization. The usual
// no-escalation rule applies to the role, and inviting the same address
// again replaces the earlier invitation, at most once a minute, if you
// could have cancelled it.
func (a *Auth) invite(w http.ResponseWriter, r *http.Request) {
	c, _ := currentFrom(r.Context())
	var req inviteRequest
	if err := httpapi.Decode(w, r, &req); err != nil {
		httpapi.WriteDecodeError(w, r, err)
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	var details []httpapi.FieldError
	if fe, ok := checkEmail(req.Email); !ok {
		details = append(details, fe)
	}
	// A role defined in code, or one of this organization's own. The
	// lookup filters by organization, so another's isn't found.
	target, err := a.roleByKey(r.Context(), a.q, c.org.ID, req.Role)
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	if !target.defined {
		details = append(details, httpapi.FieldError{Field: "role", Code: "invalid_value", Message: "That isn't one of this organization's roles."})
	}
	if details != nil {
		writeValidationFailed(w, r, details)
		return
	}
	if !mayAssign(c.role, target) {
		writeForbidden(w, r)
		return
	}
	if !a.allowEmailTo(w, r, req.Email) {
		return
	}

	ctx := r.Context()
	member, err := a.q.IsMemberByEmail(ctx, db.IsMemberByEmailParams{OrganizationID: c.org.ID, Email: req.Email})
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	if member {
		httpapi.WriteError(w, r, http.StatusConflict, "already_member", "That person is already a member.", nil)
		return
	}

	inv, tok, err := a.createInvitation(ctx, c.org.ID, c.user.ID, req.Email, req.Role)
	if a.writeMemberChangeError(w, r, err) {
		return
	}
	roleName, err := a.roleName(ctx, a.q, c.org.ID, inv.Role)
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	if tok != "" {
		org, err := a.q.GetMemberOrganization(ctx, db.GetMemberOrganizationParams{OrganizationID: c.org.ID, UserID: c.user.ID})
		if err != nil {
			httpapi.WriteInternalError(w, r, a.log, err)
			return
		}
		a.send(inv.Email, a.emails.Invitation, EmailData{
			AppName:   a.appName,
			AppURL:    a.appURL,
			Link:      a.appURL + "/accept-invitation#token=" + tok,
			ExpiresIn: InvitationLifetime,
			OrgName:   org.Name,
		}, inv.ID)
		a.logEvent(r, "auth: member invited", c.user.ID)
	}
	httpapi.WriteJSON(w, r, http.StatusCreated, toInvitationJSON(inv, roleName))
}

// createInvitation replaces any pending invitation for the address with a
// new one, and returns it with its token. Within the cooldown it returns
// the pending invitation unchanged and no token, so nothing is sent.
//
// It runs under the organization's lock and checks again there that the
// inviter still has members:manage and may give the role. Replacing an
// earlier invitation cancels it, so the inviter must also be allowed to
// cancel that one: otherwise re-inviting an address would replace an
// owner's invitation for a role the inviter couldn't grant. It returns
// errForbidden if not.
func (a *Auth) createInvitation(ctx context.Context, orgID, inviter uuid.UUID, email, role string) (db.AuthInvitation, string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return db.AuthInvitation{}, "", fmt.Errorf("generating invitation ID: %w", err)
	}
	var (
		inv db.AuthInvitation
		tok string
	)
	err = a.changeMembers(ctx, orgID, func(q *db.Queries, actor orgRole) error {
		// Read again under the lock: a custom role may have been changed
		// or deleted since.
		target, err := a.roleByKey(ctx, q, orgID, role)
		if err != nil {
			return err
		}
		if !target.defined {
			return errUnknownRole
		}
		if !mayAssign(actor, target) {
			return errForbidden
		}
		now := a.now().UTC().Truncate(time.Microsecond)
		prev, err := q.GetPendingInvitationForEmail(ctx, db.GetPendingInvitationForEmailParams{OrganizationID: orgID, Email: email})
		switch {
		case errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			return fmt.Errorf("finding invitation: %w", err)
		case now.Sub(prev.CreatedAt) < emailtoken.Cooldown:
			inv = prev
			return nil
		default:
			prevRole, err := a.roleByKey(ctx, q, orgID, prev.Role)
			if err != nil {
				return err
			}
			if !mayAssign(actor, prevRole) {
				return errForbidden
			}
			if err := q.DeleteInvitation(ctx, prev.ID); err != nil {
				return fmt.Errorf("replacing invitation: %w", err)
			}
		}

		tok = token.New()
		inv, err = q.CreateInvitation(ctx, db.CreateInvitationParams{
			ID:             id,
			OrganizationID: orgID,
			Email:          email,
			Role:           role,
			CustomRoleID:   customRoleIDOf(target),
			TokenHash:      token.Hash(tok),
			InvitedBy:      inviter,
			ExpiresAt:      now.Add(InvitationLifetime),
			Now:            now,
		})
		if err != nil {
			return fmt.Errorf("creating invitation: %w", err)
		}
		return nil
	}, inviter, PermMembersManage)
	if err != nil {
		return db.AuthInvitation{}, "", err
	}
	return inv, tok, nil
}

type invitationList struct {
	Data       []invitationJSON `json:"data"`
	NextCursor *string          `json:"next_cursor"`
}

func (a *Auth) listInvitations(w http.ResponseWriter, r *http.Request) {
	c, _ := currentFrom(r.Context())
	limit, after, ok := pageParams(w, r)
	if !ok {
		return
	}
	rows, err := a.q.ListPendingInvitations(r.Context(), db.ListPendingInvitationsParams{
		OrganizationID: c.org.ID, After: after, MaxRows: limit + 1, Now: a.now().UTC(),
	})
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	list := invitationList{Data: []invitationJSON{}}
	for i, row := range rows {
		if i == int(limit) {
			next := base64.RawURLEncoding.EncodeToString(rows[i-1].AuthInvitation.ID[:])
			list.NextCursor = &next
			break
		}
		list.Data = append(list.Data, toInvitationJSON(row.AuthInvitation, row.RoleName))
	}
	httpapi.WriteJSON(w, r, http.StatusOK, list)
}

// cancelInvitation deletes a pending invitation. Cancelling one for a role
// you couldn't grant yourself is forbidden, like granting it.
func (a *Auth) cancelInvitation(w http.ResponseWriter, r *http.Request) {
	c, _ := currentFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("invitation_id"))
	if err != nil {
		writeNotFound(w, r)
		return
	}
	inv, err := a.q.GetPendingInvitationInOrganization(r.Context(), db.GetPendingInvitationInOrganizationParams{OrganizationID: c.org.ID, ID: id})
	if errors.Is(err, pgx.ErrNoRows) {
		writeNotFound(w, r)
		return
	}
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	role, err := a.roleByKey(r.Context(), a.q, c.org.ID, inv.Role)
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	if !mayAssign(c.role, role) {
		writeForbidden(w, r)
		return
	}
	if err := a.q.DeleteInvitation(r.Context(), inv.ID); err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type acceptRequest struct {
	Token string `json:"token"`
}

var (
	errEmailMismatch     = errors.New("invitation email mismatch")
	errAlreadyMember     = errors.New("already a member")
	errInvitationInvalid = errors.New("invitation invalid")
)

// acceptInvitation adds the logged-in user to the invitation's
// organization. The user's verified email must match the invitation, so a
// forwarded link doesn't let someone else in.
func (a *Auth) acceptInvitation(w http.ResponseWriter, r *http.Request) {
	c, _ := currentFrom(r.Context())
	var req acceptRequest
	if err := httpapi.Decode(w, r, &req); err != nil {
		httpapi.WriteDecodeError(w, r, err)
		return
	}
	if req.Token == "" {
		writeValidationFailed(w, r, []httpapi.FieldError{{Field: "token", Code: "required", Message: "The link is missing its token."}})
		return
	}
	if !token.Valid(req.Token) {
		writeTokenInvalid(w, r)
		return
	}

	org, invitedBy, err := a.accept(r.Context(), req.Token, c.user)
	switch {
	case errors.Is(err, errInvitationInvalid):
		writeTokenInvalid(w, r)
	case errors.Is(err, errEmailMismatch):
		httpapi.WriteError(w, r, http.StatusForbidden, "invitation_email_mismatch",
			"This invitation was sent to a different email address. Log in with that address to accept it.", nil)
	case errors.Is(err, errEmailNotVerifiedForInvite):
		writeEmailNotVerified(w, r)
	case errors.Is(err, errAlreadyMember):
		httpapi.WriteError(w, r, http.StatusConflict, "already_member", "You're already a member of this organization.", nil)
	case err != nil:
		httpapi.WriteInternalError(w, r, a.log, err)
	default:
		a.logEvent(r, "auth: invitation accepted", c.user.ID)
		a.event(r, EventMemberAdded, &c.user.ID, &invitedBy, map[string]string{"organization_id": org.ID.String(), "role": org.Role})
		httpapi.WriteJSON(w, r, http.StatusOK, org)
	}
}

var errEmailNotVerifiedForInvite = errors.New("email not verified")

// accept checks and spends the invitation and adds the membership, all or
// nothing. It returns the organization as the new member sees it.
func (a *Auth) accept(ctx context.Context, tok string, u User) (orgJSON, uuid.UUID, error) {
	inv, err := a.q.GetInvitationByTokenHash(ctx, token.Hash(tok))
	if errors.Is(err, pgx.ErrNoRows) {
		return orgJSON{}, uuid.UUID{}, errInvitationInvalid
	}
	if err != nil {
		return orgJSON{}, uuid.UUID{}, fmt.Errorf("finding invitation: %w", err)
	}
	now := a.now().UTC().Truncate(time.Microsecond)
	if inv.AcceptedAt != nil || !now.Before(inv.ExpiresAt) {
		return orgJSON{}, uuid.UUID{}, errInvitationInvalid
	}
	if !strings.EqualFold(inv.Email, u.Email) {
		return orgJSON{}, uuid.UUID{}, errEmailMismatch
	}
	if !u.EmailVerified {
		return orgJSON{}, uuid.UUID{}, errEmailNotVerifiedForInvite
	}
	membershipID, err := uuid.NewV7()
	if err != nil {
		return orgJSON{}, uuid.UUID{}, fmt.Errorf("generating membership ID: %w", err)
	}

	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return orgJSON{}, uuid.UUID{}, fmt.Errorf("beginning acceptance: %w", err)
	}
	// After Commit this is a no-op.
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	q := db.New(tx)
	role, err := a.inviterStillMay(ctx, q, inv)
	if err != nil {
		return orgJSON{}, uuid.UUID{}, err
	}
	n, err := q.AcceptInvitation(ctx, db.AcceptInvitationParams{ID: inv.ID, Now: &now})
	if err != nil {
		return orgJSON{}, uuid.UUID{}, fmt.Errorf("accepting invitation: %w", err)
	}
	if n == 0 {
		// Used or cancelled by a concurrent request.
		return orgJSON{}, uuid.UUID{}, errInvitationInvalid
	}
	err = q.CreateMembership(ctx, db.CreateMembershipParams{
		ID: membershipID, OrganizationID: inv.OrganizationID, UserID: u.ID, Role: inv.Role, CustomRoleID: customRoleIDOf(role), Now: now,
	})
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == "23505" && pgErr.ConstraintName == "memberships_organization_user_key" {
		return orgJSON{}, uuid.UUID{}, errAlreadyMember
	}
	if err != nil {
		return orgJSON{}, uuid.UUID{}, fmt.Errorf("adding member: %w", err)
	}
	row, err := q.GetMemberOrganization(ctx, db.GetMemberOrganizationParams{OrganizationID: inv.OrganizationID, UserID: u.ID})
	if err != nil {
		return orgJSON{}, uuid.UUID{}, fmt.Errorf("reading organization: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return orgJSON{}, uuid.UUID{}, fmt.Errorf("committing acceptance: %w", err)
	}
	return toOrgJSON(Organization{ID: row.ID, Name: row.Name, CreatedAt: row.CreatedAt.UTC(), UpdatedAt: row.UpdatedAt.UTC()}, row.Role, row.RoleName), inv.InvitedBy, nil
}

// inviterStillMay returns the role inv gives, as it is now, or
// errInvitationInvalid unless whoever sent inv is still a member who could
// send it now. An invitation from someone since removed or demoted would
// otherwise still let a person in with a role the organization has taken
// away from its sender. So would one for a custom role widened since, past
// what its sender holds. A role removed from code, or deleted, grants
// nothing, so its invitation is no use either. It holds the organization's
// lock, so it can't miss a change made at the same time.
func (a *Auth) inviterStillMay(ctx context.Context, q *db.Queries, inv db.AuthInvitation) (orgRole, error) {
	if _, err := q.LockOrganization(ctx, inv.OrganizationID); errors.Is(err, pgx.ErrNoRows) {
		return orgRole{}, errInvitationInvalid
	} else if err != nil {
		return orgRole{}, fmt.Errorf("locking organization: %w", err)
	}
	target, err := a.roleByKey(ctx, q, inv.OrganizationID, inv.Role)
	if err != nil {
		return orgRole{}, err
	}
	if !target.defined {
		return orgRole{}, errInvitationInvalid
	}
	inviter, err := a.memberRole(ctx, q, inv.OrganizationID, inv.InvitedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return orgRole{}, errInvitationInvalid
	}
	if err != nil {
		return orgRole{}, fmt.Errorf("reading inviter's role: %w", err)
	}
	if !inviter.can(PermMembersManage) || !mayAssign(inviter, target) {
		return orgRole{}, errInvitationInvalid
	}
	return target, nil
}
