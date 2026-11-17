package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/atlasopsec/auth/rbac"
)

func TestInviteWithCustomRole(t *testing.T) {
	t.Parallel()
	f := setupRoles(t, Config{})
	tm := f.team(t)
	clerk := f.createRole(t, tm, OwnerRole, roleBody("Billing clerk", "invoices:read", "invoices:create"))

	res := f.invite(t, tm, OwnerRole, "new@example.com", clerk.Key)
	var inv struct {
		Role     string `json:"role"`
		RoleName string `json:"role_name"`
	}
	if res.status != http.StatusCreated || json.Unmarshal(res.body, &inv) != nil || inv.Role != clerk.Key || inv.RoleName != "Billing clerk" {
		t.Fatalf("inviting: status %d, body %s", res.status, res.body)
	}
	list := f.do(t, http.MethodGet, tm.path("/invitations"), "", withToken(tm.users[OwnerRole].Token))
	if !strings.Contains(string(list.body), `"role_name":"Billing clerk"`) {
		t.Errorf("invitations list: %s", list.body)
	}
	// Code roles show as themselves.
	f.invite(t, tm, OwnerRole, "plain@example.com", "member")
	list = f.do(t, http.MethodGet, tm.path("/invitations"), "", withToken(tm.users[OwnerRole].Token))
	if !strings.Contains(string(list.body), `"role":"member","role_name":"member"`) {
		t.Errorf("invitations list: %s", list.body)
	}

	tok := f.invitationToken(t, "new@example.com")
	u := f.user(t, "new@example.com")
	res = f.accept(t, u.Token, tok)
	if res.status != http.StatusOK || !strings.Contains(string(res.body), `"role_name":"Billing clerk"`) {
		t.Fatalf("accepting: status %d, body %s", res.status, res.body)
	}
	if got := f.roleOf(t, tm.org, u.User.ID); got != clerk.Key {
		t.Errorf("membership role %q, want %q", got, clerk.Key)
	}
	if res := f.do(t, http.MethodPost, "/v1/invoices", "", withToken(u.Token), inOrg(tm.org)); res.status != http.StatusOK {
		t.Errorf("invoices:create with the role: status %d", res.status)
	}
	// It counts as in use now.
	wantError(t, "deleting the role", f.do(t, http.MethodDelete, tm.path("/roles/"+clerk.ID.String()), "", withToken(tm.users[OwnerRole].Token)), 409, "role_in_use")
}

func TestInviteWithCustomRoleCantEscalate(t *testing.T) {
	t.Parallel()
	f := setupRoles(t, Config{})
	tm := f.team(t)
	// The manager has members:manage and invoices:read, but not
	// invoices:delete.
	reader := f.createRole(t, tm, OwnerRole, roleBody("Reader", "invoices:read"))
	deleter := f.createRole(t, tm, OwnerRole, roleBody("Deleter", "invoices:read", "invoices:delete"))

	wantError(t, "inviting with a role they can't grant", f.invite(t, tm, "manager", "a@example.com", deleter.Key), 403, "forbidden")
	if res := f.invite(t, tm, "manager", "b@example.com", reader.Key); res.status != http.StatusCreated {
		t.Errorf("inviting with a role within their permissions: status %d, body %s", res.status, res.body)
	}

	// Nor can they cancel, or replace, an invitation for one.
	if res := f.invite(t, tm, OwnerRole, "c@example.com", deleter.Key); res.status != http.StatusCreated {
		t.Fatal(res.status)
	}
	var id string
	if err := f.pool.QueryRow(context.Background(), `SELECT id FROM auth.invitations WHERE email = 'c@example.com'`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	wantError(t, "cancelling", f.do(t, http.MethodDelete, tm.path("/invitations/"+id), "", withToken(tm.users["manager"].Token)), 403, "forbidden")
	f.clock.advance(2 * 60e9)
	wantError(t, "replacing", f.invite(t, tm, "manager", "c@example.com", reader.Key), 403, "forbidden")
}

func TestInviteWithCustomRoleRejects(t *testing.T) {
	t.Parallel()
	f := setupRoles(t, Config{})
	ctx := context.Background()
	tm := f.team(t)
	other := f.user(t, "other-owner@example.com")
	otherOrg := f.createOrg(t, other.Token, "Other").ID
	theirs, err := f.auth.CreateOrgRole(ctx, otherOrg, "Theirs", []rbac.Permission{"invoices:read"}, Actor{})
	if err != nil {
		t.Fatal(err)
	}
	wantError(t, "another organization's role", f.invite(t, tm, OwnerRole, "a@example.com", theirs.Key), 422, "validation_failed")
	wantError(t, "no such role", f.invite(t, tm, OwnerRole, "a@example.com", CustomRoleKey(uuid.New())), 422, "validation_failed")
	wantError(t, "malformed key", f.invite(t, tm, OwnerRole, "a@example.com", "custom:nope"), 422, "validation_failed")

	// The database refuses it too, whatever the code does.
	_, err = f.pool.Exec(ctx, `INSERT INTO auth.invitations (id, organization_id, email, role, custom_role_id, token_hash, invited_by, expires_at)
		VALUES ($1, $2, 'b@example.com', $3, $4, $5, $6, now() + interval '1 day')`,
		uuid.New(), tm.org, theirs.Key, theirs.ID, make([]byte, 32), tm.users[OwnerRole].User.ID)
	if err == nil || !strings.Contains(err.Error(), "invitations_custom_role_fkey") {
		t.Errorf("storing another organization's role: %v, want the foreign key to refuse it", err)
	}
}

// TestCustomRoleChangedAfterInviting covers a role that changes between
// the invitation and its acceptance: it's checked as it is when accepted.
func TestCustomRoleChangedAfterInviting(t *testing.T) {
	t.Parallel()
	f := setupRoles(t, Config{})
	tm := f.team(t)
	owner := tm.users[OwnerRole].Token

	// Widened past what its sender, the manager, holds: no use.
	widened := f.createRole(t, tm, OwnerRole, roleBody("Reader", "invoices:read"))
	if res := f.invite(t, tm, "manager", "a@example.com", widened.Key); res.status != http.StatusCreated {
		t.Fatal(res.status)
	}
	if res := f.do(t, http.MethodPatch, tm.path("/roles/"+widened.ID.String()), `{"permissions":["invoices:read","invoices:delete"]}`, withToken(owner)); res.status != http.StatusOK {
		t.Fatal(res.status)
	}
	aTok := f.invitationToken(t, "a@example.com")
	a := f.user(t, "a@example.com")
	wantError(t, "accepting a widened role", f.accept(t, a.Token, aTok), 422, "token_invalid_or_expired")
	if got := f.roleOf(t, tm.org, a.User.ID); got != "" {
		t.Errorf("joined with role %q", got)
	}

	// Deleted: the role's pending invitations go with it, so it isn't
	// kept in use by them.
	gone := f.createRole(t, tm, OwnerRole, roleBody("Temporary", "invoices:read"))
	if res := f.invite(t, tm, OwnerRole, "b@example.com", gone.Key); res.status != http.StatusCreated {
		t.Fatal(res.status)
	}
	if res := f.do(t, http.MethodDelete, tm.path("/roles/"+gone.ID.String()), "", withToken(owner)); res.status != http.StatusNoContent {
		t.Fatalf("deleting a role with a pending invitation: status %d, body %s", res.status, res.body)
	}
	bTok := f.invitationToken(t, "b@example.com")
	b := f.user(t, "b@example.com")
	wantError(t, "accepting a deleted role", f.accept(t, b.Token, bTok), 422, "token_invalid_or_expired")
}
