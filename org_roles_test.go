package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/atlasopsec/auth/rbac"
)

var rolesTestRoles = rbac.Roles{
	OwnerRole: {rbac.All},
	"admin":   {PermOrganizationUpdate, PermMembersRead, PermMembersManage, PermRolesManage, "invoices:read", "invoices:create"},
	"manager": {PermMembersRead, PermMembersManage, PermRolesManage, "invoices:read"},
	"member":  {PermMembersRead, "invoices:read"},
	"viewer":  {"invoices:read"},
	"billing": {"invoices:read", "invoices:create", "invoices:delete"},
}

// setupRoles is an organization fixture whose project routes check
// invoice permissions, to see what custom roles grant.
func setupRoles(t *testing.T, cfg Config) orgFixture {
	t.Helper()
	cfg.AllowUnverifiedLogin = true
	if cfg.OrgRoles == nil {
		cfg.OrgRoles = rolesTestRoles
	}
	cfg.AppRoles = testAppRoles
	return orgFixture{setupAccessWith(t, cfg)}
}

type roleResponse struct {
	ID          uuid.UUID `json:"id"`
	Key         string    `json:"key"`
	Name        string    `json:"name"`
	Permissions []string  `json:"permissions"`
}

func (f orgFixture) createRole(t *testing.T, tm team, actor, body string) roleResponse {
	t.Helper()
	res := f.do(t, http.MethodPost, tm.path("/roles"), body, withToken(tm.users[actor].Token))
	if res.status != http.StatusCreated {
		t.Fatalf("creating role as %s: status %d, body %s", actor, res.status, res.body)
	}
	var r roleResponse
	if err := json.Unmarshal(res.body, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func roleBody(name string, perms ...string) string {
	if perms == nil {
		perms = []string{}
	}
	b, _ := json.Marshal(map[string]any{"name": name, "permissions": perms})
	return string(b)
}

func TestOrgRoles(t *testing.T) {
	t.Parallel()
	f := setupRoles(t, Config{})
	tm := f.team(t)
	owner, viewer := tm.users[OwnerRole], tm.users["viewer"]

	role := f.createRole(t, tm, OwnerRole, roleBody("  Clerk ", "invoices:create", "invoices:read", "invoices:read"))
	if role.Name != "Clerk" || role.Key != CustomRoleKey(role.ID) || !cmp.Equal(role.Permissions, []string{"invoices:create", "invoices:read"}) {
		t.Errorf("created %+v, want Clerk with its sorted permissions", role)
	}
	var list struct {
		Data       []roleResponse `json:"data"`
		NextCursor *string        `json:"next_cursor"`
	}
	res := f.do(t, http.MethodGet, tm.path("/roles"), "", withToken(tm.users["member"].Token))
	if err := json.Unmarshal(res.body, &list); err != nil || len(list.Data) != 1 || list.Data[0].ID != role.ID {
		t.Errorf("list: status %d, body %s", res.status, res.body)
	}
	wantError(t, "list without members:read", f.do(t, http.MethodGet, tm.path("/roles"), "", withToken(viewer.Token)), 403, "forbidden")

	// Given to a member, it grants its permissions and nothing more.
	if res := f.setRole(t, tm, OwnerRole, viewer.User.ID, role.Key); res.status != http.StatusOK || !strings.Contains(string(res.body), role.Key) {
		t.Fatalf("assigning: status %d, body %s", res.status, res.body)
	}
	if res := f.do(t, http.MethodPost, "/v1/invoices", "", withToken(viewer.Token), inOrg(tm.org)); res.status != http.StatusOK {
		t.Errorf("invoices:create with the role: status %d", res.status)
	}
	seen := f.seen(t, f.do(t, http.MethodGet, "/v1/invoices", "", withToken(viewer.Token), inOrg(tm.org)))
	if seen["org_role"] != role.Key || seen["can_delete"] != false {
		t.Errorf("handler saw %v, want the role key and no invoices:delete", seen)
	}

	// Changes apply on the member's next request.
	res = f.do(t, http.MethodPatch, tm.path("/roles/"+role.ID.String()), `{"permissions":["invoices:read","invoices:delete"]}`, withToken(owner.Token))
	if res.status != http.StatusOK {
		t.Fatalf("updating: status %d, body %s", res.status, res.body)
	}
	if seen := f.seen(t, f.do(t, http.MethodGet, "/v1/invoices", "", withToken(viewer.Token), inOrg(tm.org))); seen["can_delete"] != true {
		t.Errorf("after adding invoices:delete, handler saw %v", seen)
	}
	if res := f.do(t, http.MethodPost, "/v1/invoices", "", withToken(viewer.Token), inOrg(tm.org)); res.status != http.StatusForbidden {
		t.Errorf("invoices:create after it was removed: status %d", res.status)
	}
	if res := f.do(t, http.MethodPatch, tm.path("/roles/"+role.ID.String()), `{"name":"Accounts"}`, withToken(owner.Token)); res.status != http.StatusOK || !strings.Contains(string(res.body), `"Accounts"`) {
		t.Errorf("renaming: status %d, body %s", res.status, res.body)
	}

	// In use, it can't be deleted.
	wantError(t, "deleting a role in use", f.do(t, http.MethodDelete, tm.path("/roles/"+role.ID.String()), "", withToken(owner.Token)), 409, "role_in_use")
	if res := f.setRole(t, tm, OwnerRole, viewer.User.ID, "viewer"); res.status != http.StatusOK {
		t.Fatal(res.status)
	}
	if res := f.do(t, http.MethodDelete, tm.path("/roles/"+role.ID.String()), "", withToken(owner.Token)); res.status != http.StatusNoContent {
		t.Fatalf("deleting: status %d, body %s", res.status, res.body)
	}
	wantError(t, "deleting again", f.do(t, http.MethodDelete, tm.path("/roles/"+role.ID.String()), "", withToken(owner.Token)), 404, "not_found")
	wantError(t, "assigning a deleted role", f.setRole(t, tm, OwnerRole, viewer.User.ID, role.Key), 422, "validation_failed")

	var got []string
	for _, e := range f.roleEvents(t) {
		if e.ActorID == nil || *e.ActorID != owner.User.ID {
			t.Errorf("%s has actor %v, want the owner", e.Type, e.ActorID)
		}
		got = append(got, strings.ReplaceAll(strings.ReplaceAll(summary(e), role.Key, "KEY"), tm.org.String(), "ORG"))
	}
	want := []string{
		"org_role_created organization_id=ORG permissions=invoices:create,invoices:read role=KEY",
		"org_role_updated organization_id=ORG permissions=invoices:delete,invoices:read role=KEY",
		"org_role_updated organization_id=ORG permissions=invoices:delete,invoices:read role=KEY",
		"org_role_deleted organization_id=ORG role=KEY",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("role events (-want +got):\n%s", diff)
	}
}

// roleEvents returns the role definition events, oldest first.
func (f orgFixture) roleEvents(t *testing.T) []Event {
	t.Helper()
	rows, err := f.pool.Query(context.Background(), `SELECT event, actor_id, metadata FROM auth.auth_events WHERE event LIKE 'org_role_%' AND event <> 'org_role_changed' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.Type, &e.ActorID, &e.Metadata); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

func TestOrgRolesCantEscalate(t *testing.T) {
	t.Parallel()
	f := setupRoles(t, Config{})
	tm := f.team(t)
	manager := tm.users["manager"]
	// The manager has roles:manage, members:manage, members:read, and
	// invoices:read, but not invoices:create or invoices:delete.
	mine := f.createRole(t, tm, "manager", roleBody("Reader", "invoices:read"))
	big := f.createRole(t, tm, OwnerRole, roleBody("Accounts", "invoices:read", "invoices:delete"))

	tests := []struct {
		name, method, path, body string
	}{
		{"create with a permission they lack", http.MethodPost, "/roles", roleBody("Clerk", "invoices:create")},
		{"create with every permission", http.MethodPost, "/roles", roleBody("Everything", "*")},
		{"add a permission they lack to their own role", http.MethodPatch, "/roles/" + mine.ID.String(), `{"permissions":["invoices:read","invoices:delete"]}`},
		{"rename a role with permissions they lack", http.MethodPatch, "/roles/" + big.ID.String(), `{"name":"Renamed"}`},
		{"narrow a role with permissions they lack", http.MethodPatch, "/roles/" + big.ID.String(), `{"permissions":["invoices:read"]}`},
		{"delete a role with permissions they lack", http.MethodDelete, "/roles/" + big.ID.String(), ""},
	}
	for _, tt := range tests {
		res := f.do(t, tt.method, tm.path(tt.path), tt.body, withToken(manager.Token))
		if tt.body != "" && strings.Contains(tt.body, `"*"`) {
			wantError(t, tt.name, res, 422, "validation_failed")
			continue
		}
		wantError(t, tt.name, res, 403, "forbidden")
	}

	// Nor can they hand out such a role, to anyone or themselves.
	wantError(t, "assign it", f.setRole(t, tm, "manager", tm.users["viewer"].User.ID, big.Key), 403, "forbidden")
	wantError(t, "assign it to themselves", f.setRole(t, tm, "manager", manager.User.ID, big.Key), 403, "forbidden")
	// Or take it from someone who has it.
	if res := f.setRole(t, tm, OwnerRole, tm.users["member"].User.ID, big.Key); res.status != http.StatusOK {
		t.Fatal(res.status)
	}
	wantError(t, "change the role of someone who has it", f.setRole(t, tm, "manager", tm.users["member"].User.ID, "viewer"), 403, "forbidden")
	wantError(t, "remove someone who has it", f.do(t, http.MethodDelete, tm.path("/members/"+tm.users["member"].User.ID.String()), "", withToken(manager.Token)), 403, "forbidden")

	// Without roles:manage there's no role editing at all.
	wantError(t, "member creating", f.do(t, http.MethodPost, tm.path("/roles"), roleBody("Mine", "invoices:read"), withToken(tm.users["member"].Token)), 403, "forbidden")

	// Within what they hold, they can.
	if res := f.setRole(t, tm, "manager", tm.users["viewer"].User.ID, mine.Key); res.status != http.StatusOK {
		t.Errorf("assigning a role within their permissions: status %d, body %s", res.status, res.body)
	}

	// Nothing changed.
	roles, err := f.auth.ListOrgRoles(context.Background(), tm.org)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range roles {
		if r.ID == big.ID && (r.Name != "Accounts" || len(r.Permissions) != 2) || r.ID == mine.ID && len(r.Permissions) != 1 {
			t.Errorf("role changed by refused requests: %+v", r)
		}
	}
}

func TestOrgRolesValidation(t *testing.T) {
	t.Parallel()
	f := setupRoles(t, Config{})
	tm := f.team(t)
	f.createRole(t, tm, OwnerRole, roleBody("Clerk", "invoices:read"))
	tests := []struct {
		name, body, field string
	}{
		{"no name", `{"permissions":[]}`, "name"},
		{"no permissions", `{"name":"x"}`, "permissions"},
		{"blank name", roleBody("  "), "name"},
		{"long name", roleBody(strings.Repeat("a", 101)), "name"},
		{"a code role's name", roleBody("Owner"), "name"},
		{"another code role's name", roleBody("ADMIN"), "name"},
		{"taken, other case", roleBody("clerk"), "name"},
		{"every permission", roleBody("All", "*"), "permissions"},
		{"undeclared permission", roleBody("Odd", "payroll:read"), "permissions"},
		{"malformed permission", roleBody("Odd", "Invoices:Read"), "permissions"},
	}
	for _, tt := range tests {
		res := f.do(t, http.MethodPost, tm.path("/roles"), tt.body, withToken(tm.users[OwnerRole].Token))
		var e errorJSON
		_ = json.Unmarshal(res.body, &e)
		if res.status != http.StatusUnprocessableEntity || len(e.Error.Details) == 0 || e.Error.Details[0].Field != tt.field {
			t.Errorf("%s: status %d, body %s; want 422 on %s", tt.name, res.status, res.body, tt.field)
		}
	}
	wantError(t, "malformed role ID", f.do(t, http.MethodPatch, tm.path("/roles/nope"), `{"name":"x"}`, withToken(tm.users[OwnerRole].Token)), 404, "not_found")
	wantError(t, "unknown role ID", f.do(t, http.MethodPatch, tm.path("/roles/"+uuid.NewString()), `{"name":"x"}`, withToken(tm.users[OwnerRole].Token)), 404, "not_found")
	wantError(t, "not a custom role key", f.setRole(t, tm, OwnerRole, tm.users["viewer"].User.ID, "custom:nope"), 422, "validation_failed")
	wantError(t, "non-canonical key", f.setRole(t, tm, OwnerRole, tm.users["viewer"].User.ID, strings.ToUpper(CustomRoleKey(uuid.New()))), 422, "validation_failed")
}

func TestOrgRolesLimit(t *testing.T) {
	t.Parallel()
	f := setupRoles(t, Config{})
	tm := f.team(t)
	ctx := context.Background()
	for i := range maxOrgRoles {
		if _, err := f.auth.CreateOrgRole(ctx, tm.org, fmt.Sprintf("Role %d", i), nil, Actor{}); err != nil {
			t.Fatal(err)
		}
	}
	wantError(t, "one too many", f.do(t, http.MethodPost, tm.path("/roles"), roleBody("More"), withToken(tm.users[OwnerRole].Token)), 409, "too_many_roles")
	if _, err := f.auth.CreateOrgRole(ctx, tm.org, "More", nil, Actor{}); !errors.Is(err, ErrTooManyRoles) {
		t.Errorf("CreateOrgRole() error = %v, want ErrTooManyRoles", err)
	}
}

func TestOrgRolesAcrossOrganizations(t *testing.T) {
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
	owner := tm.users[OwnerRole].Token
	id := theirs.ID.String()

	wantError(t, "rename another organization's role", f.do(t, http.MethodPatch, tm.path("/roles/"+id), `{"name":"Mine"}`, withToken(owner)), 404, "not_found")
	wantError(t, "delete another organization's role", f.do(t, http.MethodDelete, tm.path("/roles/"+id), "", withToken(owner)), 404, "not_found")
	wantError(t, "assign another organization's role", f.setRole(t, tm, OwnerRole, tm.users["viewer"].User.ID, theirs.Key), 422, "validation_failed")
	if err := f.auth.SetMemberRole(ctx, tm.org, tm.users["viewer"].User.ID, theirs.Key, Actor{}); !errors.Is(err, ErrUnknownRole) {
		t.Errorf("SetMemberRole() with another organization's role: %v, want ErrUnknownRole", err)
	}
	if _, err := f.auth.UpdateOrgRole(ctx, tm.org, theirs.ID, OrgRoleChanges{Name: new("Mine")}, Actor{}); !errors.Is(err, ErrRoleNotFound) {
		t.Errorf("UpdateOrgRole() across organizations: %v, want ErrRoleNotFound", err)
	}
	if err := f.auth.DeleteOrgRole(ctx, tm.org, theirs.ID, Actor{}); !errors.Is(err, ErrRoleNotFound) {
		t.Errorf("DeleteOrgRole() across organizations: %v, want ErrRoleNotFound", err)
	}
	// Outsiders don't even learn the organization exists.
	wantError(t, "list as an outsider", f.do(t, http.MethodGet, "/v1/organizations/"+otherOrg.String()+"/roles", "", withToken(owner)), 404, "not_found")

	// The database refuses it too, whatever the code does.
	_, err = f.pool.Exec(ctx, `UPDATE auth.memberships SET role = $1, custom_role_id = $2 WHERE organization_id = $3 AND user_id = $4`,
		theirs.Key, theirs.ID, tm.org, tm.users["viewer"].User.ID)
	if err == nil || !strings.Contains(err.Error(), "memberships_custom_role_fkey") {
		t.Errorf("storing another organization's role: %v, want the foreign key to refuse it", err)
	}
	if role := f.roleOf(t, otherOrg, other.User.ID); role != OwnerRole {
		t.Errorf("other organization's owner has %q", role)
	}
}

func TestOrgRolesKeepAnOwner(t *testing.T) {
	t.Parallel()
	f := setupRoles(t, Config{})
	tm := f.team(t)
	ctx := context.Background()
	role := f.createRole(t, tm, OwnerRole, roleBody("Clerk", "invoices:read"))
	owner := tm.users[OwnerRole]
	wantError(t, "last owner to a custom role", f.setRole(t, tm, OwnerRole, owner.User.ID, role.Key), 409, "last_owner")
	if err := f.auth.SetMemberRole(ctx, tm.org, owner.User.ID, role.Key, Actor{}); !errors.Is(err, ErrLastOwner) {
		t.Errorf("SetMemberRole(): %v, want ErrLastOwner", err)
	}
	// Admins can't make or unmake owners with custom roles either.
	wantError(t, "admin demoting the owner", f.setRole(t, tm, "admin", owner.User.ID, role.Key), 403, "forbidden")
	if got := f.roleOf(t, tm.org, owner.User.ID); got != OwnerRole {
		t.Errorf("owner's role is %q", got)
	}
}

func TestOrgRolesFromCode(t *testing.T) {
	t.Parallel()
	f := setupRoles(t, Config{})
	ctx := context.Background()
	tm := f.team(t)
	by, adminID := adminActor(t, f)
	r, err := f.auth.CreateOrgRole(ctx, tm.org, "Billing clerk", []rbac.Permission{"invoices:read", "invoices:delete"}, by)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.auth.SetMemberRole(ctx, tm.org, tm.users["viewer"].User.ID, r.Key, by); err != nil {
		t.Fatal(err)
	}
	if seen := f.seen(t, f.do(t, http.MethodGet, "/v1/invoices", "", withToken(tm.users["viewer"].Token), inOrg(tm.org))); seen["can_delete"] != true {
		t.Errorf("handler saw %v", seen)
	}
	if err := f.auth.DeleteOrgRole(ctx, tm.org, r.ID, by); !errors.Is(err, ErrRoleInUse) {
		t.Errorf("DeleteOrgRole() in use: %v, want ErrRoleInUse", err)
	}
	if _, err := f.auth.CreateOrgRole(ctx, tm.org, "Payroll", []rbac.Permission{"payroll:run"}, by); !errors.Is(err, ErrUndeclaredPermission) {
		t.Errorf("undeclared permission: %v", err)
	}
	if _, err := f.auth.CreateOrgRole(ctx, uuid.New(), "Clerk", nil, by); !errors.Is(err, ErrOrganizationNotFound) {
		t.Errorf("no such organization: %v", err)
	}
	none := []rbac.Permission{}
	if r, err = f.auth.UpdateOrgRole(ctx, tm.org, r.ID, OrgRoleChanges{Permissions: none}, by); err != nil || len(r.Permissions) != 0 {
		t.Errorf("removing every permission: %+v, %v", r, err)
	}
	if res := f.do(t, http.MethodGet, "/v1/invoices", "", withToken(tm.users["viewer"].Token), inOrg(tm.org)); res.status != http.StatusForbidden {
		t.Errorf("with no permissions: status %d", res.status)
	}
	for _, e := range f.roleEvents(t) {
		if e.ActorID == nil || *e.ActorID != adminID {
			t.Errorf("%s: actor %v, want the admin", e.Type, e.ActorID)
		}
	}
}

func TestOrgRolesOnlyGrantDeclaredPermissions(t *testing.T) {
	t.Parallel()
	f := setupRoles(t, Config{})
	tm := f.team(t)
	r := f.createRole(t, tm, OwnerRole, roleBody("Clerk", "invoices:read"))
	// Stored before a project removed a permission from code, or written
	// around the module: neither grants anything.
	if _, err := f.pool.Exec(context.Background(), `UPDATE auth.organization_roles SET permissions = '{invoices:read,payroll:run,*}' WHERE id = $1`, r.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.auth.SetMemberRole(context.Background(), tm.org, tm.users["viewer"].User.ID, r.Key, Actor{}); err != nil {
		t.Fatal(err)
	}
	role, err := f.auth.memberRole(context.Background(), f.auth.q, tm.org, tm.users["viewer"].User.ID)
	if err != nil {
		t.Fatal(err)
	}
	if role.all || role.can("payroll:run") || role.can("invoices:delete") || !role.can("invoices:read") {
		t.Errorf("role grants %+v, want only invoices:read", role)
	}
}

func TestPrivilegedPermissions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		roles rbac.Roles
		twoFA []string
		want  []string
	}{
		{"no privileged roles", rolesTestRoles, nil, nil},
		{"owner only", rolesTestRoles, []string{OwnerRole}, nil},
		{"admin, owner not privileged", rbac.Roles{OwnerRole: {rbac.All}, "admin": {"a:b", "c:d"}, "member": {"c:d"}}, []string{"admin"}, []string{"a:b"}},
		{"admin", rolesTestRoles, []string{"admin"}, []string{"organization:update"}},
		{"admin and manager", rolesTestRoles, []string{"admin", "manager"}, []string{"members:manage", "organization:update", "roles:manage"}},
		{"an ordinary role with everything", rbac.Roles{OwnerRole: {rbac.All}, "admin": {"a:b"}, "god": {rbac.All}}, []string{"admin"}, nil},
		{"app role only", rolesTestRoles, []string{"support"}, nil},
	}
	for _, tt := range tests {
		got := privilegedPermissions(tt.roles, tt.twoFA)
		if len(got) == 0 && len(tt.want) == 0 {
			continue
		}
		if diff := cmp.Diff(tt.want, got); diff != "" {
			t.Errorf("%s (-want +got):\n%s", tt.name, diff)
		}
	}
}

// TestCustomRolesCantAvoidTwoFactor copies a privileged role's permission
// into a custom role: its members need 2FA too.
func TestCustomRolesCantAvoidTwoFactor(t *testing.T) {
	t.Parallel()
	f := setupRoles(t, Config{TwoFactorRoles: []string{"admin"}})
	tm := f.team(t)
	plain := f.createRole(t, tm, OwnerRole, roleBody("Reader", "invoices:read"))
	admin := f.createRole(t, tm, OwnerRole, roleBody("Office admin", "organization:update"))
	viewer, member := tm.users["viewer"], tm.users["member"]

	if res := f.setRole(t, tm, OwnerRole, viewer.User.ID, plain.Key); res.status != http.StatusOK {
		t.Fatal(res.status)
	}
	if res := f.do(t, http.MethodGet, "/v1/invoices", "", withToken(viewer.Token), inOrg(tm.org)); res.status != http.StatusOK {
		t.Errorf("ordinary custom role: status %d, want no 2FA needed", res.status)
	}
	if res := f.setRole(t, tm, OwnerRole, member.User.ID, admin.Key); res.status != http.StatusOK {
		t.Fatal(res.status)
	}
	wantError(t, "privileged custom role without 2FA", f.do(t, http.MethodGet, "/v1/profile", "", withToken(member.Token)), 403, "two_factor_setup_required")
}

func TestDeleteRoleAndAssignConcurrently(t *testing.T) {
	t.Parallel()
	f := setupRoles(t, Config{})
	tm := f.team(t)
	owner := tm.users[OwnerRole].Token
	for range 5 {
		r := f.createRole(t, tm, OwnerRole, roleBody(uuid.NewString(), "invoices:read"))
		var wg sync.WaitGroup
		var del, set int
		wg.Go(func() {
			del = f.do(t, http.MethodDelete, tm.path("/roles/"+r.ID.String()), "", withToken(owner)).status
		})
		wg.Go(func() { set = f.setRole(t, tm, OwnerRole, tm.users["viewer"].User.ID, r.Key).status })
		wg.Wait()
		ok := del == http.StatusNoContent && set == http.StatusUnprocessableEntity ||
			del == http.StatusConflict && set == http.StatusOK
		if !ok {
			t.Fatalf("delete %d and assign %d, want one to win cleanly", del, set)
		}
		if set == http.StatusOK {
			if res := f.setRole(t, tm, OwnerRole, tm.users["viewer"].User.ID, "viewer"); res.status != http.StatusOK {
				t.Fatal(res.status)
			}
		}
	}
}

// TestRoleChangeAndUseConcurrently narrows a role while its holder hands
// it out: the hand-out is checked against the role as it is under the
// lock, so a permission the holder just lost can't be granted.
func TestNarrowingAndAssigningConcurrently(t *testing.T) {
	t.Parallel()
	f := setupRoles(t, Config{})
	tm := f.team(t)
	ctx := context.Background()
	for range 5 {
		lead, err := f.auth.CreateOrgRole(ctx, tm.org, "Lead "+uuid.NewString(), []rbac.Permission{PermMembersManage, "invoices:read", "invoices:delete"}, Actor{})
		if err != nil {
			t.Fatal(err)
		}
		deleter, err := f.auth.CreateOrgRole(ctx, tm.org, "Deleter "+uuid.NewString(), []rbac.Permission{"invoices:delete"}, Actor{})
		if err != nil {
			t.Fatal(err)
		}
		if err := f.auth.SetMemberRole(ctx, tm.org, tm.users["member"].User.ID, lead.Key, Actor{}); err != nil {
			t.Fatal(err)
		}
		if err := f.auth.SetMemberRole(ctx, tm.org, tm.users["viewer"].User.ID, "viewer", Actor{}); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Go(func() {
			res := f.do(t, http.MethodPatch, tm.path("/roles/"+lead.ID.String()), `{"permissions":["members:manage","invoices:read"]}`, withToken(tm.users[OwnerRole].Token))
			if res.status != http.StatusOK {
				t.Errorf("narrowing: status %d", res.status)
			}
		})
		var set int
		wg.Go(func() { set = f.setRole(t, tm, "member", tm.users["viewer"].User.ID, deleter.Key).status })
		wg.Wait()
		// Either the hand-out came first, while the lead still had
		// invoices:delete, or it was refused.
		got := f.roleOf(t, tm.org, tm.users["viewer"].User.ID)
		if set == http.StatusOK && got != deleter.Key || set == http.StatusForbidden && got != "viewer" || set != http.StatusOK && set != http.StatusForbidden {
			t.Fatalf("assign status %d left role %q", set, got)
		}
	}
}

func TestDeletingAnOrganizationWithRolesInUse(t *testing.T) {
	t.Parallel()
	f := setupRoles(t, Config{})
	tm := f.team(t)
	r := f.createRole(t, tm, OwnerRole, roleBody("Clerk", "invoices:read"))
	if res := f.setRole(t, tm, OwnerRole, tm.users["viewer"].User.ID, r.Key); res.status != http.StatusOK {
		t.Fatal(res.status)
	}
	if _, err := f.pool.Exec(context.Background(), `DELETE FROM auth.organizations WHERE id = $1`, tm.org); err != nil {
		t.Errorf("deleting the organization: %v", err)
	}
}
