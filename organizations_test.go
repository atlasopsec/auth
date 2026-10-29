package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/atlasopsec/auth/rbac"
)

var orgTestRoles = rbac.Roles{
	OwnerRole: {rbac.All},
	"admin":   {PermOrganizationUpdate, PermMembersRead, PermMembersManage, "invoices:read"},
	"manager": {PermMembersRead, PermMembersManage},
	"member":  {PermMembersRead, "invoices:read"},
	"viewer":  {"invoices:read"},
}

type orgFixture struct {
	accessFixture
}

func setupOrgs(t *testing.T, cfg Config) orgFixture {
	t.Helper()
	cfg.AllowUnverifiedLogin = true
	if cfg.OrgRoles == nil {
		cfg.OrgRoles = orgTestRoles
	}
	return orgFixture{accessFixture{fixture: setupWith(t, cfg)}}
}

// verifiedUser signs up a user whose email is verified.
func (f orgFixture) user(t *testing.T, email string) loginJSON {
	t.Helper()
	// From its own address, like a separate person, so tests that need
	// many users stay under the per-IP sign-up limit.
	res := f.do(t, http.MethodPost, "/v1/users", credentials(email, testPassword, "web"), fromIP(nextTestIP()))
	var l loginJSON
	if res.status != http.StatusCreated || json.Unmarshal(res.body, &l) != nil {
		t.Fatalf("sign up: status %d, body %s", res.status, res.body)
	}
	if _, err := f.pool.Exec(context.Background(), `UPDATE auth.users SET email_verified_at = now() WHERE id = $1`, l.User.ID); err != nil {
		t.Fatal(err)
	}
	return l
}

type orgResponse struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
	Role string    `json:"role"`
}

func (f orgFixture) createOrg(t *testing.T, tok, name string) orgResponse {
	t.Helper()
	res := f.do(t, http.MethodPost, "/v1/organizations", `{"name":"`+name+`"}`, withToken(tok))
	if res.status != http.StatusCreated {
		t.Fatalf("creating organization: status %d, body %s", res.status, res.body)
	}
	var o orgResponse
	if err := json.Unmarshal(res.body, &o); err != nil {
		t.Fatal(err)
	}
	return o
}

// team is an organization with a user in each role.
type team struct {
	org   uuid.UUID
	users map[string]loginJSON
}

func (f orgFixture) team(t *testing.T) team {
	t.Helper()
	tm := team{users: map[string]loginJSON{}}
	tm.users[OwnerRole] = f.user(t, "owner@example.com")
	tm.org = f.createOrg(t, tm.users[OwnerRole].Token, "Acme").ID
	for _, role := range []string{"admin", "manager", "member", "viewer"} {
		tm.users[role] = f.user(t, role+"@example.com")
		f.addMember(t, tm.org, tm.users[role].User.ID, role)
	}
	return tm
}

func (tm team) path(suffix string) string { return "/v1/organizations/" + tm.org.String() + suffix }

func (f orgFixture) roleOf(t *testing.T, org, user uuid.UUID) string {
	t.Helper()
	var role string
	err := f.pool.QueryRow(context.Background(), `SELECT role FROM auth.memberships WHERE organization_id = $1 AND user_id = $2`, org, user).Scan(&role)
	if err != nil {
		return ""
	}
	return role
}

func TestCreateOrganization(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	u := f.user(t, testEmail)

	res := f.do(t, http.MethodPost, "/v1/organizations", `{"name":"  Acme Corp  "}`, withToken(u.Token))
	if res.status != http.StatusCreated {
		t.Fatalf("status %d, body %s", res.status, res.body)
	}
	var o orgResponse
	if err := json.Unmarshal(res.body, &o); err != nil {
		t.Fatal(err)
	}
	if o.Name != "Acme Corp" || o.Role != OwnerRole || o.ID == uuid.Nil {
		t.Errorf("organization = %+v, want Acme Corp with the creator as owner", o)
	}
	if got := f.roleOf(t, o.ID, u.User.ID); got != OwnerRole {
		t.Errorf("stored role = %q, want owner", got)
	}
	if !strings.Contains(string(res.body), `"created_at":"2026-01-01T12:00:00Z"`) {
		t.Errorf("body %s: want created_at", res.body)
	}
}

func TestCreateOrganizationRejects(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	verified := f.user(t, testEmail)
	unverified := f.signUp(t, "unverified@example.com")

	tests := []struct {
		name       string
		tok        string
		body       string
		wantStatus int
		wantCode   string
	}{
		{"unverified email", unverified.Token, `{"name":"Acme"}`, 403, "email_not_verified"},
		{"blank name", verified.Token, `{"name":"   "}`, 422, "validation_failed"},
		{"name too long", verified.Token, `{"name":"` + strings.Repeat("é", 201) + `"}`, 422, "validation_failed"},
		{"unknown field", verified.Token, `{"name":"Acme","owner":"x"}`, 400, "bad_request"},
		{"not logged in", "", `{"name":"Acme"}`, 401, "unauthenticated"},
	}
	for _, tt := range tests {
		res := f.do(t, http.MethodPost, "/v1/organizations", tt.body, withToken(tt.tok))
		if res.status != tt.wantStatus || res.errorCode(t) != tt.wantCode {
			t.Errorf("%s: status %d, body %s; want %d %s", tt.name, res.status, res.body, tt.wantStatus, tt.wantCode)
		}
	}
	var n int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM auth.organizations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d organizations created by rejected requests", n)
	}
	// Exactly 200 characters is fine.
	f.createOrg(t, verified.Token, strings.Repeat("é", 200))
}

func TestDisableOrganizationCreation(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{DisableOrganizationCreation: true})
	u := f.user(t, testEmail)
	if res := f.do(t, http.MethodPost, "/v1/organizations", `{"name":"Acme"}`, withToken(u.Token)); res.status != http.StatusMethodNotAllowed {
		t.Errorf("POST /v1/organizations: status %d, want 405", res.status)
	}

	// The app creates organizations itself.
	o, err := f.auth.CreateOrganization(context.Background(), " Client Co ", u.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	if o.Name != "Client Co" || f.roleOf(t, o.ID, u.User.ID) != OwnerRole {
		t.Errorf("CreateOrganization() = %+v; want the trimmed name, with the user as owner", o)
	}
	if _, err := f.auth.CreateOrganization(context.Background(), "", u.User.ID); err == nil {
		t.Error("CreateOrganization() with a blank name: error = nil")
	}
	if _, err := f.auth.CreateOrganization(context.Background(), "Ghost", uuid.Must(uuid.NewV7())); err == nil {
		t.Error("CreateOrganization() for a nonexistent user: error = nil")
	}
}

func TestNoOrganizationEndpointsWithoutOrgRoles(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	u := f.signUp(t, testEmail)
	if res := f.do(t, http.MethodGet, "/v1/organizations", "", withToken(u.Token)); res.status != http.StatusNotFound {
		t.Errorf("GET /v1/organizations: status %d, want 404", res.status)
	}
	if _, err := f.auth.CreateOrganization(context.Background(), "Acme", u.User.ID); err == nil {
		t.Error("CreateOrganization() without OrgRoles: error = nil")
	}
}

func TestListAndGetOrganizations(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	tm := f.team(t)
	other := f.user(t, "other@example.com")
	otherOrg := f.createOrg(t, other.Token, "Other Co")
	viewer := tm.users["viewer"]

	res := f.do(t, http.MethodGet, "/v1/organizations", "", withToken(viewer.Token))
	var list struct {
		Data       []orgResponse `json:"data"`
		NextCursor *string       `json:"next_cursor"`
	}
	if err := json.Unmarshal(res.body, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Data) != 1 || list.Data[0].ID != tm.org || list.Data[0].Role != "viewer" || list.NextCursor != nil {
		t.Errorf("viewer's organizations = %s, want only Acme, as viewer", res.body)
	}
	loner := f.user(t, "loner@example.com")
	if res := f.do(t, http.MethodGet, "/v1/organizations", "", withToken(loner.Token)); !strings.Contains(string(res.body), `"data":[]`) {
		t.Errorf("no organizations: body %s, want an empty list", res.body)
	}

	res = f.do(t, http.MethodGet, tm.path(""), "", withToken(viewer.Token))
	if res.status != http.StatusOK || !strings.Contains(string(res.body), `"role":"viewer"`) {
		t.Errorf("GET own organization: status %d, body %s", res.status, res.body)
	}
	for name, path := range map[string]string{
		"another organization": "/v1/organizations/" + otherOrg.ID.String(),
		"nonexistent":          "/v1/organizations/" + uuid.NewString(),
		"malformed ID":         "/v1/organizations/acme",
	} {
		if res := f.do(t, http.MethodGet, path, "", withToken(viewer.Token)); res.status != http.StatusNotFound || res.errorCode(t) != "not_found" {
			t.Errorf("%s: status %d, body %s; want 404", name, res.status, res.body)
		}
	}
}

func TestRenameOrganization(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	tm := f.team(t)
	outsider := f.user(t, "outsider@example.com")

	res := f.do(t, http.MethodPatch, tm.path(""), `{"name":"Acme Inc"}`, withToken(tm.users["admin"].Token))
	if res.status != http.StatusOK || !strings.Contains(string(res.body), `"name":"Acme Inc"`) || !strings.Contains(string(res.body), `"role":"admin"`) {
		t.Errorf("admin renaming: status %d, body %s", res.status, res.body)
	}
	for name, c := range map[string]struct {
		tok  string
		body string
		want int
	}{
		"manager without organization:update": {tm.users["manager"].Token, `{"name":"Hacked"}`, 403},
		"outsider":                            {outsider.Token, `{"name":"Hacked"}`, 404},
		"blank name":                          {tm.users[OwnerRole].Token, `{"name":""}`, 422},
	} {
		if res := f.do(t, http.MethodPatch, tm.path(""), c.body, withToken(c.tok)); res.status != c.want {
			t.Errorf("%s: status %d, body %s; want %d", name, res.status, res.body, c.want)
		}
	}
	var name string
	if err := f.pool.QueryRow(context.Background(), `SELECT name FROM auth.organizations WHERE id = $1`, tm.org).Scan(&name); err != nil || name != "Acme Inc" {
		t.Errorf("name = %q, err = %v; want Acme Inc", name, err)
	}
}

type memberPage struct {
	Data []struct {
		UserID uuid.UUID `json:"user_id"`
		Email  string    `json:"email"`
		Role   string    `json:"role"`
	} `json:"data"`
	NextCursor *string `json:"next_cursor"`
}

func (f orgFixture) members(t *testing.T, tm team, tok, query string) (memberPage, response) {
	t.Helper()
	res := f.do(t, http.MethodGet, tm.path("/members"+query), "", withToken(tok))
	var p memberPage
	if res.status == http.StatusOK {
		if err := json.Unmarshal(res.body, &p); err != nil {
			t.Fatal(err)
		}
	}
	return p, res
}

func TestListMembers(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	tm := f.team(t)
	for i := range 20 {
		u := f.user(t, fmt.Sprintf("extra%02d@example.com", i))
		f.addMember(t, tm.org, u.User.ID, "viewer")
	}

	owner := tm.users[OwnerRole].Token
	page, res := f.members(t, tm, owner, "")
	if res.status != http.StatusOK || len(page.Data) != 20 || page.NextCursor == nil {
		t.Fatalf("first page: status %d, %d members, next_cursor %v; want 20 and a cursor", res.status, len(page.Data), page.NextCursor)
	}
	// In the order they joined: the owner first.
	if page.Data[0].Email != "owner@example.com" || page.Data[0].Role != OwnerRole || page.Data[1].Email != "admin@example.com" {
		t.Errorf("first members = %+v", page.Data[:2])
	}
	next, _ := f.members(t, tm, owner, "?cursor="+*page.NextCursor)
	if len(next.Data) != 5 || next.NextCursor != nil {
		t.Errorf("second page: %d members, next_cursor %v; want 5 and none", len(next.Data), next.NextCursor)
	}
	seen := map[uuid.UUID]bool{}
	for _, m := range append(page.Data, next.Data...) {
		if seen[m.UserID] {
			t.Errorf("member %s listed twice", m.Email)
		}
		seen[m.UserID] = true
	}
	if small, _ := f.members(t, tm, owner, "?limit=3"); len(small.Data) != 3 || small.NextCursor == nil {
		t.Errorf("limit=3: %d members", len(small.Data))
	}
	if all, _ := f.members(t, tm, owner, "?limit=100"); len(all.Data) != 25 || all.NextCursor != nil {
		t.Errorf("limit=100: %d members, next_cursor %v; want all 25", len(all.Data), all.NextCursor)
	}

	for _, q := range []string{"?limit=0", "?limit=101", "?limit=ten", "?cursor=not-a-cursor", "?cursor=AAAA"} {
		if _, res := f.members(t, tm, owner, q); res.status != http.StatusUnprocessableEntity || res.errorCode(t) != "validation_failed" {
			t.Errorf("%s: status %d, body %s; want 422", q, res.status, res.body)
		}
	}
	if _, res := f.members(t, tm, tm.users["viewer"].Token, ""); res.status != http.StatusForbidden {
		t.Errorf("viewer without members:read: status %d, want 403", res.status)
	}
	outsider := f.user(t, "outsider@example.com")
	if _, res := f.members(t, tm, outsider.Token, ""); res.status != http.StatusNotFound {
		t.Errorf("outsider: status %d, want 404", res.status)
	}
}

func (f orgFixture) setRole(t *testing.T, tm team, actor string, target uuid.UUID, role string) response {
	t.Helper()
	return f.do(t, http.MethodPatch, tm.path("/members/"+target.String()), `{"role":"`+role+`"}`, withToken(tm.users[actor].Token))
}

func TestChangeMemberRole(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	tm := f.team(t)
	id := func(role string) uuid.UUID { return tm.users[role].User.ID }

	res := f.setRole(t, tm, OwnerRole, id("viewer"), "member")
	if res.status != http.StatusOK || !strings.Contains(string(res.body), `"role":"member"`) || !strings.Contains(string(res.body), `"email":"viewer@example.com"`) {
		t.Errorf("owner changing a role: status %d, body %s", res.status, res.body)
	}
	if got := f.roleOf(t, tm.org, id("viewer")); got != "member" {
		t.Errorf("stored role = %q, want member", got)
	}
	// Setting the role someone already has is a no-op.
	if res := f.setRole(t, tm, "admin", id("viewer"), "member"); res.status != http.StatusOK {
		t.Errorf("no-op change: status %d", res.status)
	}
	// An admin can grant roles within their own permissions.
	if res := f.setRole(t, tm, "admin", id("viewer"), "manager"); res.status != http.StatusOK {
		t.Errorf("admin granting manager: status %d, body %s", res.status, res.body)
	}
	if got := f.roleOf(t, tm.org, id("viewer")); got != "manager" {
		t.Errorf("stored role = %q, want manager", got)
	}
}

func TestChangeMemberRoleRejects(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	tm := f.team(t)
	id := func(role string) uuid.UUID { return tm.users[role].User.ID }
	outsider := f.user(t, "outsider@example.com")

	tests := []struct {
		name     string
		actor    string
		target   string // a path segment
		role     string
		want     int
		wantCode string
	}{
		{"manager promoting to admin (has more permissions)", "manager", id("member").String(), "admin", 403, "forbidden"},
		{"manager promoting themselves", "manager", id("manager").String(), "admin", 403, "forbidden"},
		{"manager changing an admin", "manager", id("admin").String(), "viewer", 403, "forbidden"},
		{"admin making an owner", "admin", id("member").String(), OwnerRole, 403, "forbidden"},
		{"admin making themselves owner", "admin", id("admin").String(), OwnerRole, 403, "forbidden"},
		{"admin demoting the owner", "admin", id(OwnerRole).String(), "viewer", 403, "forbidden"},
		{"member without members:manage", "member", id("viewer").String(), "member", 403, "forbidden"},
		{"undefined role", OwnerRole, id("viewer").String(), "superuser", 422, "validation_failed"},
		{"not a member", OwnerRole, outsider.User.ID.String(), "viewer", 404, "not_found"},
		{"malformed user ID", OwnerRole, "abc", "viewer", 404, "not_found"},
	}
	for _, tt := range tests {
		res := f.do(t, http.MethodPatch, tm.path("/members/"+tt.target), `{"role":"`+tt.role+`"}`, withToken(tm.users[tt.actor].Token))
		if res.status != tt.want || res.errorCode(t) != tt.wantCode {
			t.Errorf("%s: status %d, body %s; want %d %s", tt.name, res.status, res.body, tt.want, tt.wantCode)
		}
	}
	for _, role := range []string{OwnerRole, "admin", "manager", "member", "viewer"} {
		if got := f.roleOf(t, tm.org, id(role)); got != role {
			t.Errorf("%s's role changed to %q by a rejected request", role, got)
		}
	}
	if f.roleOf(t, tm.org, outsider.User.ID) != "" {
		t.Error("outsider was added")
	}
}

func TestLastOwner(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	tm := f.team(t)
	owner := tm.users[OwnerRole].User.ID
	path := tm.path("/members/" + owner.String())

	if res := f.setRole(t, tm, OwnerRole, owner, "admin"); res.status != http.StatusConflict || res.errorCode(t) != "last_owner" {
		t.Errorf("sole owner stepping down: status %d, body %s; want 409 last_owner", res.status, res.body)
	}
	if res := f.do(t, http.MethodDelete, path, "", withToken(tm.users[OwnerRole].Token)); res.status != http.StatusConflict {
		t.Errorf("sole owner leaving: status %d, want 409", res.status)
	}

	// With a second owner, the first can step down.
	if res := f.setRole(t, tm, OwnerRole, tm.users["admin"].User.ID, OwnerRole); res.status != http.StatusOK {
		t.Fatalf("making a second owner: status %d, body %s", res.status, res.body)
	}
	if res := f.setRole(t, tm, OwnerRole, owner, "admin"); res.status != http.StatusOK {
		t.Errorf("stepping down with another owner: status %d, body %s", res.status, res.body)
	}
	// Now the other owner is the last one.
	if res := f.do(t, http.MethodDelete, tm.path("/members/"+tm.users["admin"].User.ID.String()), "", withToken(tm.users["admin"].Token)); res.status != http.StatusConflict {
		t.Errorf("new sole owner leaving: status %d, want 409", res.status)
	}
}

func TestOwnersDemotingEachOtherConcurrently(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	tm := f.team(t)
	a, b := tm.users[OwnerRole], tm.users["admin"]
	if res := f.setRole(t, tm, OwnerRole, b.User.ID, OwnerRole); res.status != http.StatusOK {
		t.Fatal(res.status)
	}

	results := make(chan int, 2)
	go func() {
		results <- f.do(t, http.MethodPatch, tm.path("/members/"+b.User.ID.String()), `{"role":"viewer"}`, withToken(a.Token)).status
	}()
	go func() {
		results <- f.do(t, http.MethodPatch, tm.path("/members/"+a.User.ID.String()), `{"role":"viewer"}`, withToken(b.Token)).status
	}()
	r1, r2 := <-results, <-results
	var owners int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM auth.memberships WHERE organization_id = $1 AND role = 'owner'`, tm.org).Scan(&owners); err != nil {
		t.Fatal(err)
	}
	if owners != 1 {
		t.Errorf("%d owners left (statuses %d, %d), want 1", owners, r1, r2)
	}
}

func TestRemoveMember(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	tm := f.team(t)
	id := func(role string) uuid.UUID { return tm.users[role].User.ID }
	remove := func(actor string, target uuid.UUID) response {
		return f.do(t, http.MethodDelete, tm.path("/members/"+target.String()), "", withToken(tm.users[actor].Token))
	}

	// Rejected first, while everyone is still a member.
	for name, c := range map[string]struct {
		actor  string
		target uuid.UUID
		want   int
	}{
		"viewer removing someone": {"viewer", id("member"), 403},
		// A member can do everything a viewer can, but lacks members:manage.
		"member removing a viewer": {"member", id("viewer"), 403},
		// The viewer can read invoices; the manager can't.
		"manager removing someone with a permission they lack": {"manager", id("viewer"), 403},
		"manager removing an admin":                            {"manager", id("admin"), 403},
		"admin removing the owner":                             {"admin", id(OwnerRole), 403},
		"removing a non-member":                                {OwnerRole, uuid.Must(uuid.NewV7()), 404},
	} {
		if res := remove(c.actor, c.target); res.status != c.want {
			t.Errorf("%s: status %d, body %s; want %d", name, res.status, res.body, c.want)
		}
	}

	if res := remove("admin", id("viewer")); res.status != http.StatusNoContent {
		t.Errorf("admin removing a viewer: status %d, body %s", res.status, res.body)
	}
	if res := f.do(t, http.MethodGet, tm.path(""), "", withToken(tm.users["viewer"].Token)); res.status != http.StatusNotFound {
		t.Errorf("removed member: status %d, want 404", res.status)
	}
	// Anyone can leave, without members:manage.
	if res := remove("member", id("member")); res.status != http.StatusNoContent {
		t.Errorf("member leaving: status %d, body %s", res.status, res.body)
	}
	if f.roleOf(t, tm.org, id("member")) != "" {
		t.Error("member still in the organization after leaving")
	}
}

func TestOrganizationsAreIsolated(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	tm := f.team(t)
	rival := f.user(t, "rival@example.com")
	rivalOrg := f.createOrg(t, rival.Token, "Rival")
	victim := tm.users["member"].User.ID

	// The owner of another organization can't see or touch this one.
	for name, c := range map[string]struct {
		method, path, body string
	}{
		"read":          {http.MethodGet, tm.path(""), ""},
		"rename":        {http.MethodPatch, tm.path(""), `{"name":"Pwned"}`},
		"list members":  {http.MethodGet, tm.path("/members"), ""},
		"change a role": {http.MethodPatch, tm.path("/members/" + victim.String()), `{"role":"viewer"}`},
		"remove":        {http.MethodDelete, tm.path("/members/" + victim.String()), ""},
	} {
		if res := f.do(t, c.method, c.path, c.body, withToken(rival.Token)); res.status != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", name, res.status)
		}
	}
	// Nor manage this organization's members through their own.
	res := f.do(t, http.MethodPatch, "/v1/organizations/"+rivalOrg.ID.String()+"/members/"+victim.String(), `{"role":"viewer"}`, withToken(rival.Token))
	if res.status != http.StatusNotFound {
		t.Errorf("changing a non-member's role through another organization: status %d, want 404", res.status)
	}
	if got := f.roleOf(t, tm.org, victim); got != "member" {
		t.Errorf("victim's role = %q, want member", got)
	}
}

func TestOnlyOwnersTouchOwnersEvenWithNarrowOwnerRole(t *testing.T) {
	t.Parallel()
	// An owner role defined narrowly still can't be granted or changed by
	// an admin who has every permission it lists.
	f := setupOrgs(t, Config{OrgRoles: rbac.Roles{
		OwnerRole: {PermMembersRead},
		"admin":   {PermMembersRead, PermMembersManage},
		"member":  {PermMembersRead},
	}})
	owner := f.user(t, "owner@example.com")
	org := f.createOrg(t, owner.Token, "Acme").ID
	tm := team{org: org, users: map[string]loginJSON{OwnerRole: owner}}
	for _, role := range []string{"admin", "member"} {
		tm.users[role] = f.user(t, role+"@example.com")
		f.addMember(t, org, tm.users[role].User.ID, role)
	}

	if res := f.setRole(t, tm, "admin", tm.users["member"].User.ID, OwnerRole); res.status != http.StatusForbidden {
		t.Errorf("admin making an owner: status %d, want 403", res.status)
	}
	if res := f.setRole(t, tm, "admin", owner.User.ID, "member"); res.status != http.StatusForbidden {
		t.Errorf("admin demoting the owner: status %d, want 403", res.status)
	}
	if res := f.do(t, http.MethodDelete, tm.path("/members/"+owner.User.ID.String()), "", withToken(tm.users["admin"].Token)); res.status != http.StatusForbidden {
		t.Errorf("admin removing the owner: status %d, want 403", res.status)
	}
}

// TestMemberChangesWaitForTheOrganizationLock checks the lock directly: a
// role change must wait for another change to the same organization to
// commit, then see its result. Without the lock, both changes would count
// two owners and the organization would end up with none.
func TestMemberChangesWaitForTheOrganizationLock(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	tm := f.team(t)
	ctx := context.Background()
	a, b := tm.users[OwnerRole], tm.users["admin"]
	if res := f.setRole(t, tm, OwnerRole, b.User.ID, OwnerRole); res.status != http.StatusOK {
		t.Fatal(res.status)
	}

	// Another change holds the lock and demotes b, without committing yet.
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT id FROM auth.organizations WHERE id = $1 FOR UPDATE`, tm.org); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE auth.memberships SET role = 'viewer' WHERE organization_id = $1 AND user_id = $2`, tm.org, b.User.ID); err != nil {
		t.Fatal(err)
	}

	result := make(chan response, 1)
	go func() {
		result <- f.do(t, http.MethodPatch, tm.path("/members/"+a.User.ID.String()), `{"role":"viewer"}`, withToken(a.Token))
	}()
	for waiting := false; !waiting; {
		select {
		case res := <-result:
			t.Fatalf("role change finished (status %d) while another change held the lock; want it to wait", res.status)
		default:
		}
		if err := f.pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_stat_activity
				WHERE datname = current_database() AND wait_event_type = 'Lock'
			)`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if res := <-result; res.status != http.StatusConflict || res.errorCode(t) != "last_owner" {
		t.Errorf("status %d, body %s; want 409 last_owner", res.status, res.body)
	}
}
