package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/atlasopsec/auth/internal/testdb"
	"github.com/atlasopsec/auth/mail/mailtest"
	"github.com/atlasopsec/auth/rbac"
)

var testOrgRoles = rbac.Roles{
	OwnerRole: {rbac.All},
	"admin":   {"invoices:read", "invoices:create", "invoices:delete"},
	"member":  {"invoices:read", "invoices:create"},
	"viewer":  {"invoices:read"},
}

var testAppRoles = rbac.Roles{
	"support": {"users:read", "users:ban"},
	"auditor": {"users:read"},
}

// accessFixture has project routes behind every kind of access rule.
type accessFixture struct {
	fixture
	ran *bool
}

func setupAccess(t *testing.T) accessFixture {
	t.Helper()
	f := setupWith(t, Config{AllowUnverifiedLogin: true, OrgRoles: testOrgRoles, AppRoles: testAppRoles})
	ran := new(bool)
	// report writes what the handler saw, so tests can check the context.
	report := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*ran = true
		org, inOrg := OrgFrom(r.Context())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"org_id":          org.ID,
			"org_role":        org.Role,
			"in_org":          inOrg,
			"can_delete":      Can(r.Context(), "invoices:delete"),
			"can_ban":         Can(r.Context(), "users:ban"),
			"can_audit_users": Can(r.Context(), "users:read"),
		})
	})
	f.mux.Handle("GET /v1/invoices", f.auth.RequireOrg("invoices:read", report))
	f.mux.Handle("POST /v1/invoices", f.auth.RequireOrg("invoices:create", report))
	f.mux.Handle("POST /v1/users/{id}/ban", f.auth.Require("users:ban", report))
	f.mux.Handle("GET /v1/profile", f.auth.Authenticated(report))
	f.mux.Handle("GET /v1/status", f.auth.Public(report))
	return accessFixture{fixture: f, ran: ran}
}

func (f accessFixture) newOrg(t *testing.T) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	if _, err := f.pool.Exec(context.Background(), `INSERT INTO auth.organizations (id, name) VALUES ($1, 'Acme')`, id); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f accessFixture) addMember(t *testing.T, org, user uuid.UUID, role string) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(),
		`INSERT INTO auth.memberships (id, organization_id, user_id, role) VALUES ($1, $2, $3, $4)`,
		uuid.Must(uuid.NewV7()), org, user, role); err != nil {
		t.Fatal(err)
	}
}

func inOrg(org uuid.UUID) reqOpt { return withHeader(OrgHeader, org.String()) }

func (f accessFixture) seen(t *testing.T, res response) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(res.body, &m); err != nil {
		t.Fatalf("decoding %s: %v", res.body, err)
	}
	return m
}

func TestRequireOrg(t *testing.T) {
	t.Parallel()
	f := setupAccess(t)
	org, otherOrg := f.newOrg(t), f.newOrg(t)
	users := map[string]loginJSON{}
	for _, role := range []string{OwnerRole, "admin", "member", "viewer", "retired", "outsider", "elsewhere"} {
		users[role] = f.signUp(t, role+"@example.com")
	}
	for _, role := range []string{OwnerRole, "admin", "member", "viewer", "retired"} {
		f.addMember(t, org, users[role].User.ID, role)
	}
	// An admin of a different organization.
	f.addMember(t, otherOrg, users["elsewhere"].User.ID, "admin")

	tests := []struct {
		name       string
		user       string
		method     string
		opts       []reqOpt
		wantStatus int
		wantCode   string
	}{
		{"owner reads", OwnerRole, http.MethodGet, []reqOpt{inOrg(org)}, 200, ""},
		{"owner creates", OwnerRole, http.MethodPost, []reqOpt{inOrg(org)}, 200, ""},
		{"admin creates", "admin", http.MethodPost, []reqOpt{inOrg(org)}, 200, ""},
		{"member creates", "member", http.MethodPost, []reqOpt{inOrg(org)}, 200, ""},
		{"viewer reads", "viewer", http.MethodGet, []reqOpt{inOrg(org)}, 200, ""},
		{"viewer can't create", "viewer", http.MethodPost, []reqOpt{inOrg(org)}, 403, "forbidden"},
		{"role removed from code grants nothing", "retired", http.MethodGet, []reqOpt{inOrg(org)}, 403, "forbidden"},
		{"non-member", "outsider", http.MethodGet, []reqOpt{inOrg(org)}, 404, "not_found"},
		{"admin of another organization", "elsewhere", http.MethodGet, []reqOpt{inOrg(org)}, 404, "not_found"},
		{"nonexistent organization", OwnerRole, http.MethodGet, []reqOpt{inOrg(uuid.Must(uuid.NewV7()))}, 404, "not_found"},
		{"own role doesn't carry to another organization", "admin", http.MethodGet, []reqOpt{inOrg(otherOrg)}, 404, "not_found"},
		{"missing header", OwnerRole, http.MethodGet, nil, 400, "bad_request"},
		{"malformed header", OwnerRole, http.MethodGet, []reqOpt{withHeader(OrgHeader, "acme")}, 400, "bad_request"},
	}
	for _, tt := range tests {
		*f.ran = false
		opts := append([]reqOpt{withToken(users[tt.user].Token)}, tt.opts...)
		res := f.do(t, tt.method, "/v1/invoices", "", opts...)
		if res.status != tt.wantStatus {
			t.Errorf("%s: status %d, body %s; want %d", tt.name, res.status, res.body, tt.wantStatus)
			continue
		}
		if tt.wantCode != "" {
			if code := res.errorCode(t); code != tt.wantCode {
				t.Errorf("%s: code %q, want %q", tt.name, code, tt.wantCode)
			}
			if *f.ran {
				t.Errorf("%s: handler ran", tt.name)
			}
		}
	}

	if res := f.do(t, http.MethodGet, "/v1/invoices", "", inOrg(org)); res.status != http.StatusUnauthorized {
		t.Errorf("no session: status %d, want 401", res.status)
	}
	if !strings.Contains(f.logs.String(), `role=retired`) {
		t.Errorf("undefined role wasn't logged:\n%s", f.logs)
	}
}

func TestOwnerAlwaysHasEveryPermission(t *testing.T) {
	t.Parallel()
	f := setupWith(t, Config{AllowUnverifiedLogin: true, OrgRoles: rbac.Roles{
		OwnerRole: {"invoices:read"}, // even a narrow owner definition
		"admin":   {"settings:update"},
	}})
	ran := false
	f.mux.Handle("PATCH /v1/settings", f.auth.RequireOrg("settings:update", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ran = Can(r.Context(), "anything:else")
	})))
	af := accessFixture{fixture: f}
	org := af.newOrg(t)
	owner := f.signUp(t, testEmail)
	af.addMember(t, org, owner.User.ID, OwnerRole)

	if res := f.do(t, http.MethodPatch, "/v1/settings", "", withToken(owner.Token), inOrg(org)); res.status != http.StatusOK || !ran {
		t.Errorf("owner: status %d, Can(anything) = %v; want 200 and true", res.status, ran)
	}
}

func TestContextInsideHandlers(t *testing.T) {
	t.Parallel()
	f := setupAccess(t)
	org := f.newOrg(t)
	admin := f.signUp(t, "admin@example.com")
	member := f.signUp(t, "member@example.com")
	f.addMember(t, org, admin.User.ID, "admin")
	f.addMember(t, org, member.User.ID, "member")
	if err := f.auth.SetAppRole(context.Background(), admin.User.ID, "auditor"); err != nil {
		t.Fatal(err)
	}

	got := f.seen(t, f.do(t, http.MethodGet, "/v1/invoices", "", withToken(admin.Token), inOrg(org)))
	if got["org_id"] != org.String() || got["org_role"] != "admin" || got["in_org"] != true {
		t.Errorf("OrgFrom under RequireOrg = %v", got)
	}
	// Under RequireOrg, Can uses the organization role, not the app role.
	if got["can_delete"] != true || got["can_audit_users"] != false {
		t.Errorf("admin under RequireOrg: Can = %v; want invoices:delete only", got)
	}
	if got := f.seen(t, f.do(t, http.MethodGet, "/v1/invoices", "", withToken(member.Token), inOrg(org))); got["can_delete"] != false {
		t.Errorf("member under RequireOrg: Can(invoices:delete) = %v, want false", got["can_delete"])
	}
	// Under Authenticated, there's no role to check.
	got = f.seen(t, f.do(t, http.MethodGet, "/v1/profile", "", withToken(admin.Token)))
	if got["in_org"] != false || got["can_delete"] != false || got["can_audit_users"] != false {
		t.Errorf("under Authenticated = %v; want no organization and no permissions", got)
	}
	if _, ok := OrgFrom(context.Background()); ok {
		t.Error("OrgFrom() ok outside any access rule")
	}
	if Can(context.Background(), "invoices:read") {
		t.Error("Can() true outside any access rule")
	}
}

func TestRequire(t *testing.T) {
	t.Parallel()
	f := setupAccess(t)
	ctx := context.Background()
	support := f.signUp(t, "support@example.com")
	auditor := f.signUp(t, "auditor@example.com")
	nobody := f.signUp(t, "nobody@example.com")
	retired := f.signUp(t, "retired@example.com")
	for user, role := range map[uuid.UUID]string{support.User.ID: "support", auditor.User.ID: "auditor"} {
		if err := f.auth.SetAppRole(ctx, user, role); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO auth.user_roles (user_id, role) VALUES ($1, 'moderator')`, retired.User.ID); err != nil {
		t.Fatal(err)
	}

	ban := func(tok string) response {
		return f.do(t, http.MethodPost, "/v1/users/"+uuid.NewString()+"/ban", "", withToken(tok))
	}
	res := ban(support.Token)
	if res.status != http.StatusOK {
		t.Fatalf("support: status %d, body %s", res.status, res.body)
	}
	if got := f.seen(t, res); got["can_ban"] != true || got["in_org"] != false {
		t.Errorf("support under Require: %v", got)
	}
	for name, tok := range map[string]string{"auditor": auditor.Token, "no app role": nobody.Token, "role removed from code": retired.Token} {
		if res := ban(tok); res.status != http.StatusForbidden || res.errorCode(t) != "forbidden" {
			t.Errorf("%s: status %d, body %s; want 403 forbidden", name, res.status, res.body)
		}
	}
	if res := ban(""); res.status != http.StatusUnauthorized {
		t.Errorf("no session: status %d, want 401", res.status)
	}

	// Removing the role takes effect on the next request.
	if err := f.auth.SetAppRole(ctx, support.User.ID, ""); err != nil {
		t.Fatal(err)
	}
	if res := ban(support.Token); res.status != http.StatusForbidden {
		t.Errorf("after removing the role: status %d, want 403", res.status)
	}
}

func TestSetAppRole(t *testing.T) {
	t.Parallel()
	f := setupAccess(t)
	ctx := context.Background()
	u := f.signUp(t, testEmail)

	if err := f.auth.SetAppRole(ctx, u.User.ID, "superuser"); err == nil {
		t.Error("undefined role: error = nil")
	}
	if err := f.auth.SetAppRole(ctx, uuid.Must(uuid.NewV7()), "support"); err == nil {
		t.Error("nonexistent user: error = nil")
	}
	if err := f.auth.SetAppRole(ctx, u.User.ID, "auditor"); err != nil {
		t.Fatal(err)
	}
	if err := f.auth.SetAppRole(ctx, u.User.ID, "support"); err != nil {
		t.Fatalf("replacing the role: %v", err)
	}
	var role string
	if err := f.pool.QueryRow(ctx, `SELECT role FROM auth.user_roles WHERE user_id = $1`, u.User.ID).Scan(&role); err != nil || role != "support" {
		t.Errorf("stored role = %q, err = %v; want support", role, err)
	}
	if err := f.auth.SetAppRole(ctx, u.User.ID, ""); err != nil {
		t.Fatal(err)
	}
	if err := f.auth.SetAppRole(ctx, u.User.ID, ""); err != nil {
		t.Errorf("removing a role twice: %v", err)
	}
}

func TestMembershipChangesApplyImmediately(t *testing.T) {
	t.Parallel()
	f := setupAccess(t)
	ctx := context.Background()
	org := f.newOrg(t)
	u := f.signUp(t, testEmail)
	f.addMember(t, org, u.User.ID, "member")

	create := func() int {
		return f.do(t, http.MethodPost, "/v1/invoices", "", withToken(u.Token), inOrg(org)).status
	}
	if got := create(); got != http.StatusOK {
		t.Fatalf("member: status %d", got)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE auth.memberships SET role = 'viewer' WHERE user_id = $1`, u.User.ID); err != nil {
		t.Fatal(err)
	}
	if got := create(); got != http.StatusForbidden {
		t.Errorf("after demotion: status %d, want 403", got)
	}
	if _, err := f.pool.Exec(ctx, `DELETE FROM auth.memberships WHERE user_id = $1`, u.User.ID); err != nil {
		t.Fatal(err)
	}
	if got := create(); got != http.StatusNotFound {
		t.Errorf("after removal: status %d, want 404", got)
	}
}

func TestMisspelledPermissionsPanic(t *testing.T) {
	t.Parallel()
	f := setupAccess(t)
	h := http.NotFoundHandler()
	noOrgs := setupWith(t, Config{AllowUnverifiedLogin: true})
	for name, register := range map[string]func(){
		"Require with a misspelled permission":    func() { f.auth.Require("user:ban", h) },
		"Require with an organization permission": func() { f.auth.Require("invoices:read", h) },
		"RequireOrg with a misspelled permission": func() { f.auth.RequireOrg("invoice:read", h) },
		"RequireOrg with an app permission":       func() { f.auth.RequireOrg("users:ban", h) },
		"RequireOrg without OrgRoles":             func() { noOrgs.auth.RequireOrg("invoices:read", h) },
		"Require without AppRoles":                func() { noOrgs.auth.Require("users:ban", h) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: didn't panic", name)
				}
			}()
			register()
		}()
	}
}

func TestNewValidatesRoles(t *testing.T) {
	t.Parallel()
	pool := testdb.New(t)
	base := func() Config {
		return Config{DB: pool, Mailer: &mailtest.Recorder{}, AppURL: testAppURL, AppName: "Example"}
	}
	bad := map[string]func(*Config){
		"org roles without owner": func(c *Config) { c.OrgRoles = rbac.Roles{"admin": {"invoices:read"}} },
		"bad org permission":      func(c *Config) { c.OrgRoles = rbac.Roles{OwnerRole: {rbac.All}, "admin": {"Invoices"}} },
		"bad org role name":       func(c *Config) { c.OrgRoles = rbac.Roles{OwnerRole: {rbac.All}, "Admin": {"invoices:read"}} },
		"bad app permission":      func(c *Config) { c.AppRoles = rbac.Roles{"support": {"users"}} },
		"empty but non-nil roles": func(c *Config) { c.OrgRoles = rbac.Roles{} },
	}
	for name, change := range bad {
		cfg := base()
		change(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: New() error = nil", name)
		}
	}
	cfg := base()
	cfg.OrgRoles, cfg.AppRoles = testOrgRoles, testAppRoles
	if _, err := New(cfg); err != nil {
		t.Errorf("valid roles: New() error = %v", err)
	}
}

func TestProtect(t *testing.T) {
	t.Parallel()
	f := setupAccess(t)
	org := f.newOrg(t)
	u := f.signUp(t, testEmail)
	f.addMember(t, org, u.User.ID, "viewer")

	forgotten := false
	f.mux.HandleFunc("GET /v1/reports", func(w http.ResponseWriter, r *http.Request) { forgotten = true })
	logging := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) })
	}
	f.mux.Handle("GET /v1/wrapped-wrong", logging(f.auth.RequireOrg("invoices:read", http.NotFoundHandler())))
	f.mux.Handle("GET /v1/folder/", f.auth.Public(http.NotFoundHandler()))
	protected := f.auth.Protect(f.mux)

	serve := func(method, path string, opts ...reqOpt) *httptest.ResponseRecorder {
		r := httptest.NewRequestWithContext(t.Context(), method, path, nil)
		for _, o := range opts {
			o(r)
		}
		w := httptest.NewRecorder()
		protected.ServeHTTP(w, r)
		return w
	}

	// A route without an access rule never runs, even for a logged-in user.
	w := serve(http.MethodGet, "/v1/reports", withToken(u.Token))
	if w.Code != http.StatusInternalServerError || forgotten {
		t.Errorf("unprotected route: status %d, handler ran = %v; want 500 and not run", w.Code, forgotten)
	}
	if !strings.Contains(w.Body.String(), `"internal_error"`) || strings.Contains(w.Body.String(), "/v1/reports") {
		t.Errorf("body %s: want a generic internal_error", w.Body)
	}
	if w.Header().Get("X-Request-ID") == "" {
		t.Error("no X-Request-ID on the refusal")
	}
	if !strings.Contains(f.logs.String(), "GET /v1/reports") || !strings.Contains(f.logs.String(), "no access rule") {
		t.Errorf("refusal wasn't logged with the route:\n%s", f.logs)
	}
	if w := serve(http.MethodGet, "/v1/wrapped-wrong", withToken(u.Token), inOrg(org)); w.Code != http.StatusInternalServerError {
		t.Errorf("access rule not outermost: status %d, want 500", w.Code)
	}

	// Routes with access rules, and the module's own routes, work as usual.
	checks := []struct {
		name   string
		method string
		path   string
		opts   []reqOpt
		want   int
	}{
		{"RequireOrg", http.MethodGet, "/v1/invoices", []reqOpt{withToken(u.Token), inOrg(org)}, 200},
		{"RequireOrg denying", http.MethodPost, "/v1/invoices", []reqOpt{withToken(u.Token), inOrg(org)}, 403},
		{"Authenticated", http.MethodGet, "/v1/profile", []reqOpt{withToken(u.Token)}, 200},
		{"Public", http.MethodGet, "/v1/status", nil, 200},
		{"module route", http.MethodGet, "/v1/users/me", []reqOpt{withToken(u.Token)}, 200},
		{"module route, logged out", http.MethodGet, "/v1/sessions", nil, 401},
		{"unknown path", http.MethodGet, "/v1/nothing-here", nil, 404},
		{"wrong method", http.MethodDelete, "/v1/invoices", nil, 405},
	}
	for _, c := range checks {
		if w := serve(c.method, c.path, c.opts...); w.Code != c.want {
			t.Errorf("%s: status %d, body %s; want %d", c.name, w.Code, w.Body, c.want)
		}
	}
	// The mux's own redirects (the exact status depends on the Go version).
	if w := serve(http.MethodGet, "/v1/folder"); w.Code/100 != 3 || w.Header().Get("Location") != "/v1/folder/" {
		t.Errorf("trailing-slash redirect: status %d, Location %q", w.Code, w.Header().Get("Location"))
	}
}
