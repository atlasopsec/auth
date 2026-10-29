package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/atlasopsec/auth/internal/testdb"
	"github.com/atlasopsec/auth/mail/mailtest"
)

// setupPrivileged returns the access fixture with owners, admins, and
// support staff required to have 2FA.
func setupPrivileged(t *testing.T) accessFixture {
	t.Helper()
	return setupAccessWith(t, Config{
		AllowUnverifiedLogin: true,
		OrgRoles:             testOrgRoles,
		AppRoles:             testAppRoles,
		TwoFactorRoles:       []string{OwnerRole, "admin", "support"},
	})
}

func TestTwoFactorRolesMustBeDefined(t *testing.T) {
	t.Parallel()
	pool := testdb.New(t)
	cfg := func(roles ...string) Config {
		return Config{
			DB: pool, Mailer: &mailtest.Recorder{}, AppURL: testAppURL, AppName: "Example", EncryptionKey: testEncryptionKey,
			OrgRoles: testOrgRoles, AppRoles: testAppRoles, TwoFactorRoles: roles,
		}
	}
	for _, roles := range [][]string{nil, {"admin"}, {"support"}, {OwnerRole, "admin", "support"}} {
		if _, err := New(cfg(roles...)); err != nil {
			t.Errorf("TwoFactorRoles %v: error = %v", roles, err)
		}
	}
	for _, roles := range [][]string{{"superuser"}, {"admin", "Admin"}} {
		if _, err := New(cfg(roles...)); err == nil {
			t.Errorf("TwoFactorRoles %v: error = nil, want an error", roles)
		}
	}
	noRoles := cfg("admin")
	noRoles.OrgRoles, noRoles.AppRoles = nil, nil
	if _, err := New(noRoles); err == nil {
		t.Error("TwoFactorRoles without any roles defined: error = nil, want an error")
	}
}

type meStatus struct {
	TwoFactorEnabled  bool `json:"two_factor_enabled"`
	TwoFactorRequired bool `json:"two_factor_required"`
}

func (f accessFixture) me(t *testing.T, tok string) meStatus {
	t.Helper()
	res := f.do(t, http.MethodGet, "/v1/users/me", "", withToken(tok))
	var m meStatus
	if res.status != http.StatusOK || json.Unmarshal(res.body, &m) != nil {
		t.Fatalf("GET /v1/users/me: status %d, body %s", res.status, res.body)
	}
	return m
}

func TestRequiredTwoFactorAllowsOnlySetup(t *testing.T) {
	t.Parallel()
	f := setupPrivileged(t)
	l := f.signUp(t, testEmail)
	org := f.newOrg(t)
	f.addMember(t, org, l.User.ID, "member")
	if err := f.auth.SetAppRole(context.Background(), l.User.ID, "auditor", Actor{}); err != nil {
		t.Fatal(err)
	}
	if err := f.auth.SetTwoFactorRequired(context.Background(), l.User.ID, true, Actor{}); err != nil {
		t.Fatal(err)
	}

	blocked := []struct{ method, path string }{
		{http.MethodGet, "/v1/profile"},
		{http.MethodGet, "/v1/invoices"},
		{http.MethodPost, "/v1/users/" + uuid.NewString() + "/ban"},
		{http.MethodGet, "/v1/sessions"},
		{http.MethodDelete, "/v1/sessions"},
		{http.MethodGet, "/v1/organizations"},
	}
	for _, b := range blocked {
		wantError(t, b.method+" "+b.path, f.do(t, b.method, b.path, "", withToken(l.Token), inOrg(org)), 403, "two_factor_setup_required")
	}
	if *f.ran {
		t.Error("a project handler ran for a user who must set up 2FA")
	}
	if m := f.me(t, l.Token); !m.TwoFactorRequired || m.TwoFactorEnabled {
		t.Errorf("GET /v1/users/me = %+v, want required and not enabled", m)
	}
	// Logging out works too.
	other := f.logIn(t, testEmail)
	if res := f.do(t, http.MethodDelete, "/v1/sessions/current", "", withToken(other.Token)); res.status != http.StatusNoContent {
		t.Errorf("logging out: status %d, body %s", res.status, res.body)
	}

	f.enableTwoFactor(t, l.Token)
	for _, b := range blocked[:3] {
		if res := f.do(t, b.method, b.path, "", withToken(l.Token), inOrg(org)); res.status == http.StatusForbidden && res.errorCode(t) == "two_factor_setup_required" {
			t.Errorf("%s %s after setting up 2FA: still blocked", b.method, b.path)
		}
	}
	wantError(t, "turning off required 2FA", f.do(t, http.MethodDelete, "/v1/users/me/two-factor", pwCodeBody(testPassword, "000000"), withToken(l.Token)), 403, "two_factor_required")
}

func TestSetTwoFactorRequired(t *testing.T) {
	t.Parallel()
	f := setupPrivileged(t)
	l := f.signUp(t, testEmail)
	ctx := context.Background()

	if m := f.me(t, l.Token); m.TwoFactorRequired {
		t.Fatal("required before SetTwoFactorRequired")
	}
	if err := f.auth.SetTwoFactorRequired(ctx, l.User.ID, true, Actor{}); err != nil {
		t.Fatal(err)
	}
	wantError(t, "required", f.do(t, http.MethodGet, "/v1/profile", "", withToken(l.Token)), 403, "two_factor_setup_required")
	if err := f.auth.SetTwoFactorRequired(ctx, l.User.ID, false, Actor{}); err != nil {
		t.Fatal(err)
	}
	if res := f.do(t, http.MethodGet, "/v1/profile", "", withToken(l.Token)); res.status != http.StatusOK {
		t.Errorf("no longer required: status %d, body %s", res.status, res.body)
	}
	if err := f.auth.SetTwoFactorRequired(ctx, uuid.Must(uuid.NewV7()), true, Actor{}); err == nil {
		t.Error("unknown user: error = nil, want an error")
	}
}

func TestTwoFactorRolesRequireTwoFactor(t *testing.T) {
	t.Parallel()
	f := setupPrivileged(t)
	org, otherOrg := f.newOrg(t), f.newOrg(t)
	ctx := context.Background()

	for _, tt := range []struct {
		email    string
		role     func(uuid.UUID)
		required bool
	}{
		{"member@example.com", func(id uuid.UUID) { f.addMember(t, org, id, "member") }, false},
		{"viewer@example.com", func(id uuid.UUID) { f.addMember(t, org, id, "viewer") }, false},
		{"auditor@example.com", func(id uuid.UUID) { _ = f.auth.SetAppRole(ctx, id, "auditor", Actor{}) }, false},
		{"admin@example.com", func(id uuid.UUID) { f.addMember(t, org, id, "admin") }, true},
		{"owner@example.com", func(id uuid.UUID) { f.addMember(t, org, id, OwnerRole) }, true},
		{"support@example.com", func(id uuid.UUID) { _ = f.auth.SetAppRole(ctx, id, "support", Actor{}) }, true},
		// An admin anywhere needs 2FA everywhere.
		{"split@example.com", func(id uuid.UUID) {
			f.addMember(t, org, id, "viewer")
			f.addMember(t, otherOrg, id, "admin")
		}, true},
	} {
		l := f.signUp(t, tt.email)
		tt.role(l.User.ID)
		if m := f.me(t, l.Token); m.TwoFactorRequired != tt.required {
			t.Errorf("%s: two_factor_required = %v, want %v", tt.email, m.TwoFactorRequired, tt.required)
		}
		res := f.do(t, http.MethodGet, "/v1/invoices", "", withToken(l.Token), inOrg(org))
		if blocked := res.status == http.StatusForbidden && res.errorCode(t) == "two_factor_setup_required"; blocked != tt.required {
			t.Errorf("%s: status %d, body %s; blocked = %v, want %v", tt.email, res.status, res.body, blocked, tt.required)
		}
	}
}

// loginExpiry returns how long after now a login response's session
// expires.
func (f accessFixture) loginExpiry(t *testing.T, res response) (string, time.Duration) {
	t.Helper()
	var l loginJSON
	if res.status != http.StatusCreated || json.Unmarshal(res.body, &l) != nil {
		t.Fatalf("want a login, got status %d, body %s", res.status, res.body)
	}
	exp, err := time.Parse(time.RFC3339, l.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	return l.Token, exp.Sub(f.clock.now())
}

func TestPrivilegedSessionsLast12Hours(t *testing.T) {
	t.Parallel()
	f := setupPrivileged(t)
	org := f.newOrg(t)
	admin := f.signUp(t, "admin@example.com")
	member := f.signUp(t, "member@example.com")
	f.addMember(t, org, admin.User.ID, "admin")
	f.addMember(t, org, member.User.ID, "member")
	secret, _ := f.enableTwoFactor(t, admin.Token)

	// Logging in with 2FA.
	tok, d := f.loginExpiry(t, f.verify(t, f.startChallenge(t, "admin@example.com"), f.code(secret)))
	if d != 12*time.Hour {
		t.Errorf("admin session expires in %v, want 12h", d)
	}
	_, d = f.loginExpiry(t, f.do(t, http.MethodPost, "/v1/sessions", credentials("member@example.com", testPassword, "web")))
	if d != 30*day {
		t.Errorf("member session expires in %v, want 30 days", d)
	}

	f.clock.advance(12*time.Hour - time.Second)
	if f.status(t, tok) != http.StatusOK {
		t.Fatal("admin session ended early")
	}
	f.clock.advance(time.Second)
	if f.status(t, tok) != http.StatusUnauthorized {
		t.Error("admin session still works after 12 hours")
	}
	if f.status(t, member.Token) != http.StatusOK {
		t.Error("member session ended after 12 hours")
	}
}

func TestPrivilegedSessionsWithoutTwoFactor(t *testing.T) {
	t.Parallel()
	f := setupPrivileged(t)
	org := f.newOrg(t)
	l := f.signUp(t, testEmail)
	f.addMember(t, org, l.User.ID, "admin")
	link := f.emailTokenOf(t, testEmail, 0)

	// An admin who hasn't set up 2FA yet still gets a 12-hour session,
	// from a login or the verification link.
	if _, d := f.loginExpiry(t, f.do(t, http.MethodPost, "/v1/sessions", credentials(testEmail, testPassword, "web"))); d != 12*time.Hour {
		t.Errorf("login: session expires in %v, want 12h", d)
	}
	body, _ := json.Marshal(map[string]string{"token": link, "password": testPassword, "client": "web"})
	if _, d := f.loginExpiry(t, f.do(t, http.MethodPost, "/v1/email-verifications/confirm", string(body))); d != 12*time.Hour {
		t.Errorf("verification link: session expires in %v, want 12h", d)
	}
}

func TestPromotionEndsLongSessions(t *testing.T) {
	t.Parallel()
	f := setupPrivileged(t)
	org := f.newOrg(t)
	l := f.signUp(t, testEmail)
	stays := f.signUp(t, "grace@example.com")
	f.addMember(t, org, l.User.ID, "member")
	f.addMember(t, org, stays.User.ID, "member")
	f.enableTwoFactor(t, l.Token)

	// Promoted 11 hours into a regular session.
	f.clock.advance(11 * time.Hour)
	if _, err := f.pool.Exec(context.Background(), `UPDATE auth.memberships SET role = 'admin' WHERE user_id = $1`, l.User.ID); err != nil {
		t.Fatal(err)
	}
	if f.status(t, l.Token) != http.StatusOK {
		t.Fatal("session ended right after the promotion, before 12 hours")
	}
	f.clock.advance(time.Hour)
	if f.status(t, l.Token) != http.StatusUnauthorized {
		t.Error("session still works 12 hours in, after a promotion")
	}
	if n := f.sessionCount(t, l.User.ID); n != 0 {
		t.Errorf("%d sessions left, want the expired one deleted", n)
	}
	if f.status(t, stays.Token) != http.StatusOK {
		t.Error("a member's session ended after 12 hours")
	}
}
