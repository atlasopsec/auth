package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/atlasopsec/auth/internal/oauth/oauthtest"
	"github.com/atlasopsec/auth/internal/totp"
)

// setupManaged has accounts copied in from code, with
// AccountsManagedElsewhere on: an owner and a member of one organization,
// both able to log in.
func setupManaged(t *testing.T) (orgFixture, team) {
	t.Helper()
	f := setupRoles(t, Config{AccountsManagedElsewhere: true})
	ctx := context.Background()
	tm := team{users: map[string]loginJSON{}}
	var ids []uuid.UUID
	for _, email := range []string{"owner@example.com", "member@example.com"} {
		u, err := f.auth.CreateUser(ctx, NewUser{Email: email, PasswordHash: testHash(t, testPassword)}, Actor{})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, u.ID)
	}
	o, err := f.auth.CreateOrganization(ctx, "Acme", ids[0], Actor{})
	if err != nil {
		t.Fatal(err)
	}
	tm.org = o.ID
	if err := f.auth.SetMemberRole(ctx, tm.org, ids[1], "member", Actor{}); err != nil {
		t.Fatal(err)
	}
	tm.users[OwnerRole] = f.logIn(t, "owner@example.com")
	tm.users["member"] = f.logIn(t, "member@example.com")
	return f, tm
}

func TestAccountsManagedElsewhereTurnsOffChanges(t *testing.T) {
	t.Parallel()
	f, tm := setupManaged(t)
	owner, member := tm.users[OwnerRole], tm.users["member"]
	role, err := f.auth.CreateOrgRole(context.Background(), tm.org, "Clerk", nil, Actor{})
	if err != nil {
		t.Fatal(err)
	}
	tok := withToken(owner.Token)
	off := []struct {
		method, path, body string
		opts               []reqOpt
	}{
		{http.MethodPost, "/v1/users", credentials("new@example.com", testPassword, "web"), nil},
		{http.MethodPost, "/v1/email-verifications", `{"email":"owner@example.com"}`, nil},
		{http.MethodPost, "/v1/email-verifications/confirm", `{"token":"x","password":"y"}`, nil},
		{http.MethodPost, "/v1/password-resets", `{"email":"owner@example.com"}`, nil},
		{http.MethodPost, "/v1/password-resets/confirm", `{"token":"x","password":"a new long password"}`, nil},
		{http.MethodPost, "/v1/users/me/password", `{"current_password":"` + testPassword + `","new_password":"a new long password"}`, []reqOpt{tok}},
		{http.MethodPost, "/v1/email-changes", `{"email":"elsewhere@example.com"}`, []reqOpt{tok}},
		{http.MethodPost, "/v1/email-changes/confirm", `{"token":"x"}`, nil},
		{http.MethodPost, "/v1/users/me/two-factor", "", []reqOpt{tok}},
		{http.MethodPost, "/v1/users/me/two-factor/confirm", `{"code":"123456"}`, []reqOpt{tok}},
		{http.MethodDelete, "/v1/users/me/two-factor", `{"current_password":"` + testPassword + `","code":"123456"}`, []reqOpt{tok}},
		{http.MethodPost, "/v1/organizations", `{"name":"Another"}`, []reqOpt{tok}},
		{http.MethodPatch, tm.path("/members/" + member.User.ID.String()), `{"role":"viewer"}`, []reqOpt{tok}},
		{http.MethodDelete, tm.path("/members/" + member.User.ID.String()), "", []reqOpt{tok}},
		{http.MethodDelete, tm.path("/members/" + member.User.ID.String()), "", []reqOpt{withToken(member.Token)}},
		{http.MethodPost, tm.path("/invitations"), `{"email":"new@example.com","role":"member"}`, []reqOpt{tok}},
		{http.MethodGet, tm.path("/invitations"), "", []reqOpt{tok}},
		{http.MethodPost, "/v1/invitations/accept", `{"token":"x"}`, []reqOpt{tok}},
		{http.MethodPost, tm.path("/roles"), roleBody("Another"), []reqOpt{tok}},
		{http.MethodPatch, tm.path("/roles/" + role.ID.String()), `{"name":"Renamed"}`, []reqOpt{tok}},
		{http.MethodDelete, tm.path("/roles/" + role.ID.String()), "", []reqOpt{tok}},
		{http.MethodPost, "/v1/users/me/oauth-accounts", startBody(providerGoogle, "web", "x"), []reqOpt{tok}},
		{http.MethodDelete, "/v1/users/me/oauth-accounts/" + uuid.NewString(), "", []reqOpt{tok}},
	}
	for _, tt := range off {
		res := f.do(t, tt.method, tt.path, tt.body, tt.opts...)
		if res.status != http.StatusNotFound && res.status != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: status %d, body %s; want no such route", tt.method, tt.path, res.status, res.body)
		}
	}

	// Nothing changed.
	if n := f.userCount(t); n != 2 {
		t.Errorf("%d users, want 2", n)
	}
	if role := f.roleOf(t, tm.org, member.User.ID); role != "member" {
		t.Errorf("member's role is %q", role)
	}
	roles, err := f.auth.ListOrgRoles(context.Background(), tm.org)
	if err != nil || len(roles) != 1 || roles[0].Name != "Clerk" {
		t.Errorf("roles = %+v (%v), want Clerk alone", roles, err)
	}
	f.logIn(t, "owner@example.com")
}

func TestAccountsManagedElsewhereKeepsSignIn(t *testing.T) {
	t.Parallel()
	f, tm := setupManaged(t)
	ctx := context.Background()
	owner, member := tm.users[OwnerRole], tm.users["member"]

	for _, tt := range []struct {
		method, path string
		tok          string
		want         int
	}{
		{http.MethodGet, "/v1/users/me", owner.Token, http.StatusOK},
		{http.MethodGet, "/v1/sessions", owner.Token, http.StatusOK},
		{http.MethodGet, "/v1/organizations", owner.Token, http.StatusOK},
		{http.MethodGet, tm.path(""), owner.Token, http.StatusOK},
		{http.MethodGet, tm.path("/members"), owner.Token, http.StatusOK},
		{http.MethodGet, tm.path("/roles"), member.Token, http.StatusOK},
		{http.MethodGet, "/v1/invoices", member.Token, http.StatusOK},
		{http.MethodGet, "/v1/users/me/oauth-accounts", owner.Token, http.StatusOK},
	} {
		if res := f.do(t, tt.method, tt.path, "", withToken(tt.tok), inOrg(tm.org)); res.status != tt.want {
			t.Errorf("%s %s: status %d, body %s; want %d", tt.method, tt.path, res.status, res.body, tt.want)
		}
	}
	if res := f.do(t, http.MethodPatch, tm.path(""), `{"name":"Acme Ltd"}`, withToken(owner.Token)); res.status != http.StatusOK {
		t.Errorf("renaming the organization: status %d", res.status)
	}

	// 2FA imported from code works at login, and the user can make
	// recovery codes.
	secret := []byte("0123456789abcdefghij")
	if err := f.auth.ImportTwoFactor(ctx, member.User.ID, totp.EncodeSecret(secret), Actor{}); err != nil {
		t.Fatal(err)
	}
	res := f.do(t, http.MethodPost, "/v1/sessions", credentials("member@example.com", testPassword, "web"))
	l := loginOf(t, f.verify(t, challengeIn(t, res), f.code(secret)))
	f.clock.advance(totp.Period)
	body, _ := json.Marshal(map[string]string{"current_password": testPassword, "code": f.code(secret)})
	if res := f.do(t, http.MethodPost, "/v1/users/me/two-factor/recovery-codes", string(body), withToken(l.Token)); res.status != http.StatusOK {
		t.Errorf("recovery codes: status %d, body %s", res.status, res.body)
	}

	// Logging out still works, one session and everywhere.
	if res := f.do(t, http.MethodDelete, "/v1/sessions/current", "", withToken(l.Token)); res.status != http.StatusNoContent {
		t.Errorf("logging out: status %d", res.status)
	}
	if res := f.do(t, http.MethodDelete, "/v1/sessions", "", withToken(owner.Token)); res.status != http.StatusNoContent {
		t.Errorf("logging out everywhere: status %d", res.status)
	}
}

func TestAccountsManagedElsewhereProviders(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{AccountsManagedElsewhere: true})
	ctx := context.Background()
	before := f.userCount(t)

	// No account has this Google account: signing in would create one.
	wantError(t, "new provider account", f.googleSignIn(t, oauthtest.GoogleUser{Subject: "g-new", Email: "new@example.com", EmailVerified: true}), 403, "sign_up_not_allowed")
	if n := f.userCount(t); n != before {
		t.Errorf("%d users, want %d", n, before)
	}
	// An existing account by email: signing in would link it.
	u, err := f.auth.CreateUser(ctx, NewUser{Email: testEmail}, Actor{})
	if err != nil {
		t.Fatal(err)
	}
	wantError(t, "link by email", f.googleSignIn(t, ada("g-ada")), 403, "sign_up_not_allowed")
	var n int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM auth.oauth_accounts`).Scan(&n); err != nil || n != 0 {
		t.Errorf("%d provider accounts linked (%v), want 0", n, err)
	}

	// A provider account already linked still signs in.
	if _, err := f.pool.Exec(ctx, `INSERT INTO auth.oauth_accounts (id, user_id, provider, provider_user_id, email) VALUES ($1, $2, 'google', 'g-ada', $3)`, uuid.New(), u.ID, testEmail); err != nil {
		t.Fatal(err)
	}
	if l := loginOf(t, f.googleSignIn(t, ada("g-ada"))); l.User.ID != u.ID {
		t.Errorf("signed in as %v, want %v", l.User.ID, u.ID)
	}
}

func TestAccountsManagedElsewhereImpliesNoOrganizationCreation(t *testing.T) {
	t.Parallel()
	f, _ := setupManaged(t)
	if !f.auth.disableOrgCreation {
		t.Error("organization creation is on")
	}
}
