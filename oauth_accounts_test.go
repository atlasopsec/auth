package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/atlasopsec/auth/internal/oauth/oauthtest"
	"github.com/atlasopsec/auth/internal/token"
)

func linkBody(provider, challenge, pw string) string {
	b, _ := json.Marshal(map[string]string{"provider": provider, "client": "web", "client_challenge": challenge, "current_password": pw})
	return string(b)
}

// startLink starts linking provider for the session tok, and returns the
// authorization URL and client verifier.
func (f oauthFixture) startLink(t *testing.T, tok, provider, pw string) (string, string) {
	t.Helper()
	verifier := token.New()
	res := f.do(t, http.MethodPost, "/v1/users/me/oauth-accounts", linkBody(provider, challengeOf(verifier), pw), withToken(tok))
	var flow struct {
		AuthorizationURL string `json:"authorization_url"`
	}
	if res.status != http.StatusCreated || json.Unmarshal(res.body, &flow) != nil {
		t.Fatalf("starting a link: status %d, body %s", res.status, res.body)
	}
	return flow.AuthorizationURL, verifier
}

// linkGitHub links GitHub user ghID for the session tok.
func (f oauthFixture) linkGitHub(t *testing.T, tok, pw string, ghID int64) response {
	t.Helper()
	authURL, verifier := f.startLink(t, tok, providerGitHub, pw)
	code, state := f.github.Authorize(authURL, oauthtest.GitHubUser{ID: ghID, Emails: []oauthtest.GitHubEmail{{Email: "ada@github.example", Primary: true}}})
	return f.do(t, http.MethodPost, "/v1/oauth-flows/complete", completeBody(state, code, verifier), withToken(tok))
}

type oauthAccountsJSON struct {
	Data []struct {
		ID       uuid.UUID `json:"id"`
		Provider string    `json:"provider"`
		Email    string    `json:"email"`
	} `json:"data"`
	NextCursor *string `json:"next_cursor"`
}

func (f oauthFixture) oauthAccounts(t *testing.T, tok string) oauthAccountsJSON {
	t.Helper()
	res := f.do(t, http.MethodGet, "/v1/users/me/oauth-accounts", "", withToken(tok))
	var l oauthAccountsJSON
	if res.status != http.StatusOK || json.Unmarshal(res.body, &l) != nil {
		t.Fatalf("listing: status %d, body %s", res.status, res.body)
	}
	return l
}

func (f oauthFixture) unlink(t *testing.T, tok string, id uuid.UUID, pw string) response {
	t.Helper()
	return f.do(t, http.MethodDelete, "/v1/users/me/oauth-accounts/"+id.String(), pwBody(pw), withToken(tok))
}

// wantDetail checks res is a 422 with the field error fc ("field:code").
func wantDetail(t *testing.T, what string, res response, fc string) {
	t.Helper()
	if res.status != http.StatusUnprocessableEntity || !strings.Contains(string(res.body), detailJSON(fc)) {
		t.Errorf("%s: status %d, body %s; want 422 with %s", what, res.status, res.body, fc)
	}
}

func (f oauthFixture) lastSubject(addr string) string {
	emails := f.emailsTo(addr)
	if len(emails) == 0 {
		return ""
	}
	return emails[len(emails)-1].Subject
}

func TestLinkProvider(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{AllowUnverifiedLogin: true})
	v := f.verifiedUser(t, testEmail)
	if l := f.oauthAccounts(t, v.Token); len(l.Data) != 0 || l.NextCursor != nil {
		t.Errorf("before linking: %+v", l)
	}
	if res := f.do(t, http.MethodGet, "/v1/users/me/oauth-accounts", "", withToken(v.Token)); !strings.Contains(string(res.body), `"data":[]`) {
		t.Errorf("empty list = %s, want data: []", res.body)
	}

	challenge := challengeOf(token.New())
	wantDetail(t, "no password", f.do(t, http.MethodPost, "/v1/users/me/oauth-accounts", linkBody(providerGitHub, challenge, ""), withToken(v.Token)), "current_password:required")
	wantDetail(t, "wrong password", f.do(t, http.MethodPost, "/v1/users/me/oauth-accounts", linkBody(providerGitHub, challenge, "not my password"), withToken(v.Token)), "current_password:incorrect")
	wantError(t, "not logged in", f.do(t, http.MethodPost, "/v1/users/me/oauth-accounts", linkBody(providerGitHub, challenge, testPassword)), 401, "unauthenticated")

	res := f.linkGitHub(t, v.Token, testPassword, 7)
	var acct struct {
		ID       uuid.UUID `json:"id"`
		Provider string    `json:"provider"`
		Email    string    `json:"email"`
	}
	if res.status != http.StatusCreated || json.Unmarshal(res.body, &acct) != nil {
		t.Fatalf("finishing the link: status %d, body %s", res.status, res.body)
	}
	if acct.Provider != providerGitHub || acct.Email != "ada@github.example" {
		t.Errorf("linked account = %+v", acct)
	}
	if l := f.oauthAccounts(t, v.Token); len(l.Data) != 1 || l.Data[0].ID != acct.ID {
		t.Errorf("after linking: %+v", l)
	}
	if got := f.lastSubject(testEmail); got != "GitHub sign-in was added to your Example account" {
		t.Errorf("last email = %q, want the linked notice", got)
	}

	// GitHub now signs in to this account, though its email isn't
	// verified there: linking matched it by ID.
	authURL, verifier := f.startFlow(t, providerGitHub, "web")
	code, state := f.github.Authorize(authURL, oauthtest.GitHubUser{ID: 7})
	if l := loginOf(t, f.complete(t, state, code, verifier)); l.User.ID != v.User.ID {
		t.Errorf("GitHub signed in as %s, want %s", l.User.ID, v.User.ID)
	}
}

func TestLinkNeedsTheSameSession(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{AllowUnverifiedLogin: true})
	ada := f.verifiedUser(t, testEmail)
	grace := f.verifiedUser(t, "grace@example.com")

	authURL, verifier := f.startLink(t, ada.Token, providerGitHub, testPassword)
	code, state := f.github.Authorize(authURL, oauthtest.GitHubUser{ID: 7})
	wantError(t, "no session", f.complete(t, state, code, verifier), 401, "oauth_failed")
	wantError(t, "another user's session", f.do(t, http.MethodPost, "/v1/oauth-flows/complete", completeBody(state, code, verifier), withToken(grace.Token)), 401, "oauth_failed")
	wantError(t, "a made-up session", f.do(t, http.MethodPost, "/v1/oauth-flows/complete", completeBody(state, code, verifier), withToken(token.New())), 401, "oauth_failed")
	if l := f.oauthAccounts(t, grace.Token); len(l.Data) != 0 {
		t.Errorf("linked to grace: %+v", l)
	}
	// None of those spent the flow.
	if res := f.do(t, http.MethodPost, "/v1/oauth-flows/complete", completeBody(state, code, verifier), withToken(ada.Token)); res.status != http.StatusCreated {
		t.Errorf("ada's session: status %d, body %s", res.status, res.body)
	}
}

func TestLinkRejects(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{AllowUnverifiedLogin: true})
	ada := f.verifiedUser(t, testEmail)
	grace := f.verifiedUser(t, "grace@example.com")
	if res := f.linkGitHub(t, ada.Token, testPassword, 7); res.status != http.StatusCreated {
		t.Fatalf("linking: status %d, body %s", res.status, res.body)
	}

	wantError(t, "a second GitHub account", f.do(t, http.MethodPost, "/v1/users/me/oauth-accounts", linkBody(providerGitHub, challengeOf(token.New()), testPassword), withToken(ada.Token)), 409, "oauth_already_linked")
	wantError(t, "ada's GitHub account, for grace", f.linkGitHub(t, grace.Token, testPassword, 7), 409, "oauth_account_in_use")

	// A second GitHub account linked while a flow was open.
	authURL, verifier := f.startLink(t, grace.Token, providerGitHub, testPassword)
	if res := f.linkGitHub(t, grace.Token, testPassword, 8); res.status != http.StatusCreated {
		t.Fatalf("linking: status %d, body %s", res.status, res.body)
	}
	code, state := f.github.Authorize(authURL, oauthtest.GitHubUser{ID: 9})
	wantError(t, "linked meanwhile", f.do(t, http.MethodPost, "/v1/oauth-flows/complete", completeBody(state, code, verifier), withToken(grace.Token)), 409, "oauth_already_linked")
}

func TestUnlink(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{AllowUnverifiedLogin: true})
	ada := f.verifiedUser(t, testEmail)
	grace := f.verifiedUser(t, "grace@example.com")
	f.linkGitHub(t, ada.Token, testPassword, 7)
	f.linkGitHub(t, grace.Token, testPassword, 8)
	adaGitHub := f.oauthAccounts(t, ada.Token).Data[0].ID
	graceGitHub := f.oauthAccounts(t, grace.Token).Data[0].ID

	wantDetail(t, "no password", f.unlink(t, ada.Token, adaGitHub, ""), "current_password:required")
	wantDetail(t, "wrong password", f.unlink(t, ada.Token, adaGitHub, "not my password"), "current_password:incorrect")
	wantError(t, "another user's account", f.unlink(t, ada.Token, graceGitHub, testPassword), 404, "not_found")
	wantError(t, "unknown account", f.unlink(t, ada.Token, uuid.Must(uuid.NewV7()), testPassword), 404, "not_found")
	wantError(t, "malformed ID", f.do(t, http.MethodDelete, "/v1/users/me/oauth-accounts/nope", pwBody(testPassword), withToken(ada.Token)), 404, "not_found")
	if len(f.oauthAccounts(t, grace.Token).Data) != 1 {
		t.Fatal("grace's account was removed")
	}

	if res := f.unlink(t, ada.Token, adaGitHub, testPassword); res.status != http.StatusNoContent {
		t.Fatalf("unlinking: status %d, body %s", res.status, res.body)
	}
	if l := f.oauthAccounts(t, ada.Token); len(l.Data) != 0 {
		t.Errorf("after unlinking: %+v", l)
	}
	if got := f.lastSubject(testEmail); got != "GitHub sign-in was removed from your Example account" {
		t.Errorf("last email = %q, want the unlinked notice", got)
	}
}

func TestLastLoginMethod(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{})
	// Signed up with Google: no password.
	l := loginOf(t, f.googleSignIn(t, ada("g-1")))
	google := f.oauthAccounts(t, l.Token).Data[0].ID

	wantError(t, "the only way in", f.unlink(t, l.Token, google, ""), 409, "last_login_method")
	// No password to give, so linking takes the session alone.
	if res := f.linkGitHub(t, l.Token, "", 7); res.status != http.StatusCreated {
		t.Fatalf("linking GitHub: status %d, body %s", res.status, res.body)
	}
	if res := f.unlink(t, l.Token, google, ""); res.status != http.StatusNoContent {
		t.Fatalf("unlinking Google with GitHub left: status %d, body %s", res.status, res.body)
	}
	github := f.oauthAccounts(t, l.Token).Data[0].ID
	wantError(t, "GitHub, now the only way in", f.unlink(t, l.Token, github, ""), 409, "last_login_method")
}

// TestUnlinksWaitForEachOther checks two unlinks can't each leave the
// other account as the last way in, and then both go through.
func TestUnlinksWaitForEachOther(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{})
	l := loginOf(t, f.googleSignIn(t, ada("g-1")))
	f.linkGitHub(t, l.Token, "", 7)
	accts := f.oauthAccounts(t, l.Token).Data
	ctx := context.Background()

	// Another request is unlinking Google: it holds the lock and has
	// deleted it, but hasn't committed.
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT 1 FROM auth.users WHERE id = $1 FOR UPDATE`, l.User.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM auth.oauth_accounts WHERE id = $1`, accts[0].ID); err != nil {
		t.Fatal(err)
	}

	result := make(chan response, 1)
	go func() { result <- f.unlink(t, l.Token, accts[1].ID, "") }()
	f.waitForLock(t, result)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	wantError(t, "unlinking the other at the same time", <-result, 409, "last_login_method")
}

func TestOAuthNoticesCanBeCustomized(t *testing.T) {
	t.Parallel()
	var got []EmailData
	custom := func(name string) func(EmailData) (string, string, string) {
		return func(d EmailData) (string, string, string) {
			got = append(got, d)
			return name, "", ""
		}
	}
	f := setupOAuth(t, Config{AllowUnverifiedLogin: true, Emails: Emails{OAuthLinked: custom("linked"), OAuthUnlinked: custom("unlinked")}})
	v := f.verifiedUser(t, testEmail)
	f.linkGitHub(t, v.Token, testPassword, 7)
	f.unlink(t, v.Token, f.oauthAccounts(t, v.Token).Data[0].ID, testPassword)
	f.sent()

	var providers []string
	for _, d := range got {
		providers = append(providers, d.Provider)
	}
	if diff := cmp.Diff([]string{"GitHub", "GitHub"}, providers); diff != "" {
		t.Errorf("template data providers (-want +got):\n%s", diff)
	}
}
