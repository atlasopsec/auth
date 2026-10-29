package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/atlasopsec/auth/internal/oauth"
	"github.com/atlasopsec/auth/internal/oauth/oauthtest"
	"github.com/atlasopsec/auth/internal/testdb"
	"github.com/atlasopsec/auth/internal/token"
	"github.com/atlasopsec/auth/mail/mailtest"
)

type oauthFixture struct {
	accessFixture
	google *oauthtest.Google
	github *oauthtest.GitHub
}

// setupOAuth returns the access fixture with Google and GitHub sign-in,
// pointed at fakes.
func setupOAuth(t *testing.T, cfg Config) oauthFixture {
	t.Helper()
	cfg.OrgRoles, cfg.AppRoles = testOrgRoles, testAppRoles
	cfg.OAuth = OAuth{
		Google: &Google{ClientID: oauthtest.ClientID, ClientSecret: oauthtest.ClientSecret},
		GitHub: &GitHub{ClientID: oauthtest.ClientID, ClientSecret: oauthtest.ClientSecret},
	}
	f := oauthFixture{accessFixture: setupAccessWith(t, cfg)}
	f.google = oauthtest.NewGoogle(t, f.clock.now)
	f.github = oauthtest.NewGitHub(t)
	f.auth.providers[providerGoogle] = oauth.NewGoogle(oauthtest.ClientID, oauthtest.ClientSecret, f.google.Endpoints(), f.clock.now)
	f.auth.providers[providerGitHub] = oauth.NewGitHub(oauthtest.ClientID, oauthtest.ClientSecret, f.github.Endpoints())
	return f
}

func challengeOf(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func startBody(provider, client, challenge string) string {
	b, _ := json.Marshal(map[string]string{"provider": provider, "client": client, "client_challenge": challenge})
	return string(b)
}

func completeBody(state, code, verifier string) string {
	b, _ := json.Marshal(map[string]string{"state": state, "code": code, "client_verifier": verifier})
	return string(b)
}

// startFlow starts a sign-in and returns the authorization URL and the
// client verifier.
func (f oauthFixture) startFlow(t *testing.T, provider, client string) (string, string) {
	t.Helper()
	verifier := token.New()
	res := f.do(t, http.MethodPost, "/v1/oauth-flows", startBody(provider, client, challengeOf(verifier)))
	var flow struct {
		AuthorizationURL string `json:"authorization_url"`
	}
	if res.status != http.StatusCreated || json.Unmarshal(res.body, &flow) != nil {
		t.Fatalf("starting a flow: status %d, body %s", res.status, res.body)
	}
	return flow.AuthorizationURL, verifier
}

func (f oauthFixture) complete(t *testing.T, state, code, verifier string) response {
	t.Helper()
	return f.do(t, http.MethodPost, "/v1/oauth-flows/complete", completeBody(state, code, verifier))
}

// googleSignIn signs in with Google as u, from the web.
func (f oauthFixture) googleSignIn(t *testing.T, u oauthtest.GoogleUser) response {
	t.Helper()
	authURL, verifier := f.startFlow(t, providerGoogle, "web")
	code, state := f.google.Authorize(authURL, u)
	return f.complete(t, state, code, verifier)
}

func ada(sub string) oauthtest.GoogleUser {
	return oauthtest.GoogleUser{Subject: sub, Email: testEmail, EmailVerified: true}
}

func loginOf(t *testing.T, res response) loginJSON {
	t.Helper()
	var l loginJSON
	if res.status != http.StatusCreated || json.Unmarshal(res.body, &l) != nil {
		t.Fatalf("want a login, got status %d, body %s", res.status, res.body)
	}
	return l
}

func TestOAuthConfig(t *testing.T) {
	t.Parallel()
	pool := testdb.New(t)
	cfg := func(o OAuth) Config {
		return Config{DB: pool, Mailer: &mailtest.Recorder{}, AppURL: testAppURL, AppName: "Example", EncryptionKey: testEncryptionKey, OAuth: o}
	}
	for name, o := range map[string]OAuth{
		"Google without secret": {Google: &Google{ClientID: "id"}},
		"Google without ID":     {Google: &Google{ClientSecret: "secret"}},
		"GitHub without secret": {GitHub: &GitHub{ClientID: "id"}},
		"GitHub without ID":     {GitHub: &GitHub{ClientSecret: "secret"}},
	} {
		if _, err := New(cfg(o)); err == nil {
			t.Errorf("%s: error = nil, want an error", name)
		}
	}
	a, err := New(cfg(OAuth{GitHub: &GitHub{ClientID: "id", ClientSecret: "secret"}}))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.providers[providerGoogle]; ok {
		t.Error("Google is on without being configured")
	}
}

func TestOAuthSignUp(t *testing.T) {
	t.Parallel()
	var hooked User
	f := setupOAuth(t, Config{Hooks: Hooks{OnUserCreated: func(_ context.Context, _ pgx.Tx, u User) error {
		hooked = u
		return nil
	}}})
	sent := len(f.sent())

	// From the mobile app: the provider sends the user to the mobile page.
	authURL, verifier := f.startFlow(t, providerGoogle, "mobile")
	u, _ := url.Parse(authURL)
	if got := u.Query().Get("redirect_uri"); got != testAppURL+"/oauth/callback/mobile" {
		t.Errorf("redirect_uri = %s, want the mobile callback page", got)
	}
	code, state := f.google.Authorize(authURL, ada("g-1"))
	l := loginOf(t, f.complete(t, state, code, verifier))
	if l.User.Email != testEmail || !l.User.EmailVerified {
		t.Errorf("user = %+v, want ada with a verified email", l.User)
	}
	if hooked.ID != l.User.ID || !hooked.EmailVerified {
		t.Errorf("OnUserCreated got %+v, want the new, verified user", hooked)
	}
	if f.passwordHash(t, testEmail) != nil {
		t.Error("an OAuth sign-up has a password")
	}
	var client string
	if err := f.pool.QueryRow(context.Background(), `SELECT client FROM auth.sessions WHERE token_hash = $1`, token.Hash(l.Token)).Scan(&client); err != nil || client != "mobile" {
		t.Errorf("session client = %q (%v), want mobile", client, err)
	}
	if f.status(t, l.Token) != http.StatusOK {
		t.Error("the session doesn't work")
	}
	if len(f.sent()) != sent {
		t.Error("an OAuth sign-up sent email; the provider already verified the address")
	}

	// Later sign-ins match by Google's ID, even after the address there
	// changed and isn't verified.
	again := loginOf(t, f.googleSignIn(t, oauthtest.GoogleUser{Subject: "g-1", Email: "new@example.com"}))
	if again.User.ID != l.User.ID {
		t.Errorf("second sign-in: user %s, want %s", again.User.ID, l.User.ID)
	}
	if f.userCount(t) != 1 {
		t.Errorf("%d users, want 1", f.userCount(t))
	}
}

func TestOAuthWithGitHub(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{AllowUnverifiedLogin: true})
	signIn := func(u oauthtest.GitHubUser) response {
		authURL, verifier := f.startFlow(t, providerGitHub, "web")
		code, state := f.github.Authorize(authURL, u)
		return f.complete(t, state, code, verifier)
	}
	l := loginOf(t, signIn(oauthtest.GitHubUser{ID: 7, Emails: []oauthtest.GitHubEmail{{Email: testEmail, Primary: true, Verified: true}}}))
	if l.User.Email != testEmail {
		t.Errorf("user = %+v", l.User)
	}
	wantError(t, "unverified primary email", signIn(oauthtest.GitHubUser{ID: 8, Emails: []oauthtest.GitHubEmail{{Email: "grace@example.com", Primary: true}}}), 403, "oauth_email_not_verified")
}

func TestOAuthLinksVerifiedAccount(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{AllowUnverifiedLogin: true})
	existing := f.verifiedUser(t, testEmail)

	// The provider's address differs only in case.
	l := loginOf(t, f.googleSignIn(t, oauthtest.GoogleUser{Subject: "g-1", Email: strings.ToUpper(testEmail), EmailVerified: true}))
	if l.User.ID != existing.User.ID {
		t.Fatalf("signed in as %s, want the existing account %s", l.User.ID, existing.User.ID)
	}
	if f.canLogIn(t, testEmail, testPassword) != http.StatusCreated {
		t.Error("the password stopped working")
	}
	if f.status(t, existing.Token) != http.StatusOK {
		t.Error("the existing session ended")
	}
	if f.userCount(t) != 1 {
		t.Errorf("%d users, want 1", f.userCount(t))
	}
}

func TestOAuthRefusesUnverifiedProviderEmail(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{AllowUnverifiedLogin: true})
	existing := f.verifiedUser(t, testEmail)

	for name, u := range map[string]oauthtest.GoogleUser{
		"existing account": {Subject: "g-1", Email: testEmail},
		"new address":      {Subject: "g-2", Email: "grace@example.com"},
		"no address":       {Subject: "g-3"},
	} {
		wantError(t, name, f.googleSignIn(t, u), 403, "oauth_email_not_verified")
	}
	if f.userCount(t) != 1 {
		t.Errorf("%d users, want 1", f.userCount(t))
	}
	var linked int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM auth.oauth_accounts`).Scan(&linked); err != nil || linked != 0 {
		t.Errorf("%d linked accounts (%v), want 0", linked, err)
	}
	// Verified later at Google, it links.
	if l := loginOf(t, f.googleSignIn(t, ada("g-1"))); l.User.ID != existing.User.ID {
		t.Error("didn't link once verified")
	}
}

// TestOAuthTakesBackUnverifiedAccount is the pre-hijacking case: someone
// signed up with Ada's address first, and Ada then signs in with Google.
func TestOAuthTakesBackUnverifiedAccount(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{AllowUnverifiedLogin: true})
	squatter := f.signUp(t, testEmail)
	secret, _ := f.enableTwoFactor(t, squatter.Token)
	pending := f.startChallenge(t, testEmail)
	link := f.emailTokenOf(t, testEmail, 0)

	l := loginOf(t, f.googleSignIn(t, ada("g-1")))
	if l.User.ID != squatter.User.ID || !l.User.EmailVerified {
		t.Fatalf("user = %+v, want the same account, now verified", l.User)
	}
	if f.passwordHash(t, testEmail) != nil {
		t.Error("the squatter's password still works")
	}
	if f.status(t, squatter.Token) != http.StatusUnauthorized {
		t.Error("the squatter's session still works")
	}
	if f.twoFactorEnabled(t, l.Token) {
		t.Error("the squatter's 2FA is still on")
	}
	wantError(t, "the squatter's pending 2FA login", f.verify(t, pending, f.code(secret)), 401, "two_factor_challenge_invalid")
	var codes int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM auth.recovery_codes WHERE user_id = $1`, l.User.ID).Scan(&codes); err != nil || codes != 0 {
		t.Errorf("%d of the squatter's recovery codes left (%v), want 0", codes, err)
	}
	body, _ := json.Marshal(map[string]string{"token": link, "password": testPassword, "client": "web"})
	wantError(t, "the squatter's verification link", f.do(t, http.MethodPost, "/v1/email-verifications/confirm", string(body)), 422, "token_invalid_or_expired")
	if !strings.Contains(f.logs.String(), "auth: unverified account taken back") {
		t.Error("taking the account back wasn't logged")
	}
}

func TestOAuthWithTwoFactor(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{AllowUnverifiedLogin: true})
	v := f.verifiedUser(t, testEmail)
	secret, _ := f.enableTwoFactor(t, v.Token)

	res := f.googleSignIn(t, ada("g-1"))
	if res.status != http.StatusOK {
		t.Fatalf("status %d, body %s; want a 2FA challenge", res.status, res.body)
	}
	if l := loginOf(t, f.verify(t, challengeIn(t, res), f.code(secret))); l.User.ID != v.User.ID {
		t.Errorf("logged in as %s, want %s", l.User.ID, v.User.ID)
	}

	f.tripGuessingLimit(t, v.User.ID)
	wantError(t, "while paused", f.googleSignIn(t, ada("g-1")), 429, "rate_limited")
}

func TestOAuthPrivilegedSessions(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{AllowUnverifiedLogin: true, TwoFactorRoles: []string{"admin"}})
	v := f.verifiedUser(t, testEmail)
	f.addMember(t, f.newOrg(t), v.User.ID, "admin")

	if _, d := f.loginExpiry(t, f.googleSignIn(t, ada("g-1"))); d != 12*time.Hour {
		t.Errorf("admin session expires in %v, want 12h", d)
	}
}

func TestOAuthFlowRejects(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{})
	verifier := token.New()

	for name, body := range map[string]string{
		"no provider":          startBody("", "web", challengeOf(verifier)),
		"unknown provider":     startBody("myspace", "web", challengeOf(verifier)),
		"provider turned off":  startBody("apple", "web", challengeOf(verifier)),
		"no client":            startBody(providerGoogle, "", challengeOf(verifier)),
		"no challenge":         startBody(providerGoogle, "web", ""),
		"challenge not base64": startBody(providerGoogle, "web", "not base64!"),
		"short challenge":      startBody(providerGoogle, "web", base64.RawURLEncoding.EncodeToString([]byte("short"))),
	} {
		wantError(t, name, f.do(t, http.MethodPost, "/v1/oauth-flows", body), 422, "validation_failed")
	}
	for name, body := range map[string]string{
		"no state":    completeBody("", "code", verifier),
		"no code":     completeBody(token.New(), "", verifier),
		"no verifier": completeBody(token.New(), "code", ""),
	} {
		wantError(t, name, f.do(t, http.MethodPost, "/v1/oauth-flows/complete", body), 422, "validation_failed")
	}

	wantError(t, "malformed state", f.complete(t, "not-a-state", "code", verifier), 401, "oauth_failed")
	wantError(t, "unknown state", f.complete(t, token.New(), "code", verifier), 401, "oauth_failed")

	// The device that started the flow has the verifier; anyone else who
	// gets the redirect doesn't.
	authURL, verifier := f.startFlow(t, providerGoogle, "mobile")
	code, state := f.google.Authorize(authURL, ada("g-1"))
	wantError(t, "wrong client verifier", f.complete(t, state, code, token.New()), 401, "oauth_failed")
	// A failed attempt doesn't spend the flow: the right device can still
	// finish.
	if res := f.complete(t, state, code, verifier); res.status != http.StatusCreated {
		t.Fatalf("right client verifier: status %d, body %s", res.status, res.body)
	}
	wantError(t, "flow finished again", f.complete(t, state, code, verifier), 401, "oauth_failed")
	// Even with a fresh code for the same state, which a careless provider
	// might issue.
	code, _ = f.google.Authorize(authURL, ada("g-1"))
	wantError(t, "flow finished again with a new code", f.complete(t, state, code, verifier), 401, "oauth_failed")

	authURL, verifier = f.startFlow(t, providerGoogle, "web")
	_, state = f.google.Authorize(authURL, ada("g-1"))
	wantError(t, "code the provider didn't issue", f.complete(t, state, "made-up-code", verifier), 401, "oauth_failed")

	authURL, verifier = f.startFlow(t, providerGoogle, "web")
	code, state = f.google.Authorize(authURL, ada("g-1"))
	f.clock.advance(10 * time.Minute)
	wantError(t, "expired flow", f.complete(t, state, code, verifier), 401, "oauth_failed")

	// Turned off between starting and finishing, e.g. by a deploy.
	authURL, verifier = f.startFlow(t, providerGitHub, "web")
	code, state = f.github.Authorize(authURL, oauthtest.GitHubUser{ID: 9})
	delete(f.auth.providers, providerGitHub)
	wantError(t, "provider turned off", f.complete(t, state, code, verifier), 401, "oauth_failed")

	wantError(t, "unusable email", f.googleSignIn(t, oauthtest.GoogleUser{Subject: "g-9", Email: "not an email", EmailVerified: true}), 401, "oauth_failed")

	if !strings.Contains(f.logs.String(), "client verifier doesn't match") {
		t.Errorf("failure causes weren't logged:\n%s", f.logs)
	}
}

func TestOAuthKeepsSecretsOutOfLogs(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{})
	authURL, verifier := f.startFlow(t, providerGoogle, "web")
	code, state := f.google.Authorize(authURL, ada("g-1"))
	f.complete(t, state, code, token.New())
	l := loginOf(t, f.complete(t, state, code, verifier))
	wantError(t, "unverified", f.googleSignIn(t, oauthtest.GoogleUser{Subject: "g-2", Email: "grace@example.com"}), 403, "oauth_email_not_verified")

	logs := f.logs.String()
	if !strings.Contains(logs, "auth: user signed up with google") || !strings.Contains(logs, "auth: user logged in with google") {
		t.Fatalf("events weren't logged:\n%s", logs)
	}
	u, _ := url.Parse(authURL)
	for _, s := range []string{state, code, verifier, l.Token, u.Query().Get("nonce"), u.Query().Get("code_challenge"), testEmail, "grace@example.com"} {
		if strings.Contains(logs, s) {
			t.Errorf("logs contain %q", s)
		}
	}
}

func TestPasswordNotSet(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{})
	l := loginOf(t, f.googleSignIn(t, ada("g-1")))

	for _, c := range []struct{ method, path, body string }{
		{http.MethodPost, "/v1/users/me/two-factor", pwBody("")},
		{http.MethodPost, "/v1/users/me/password", changeBody("", newPassword)},
		{http.MethodPost, "/v1/email-changes", emailChangeBody("new@example.com", "")},
	} {
		wantError(t, c.method+" "+c.path, f.do(t, c.method, c.path, c.body, withToken(l.Token)), 409, "password_not_set")
	}
	if f.passwordHash(t, testEmail) != nil {
		t.Error("a password was set")
	}

	// With 2FA turned on directly, turning it off or regenerating codes
	// still needs a password.
	if _, err := f.pool.Exec(context.Background(), `INSERT INTO auth.totp_secrets (user_id, secret_encrypted, confirmed_at) VALUES ($1, '\x00', now())`, l.User.ID); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ method, path string }{
		{http.MethodDelete, "/v1/users/me/two-factor"},
		{http.MethodPost, "/v1/users/me/two-factor/recovery-codes"},
	} {
		wantError(t, c.method+" "+c.path, f.do(t, c.method, c.path, pwCodeBody("", "123456"), withToken(l.Token)), 409, "password_not_set")
	}
}
