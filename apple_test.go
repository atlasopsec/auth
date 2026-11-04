package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/atlasopsec/auth/internal/oauth/oauthtest"
	"github.com/atlasopsec/auth/internal/testdb"
	"github.com/atlasopsec/auth/internal/token"
	"github.com/atlasopsec/auth/mail/mailtest"
)

func appleBody(identityToken, nonce string) string {
	b, _ := json.Marshal(map[string]string{"identity_token": identityToken, "nonce": nonce})
	return string(b)
}

// appleSignIn signs in as u on the native Apple sheet.
func (f oauthFixture) appleSignIn(t *testing.T, u oauthtest.AppleUser) response {
	t.Helper()
	nonce := token.New()
	return f.do(t, http.MethodPost, "/v1/apple-sign-ins", appleBody(f.apple.IdentityToken(u, nonce), nonce))
}

func TestAppleConfig(t *testing.T) {
	t.Parallel()
	_, err := New(Config{
		DB: testdb.New(t), Mailer: &mailtest.Recorder{}, AppURL: testAppURL, AppName: "Example", EncryptionKey: testEncryptionKey,
		OAuth: OAuth{Apple: &Apple{}},
	})
	if err == nil {
		t.Error("Apple without bundle IDs: error = nil, want an error")
	}
}

func TestAppleSignIn(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{})
	const relay = "x7k2@privaterelay.appleid.com"

	l := loginOf(t, f.appleSignIn(t, oauthtest.AppleUser{Subject: "a-1", Email: relay, EmailVerified: true}))
	if l.User.Email != relay || !l.User.EmailVerified {
		t.Errorf("user = %+v, want the relay address, verified", l.User)
	}
	var client string
	if err := f.pool.QueryRow(context.Background(), `SELECT client FROM auth.sessions WHERE token_hash = $1`, token.Hash(l.Token)).Scan(&client); err != nil || client != "mobile" {
		t.Errorf("session client = %q (%v), want mobile", client, err)
	}
	if accts := f.oauthAccounts(t, l.Token).Data; len(accts) != 1 || accts[0].Provider != providerApple {
		t.Errorf("linked accounts = %+v, want Apple", accts)
	}
	// Later sign-ins match by Apple's ID.
	if again := loginOf(t, f.appleSignIn(t, oauthtest.AppleUser{Subject: "a-1"})); again.User.ID != l.User.ID {
		t.Errorf("second sign-in: user %s, want %s", again.User.ID, l.User.ID)
	}
	if !strings.Contains(f.logs.String(), "auth: user signed up with apple") {
		t.Error("the sign-up wasn't logged")
	}
}

func TestAppleSignInRejects(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{})
	nonce := token.New()
	tok := f.apple.IdentityToken(oauthtest.AppleUser{Subject: "a-1", Email: testEmail, EmailVerified: true}, nonce)

	wantDetail(t, "no token", f.do(t, http.MethodPost, "/v1/apple-sign-ins", appleBody("", nonce)), "identity_token:required")
	wantDetail(t, "no nonce", f.do(t, http.MethodPost, "/v1/apple-sign-ins", appleBody(tok, "")), "nonce:required")
	wantError(t, "garbage token", f.do(t, http.MethodPost, "/v1/apple-sign-ins", appleBody("not-a-jwt", nonce)), 401, "oauth_failed")
	wantError(t, "another nonce", f.do(t, http.MethodPost, "/v1/apple-sign-ins", appleBody(tok, token.New())), 401, "oauth_failed")
	wantError(t, "another app's token", f.appleSignIn(t, oauthtest.AppleUser{Subject: "a-1", Email: testEmail, EmailVerified: true, Claims: map[string]any{"aud": "com.evil.app"}}), 401, "oauth_failed")
	wantError(t, "unverified email", f.appleSignIn(t, oauthtest.AppleUser{Subject: "a-2", Email: "grace@example.com"}), 403, "oauth_email_not_verified")
	if f.userCount(t) != 0 {
		t.Errorf("%d users, want 0", f.userCount(t))
	}
	if !strings.Contains(f.logs.String(), "nonce doesn't match") {
		t.Error("the failure cause wasn't logged")
	}

	off := setupAccess(t)
	wantError(t, "Apple off", off.do(t, http.MethodPost, "/v1/apple-sign-ins", appleBody(tok, nonce)), 404, "not_found")
	// Apple has no web or Android flow.
	wantError(t, "Apple redirect flow", f.do(t, http.MethodPost, "/v1/oauth-flows", startBody(providerApple, "web", challengeOf(token.New()))), 422, "validation_failed")
}

// iCloudEmail is an address at Apple's own mail service, so Apple runs its
// mailbox and a verified one can sign in to an existing account by email.
const iCloudEmail = "ada@icloud.com"

func TestAppleSignInWithTwoFactor(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{AllowUnverifiedLogin: true})
	v := f.verifiedUser(t, iCloudEmail)
	secret, _ := f.enableTwoFactor(t, v.Token)

	res := f.appleSignIn(t, oauthtest.AppleUser{Subject: "a-1", Email: iCloudEmail, EmailVerified: true})
	if l := loginOf(t, f.verify(t, challengeIn(t, res), f.code(secret))); l.User.ID != v.User.ID {
		t.Errorf("logged in as %s, want %s", l.User.ID, v.User.ID)
	}
}

func TestUnlinkApple(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{AllowUnverifiedLogin: true})
	v := f.verifiedUser(t, iCloudEmail)
	loginOf(t, f.appleSignIn(t, oauthtest.AppleUser{Subject: "a-1", Email: iCloudEmail, EmailVerified: true}))
	apple := f.oauthAccounts(t, v.Token).Data[0].ID

	if res := f.unlink(t, v.Token, apple, testPassword); res.status != http.StatusNoContent {
		t.Fatalf("unlinking: status %d, body %s", res.status, res.body)
	}
	if got := f.lastSubject(iCloudEmail); got != "Apple sign-in was removed from your Example account" {
		t.Errorf("last email = %q", got)
	}
}

// usedNonces counts the recorded nonces matching nonce.
func (f oauthFixture) usedNonces(t *testing.T, nonce string) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM auth.used_apple_nonces WHERE nonce_hash = $1`, token.Hash(nonce)).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (f oauthFixture) sessionCount(t *testing.T, userID uuid.UUID) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM auth.sessions WHERE user_id = $1`, userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestAppleSignInRefusesReplay(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{})
	u := oauthtest.AppleUser{Subject: "a-1", Email: testEmail, EmailVerified: true}
	nonce := token.New()
	captured := appleBody(f.apple.IdentityToken(u, nonce), nonce)

	l := loginOf(t, f.do(t, http.MethodPost, "/v1/apple-sign-ins", captured))
	// The same token and nonce, sent again before the token expires.
	wantError(t, "replayed", f.do(t, http.MethodPost, "/v1/apple-sign-ins", captured), 401, "oauth_failed")
	f.clock.advance(9 * time.Minute)
	wantError(t, "replayed just before expiry", f.do(t, http.MethodPost, "/v1/apple-sign-ins", captured), 401, "oauth_failed")
	if n := f.sessionCount(t, l.User.ID); n != 1 {
		t.Errorf("%d sessions, want 1: the replays signed in", n)
	}
	if !strings.Contains(f.logs.String(), "nonce was already used") {
		t.Error("the replay wasn't logged")
	}

	// The real app signing in again gets a new token and nonce, and that
	// still works.
	if again := loginOf(t, f.appleSignIn(t, oauthtest.AppleUser{Subject: "a-1"})); again.User.ID != l.User.ID {
		t.Errorf("new sign-in: user %s, want %s", again.User.ID, l.User.ID)
	}
	// Only the nonce's hash is stored.
	if n := f.usedNonces(t, nonce); n != 1 {
		t.Errorf("%d rows with the nonce's hash, want 1", n)
	}
	var raw int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM auth.used_apple_nonces WHERE position($1::bytea IN nonce_hash) > 0`, []byte(nonce)).Scan(&raw); err != nil || raw != 0 {
		t.Errorf("rows containing the raw nonce = %d (%v), want 0", raw, err)
	}
}

func TestAppleSignInConcurrentReplays(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{})
	nonce := token.New()
	captured := appleBody(f.apple.IdentityToken(oauthtest.AppleUser{Subject: "a-1", Email: testEmail, EmailVerified: true}, nonce), nonce)

	const n = 8
	statuses := make(chan int, n)
	for range n {
		go func() { statuses <- f.do(t, http.MethodPost, "/v1/apple-sign-ins", captured).status }()
	}
	succeeded := 0
	for range n {
		switch s := <-statuses; s {
		case http.StatusCreated:
			succeeded++
		case http.StatusUnauthorized:
		default:
			t.Errorf("status %d", s)
		}
	}
	if succeeded != 1 {
		t.Errorf("%d concurrent sign-ins with one token succeeded, want 1", succeeded)
	}
}

func TestAppleSignInRefusedTokenDoesNotSpendNonce(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{})
	u := oauthtest.AppleUser{Subject: "a-1", Email: testEmail, EmailVerified: true}
	nonce := token.New()

	// Tokens that fail a check record nothing, so they can't use up the
	// real app's nonce.
	bad := []oauthtest.AppleUser{
		{Subject: "a-1", Claims: map[string]any{"aud": "com.evil.app"}},
		{Subject: "a-1", WrongKey: true},
		{Subject: "a-1", Claims: map[string]any{"exp": f.clock.now().Add(-time.Minute).Unix()}},
	}
	for _, b := range bad {
		wantError(t, "bad token", f.do(t, http.MethodPost, "/v1/apple-sign-ins", appleBody(f.apple.IdentityToken(b, nonce), nonce)), 401, "oauth_failed")
	}
	if n := f.usedNonces(t, nonce); n != 0 {
		t.Fatalf("%d nonces recorded by refused tokens, want 0", n)
	}
	loginOf(t, f.do(t, http.MethodPost, "/v1/apple-sign-ins", appleBody(f.apple.IdentityToken(u, nonce), nonce)))
}

func TestAppleNoncesExpireWithTheirTokens(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{})
	u := oauthtest.AppleUser{Subject: "a-1", Email: testEmail, EmailVerified: true}
	nonce := token.New()
	loginOf(t, f.do(t, http.MethodPost, "/v1/apple-sign-ins", appleBody(f.apple.IdentityToken(u, nonce), nonce)))

	// Cleanup keeps the nonce while its token works.
	if err := f.auth.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := f.usedNonces(t, nonce); n != 1 {
		t.Fatalf("after cleanup before expiry: %d nonces, want 1", n)
	}

	// After the token expires it's refused anyway. A new token that
	// reuses the nonce (from an app that doesn't make a new one each time)
	// works, even before cleanup has run.
	f.clock.advance(11 * time.Minute)
	loginOf(t, f.do(t, http.MethodPost, "/v1/apple-sign-ins", appleBody(f.apple.IdentityToken(u, nonce), nonce)))
	wantError(t, "that token replayed", f.do(t, http.MethodPost, "/v1/apple-sign-ins", appleBody(f.apple.IdentityToken(u, nonce), nonce)), 401, "oauth_failed")

	f.clock.advance(11 * time.Minute)
	if err := f.auth.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := f.usedNonces(t, nonce); n != 0 {
		t.Errorf("after cleanup past expiry: %d nonces, want 0", n)
	}
}
