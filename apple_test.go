package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

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

func TestAppleSignInWithTwoFactor(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{AllowUnverifiedLogin: true})
	v := f.verifiedUser(t, testEmail)
	secret, _ := f.enableTwoFactor(t, v.Token)

	res := f.appleSignIn(t, oauthtest.AppleUser{Subject: "a-1", Email: testEmail, EmailVerified: true})
	if l := loginOf(t, f.verify(t, challengeIn(t, res), f.code(secret))); l.User.ID != v.User.ID {
		t.Errorf("logged in as %s, want %s", l.User.ID, v.User.ID)
	}
}

func TestUnlinkApple(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{AllowUnverifiedLogin: true})
	v := f.verifiedUser(t, testEmail)
	loginOf(t, f.appleSignIn(t, oauthtest.AppleUser{Subject: "a-1", Email: testEmail, EmailVerified: true}))
	apple := f.oauthAccounts(t, v.Token).Data[0].ID

	if res := f.unlink(t, v.Token, apple, testPassword); res.status != http.StatusNoContent {
		t.Fatalf("unlinking: status %d, body %s", res.status, res.body)
	}
	if got := f.lastSubject(testEmail); got != "Apple sign-in was removed from your Example account" {
		t.Errorf("last email = %q", got)
	}
}
