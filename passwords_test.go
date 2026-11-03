package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/atlasopsec/auth/internal/emailtoken"
	"github.com/atlasopsec/auth/internal/oauth/oauthtest"
	"github.com/atlasopsec/auth/internal/password"
	"github.com/atlasopsec/auth/internal/testdb"
	"github.com/atlasopsec/auth/mail/mailtest"
)

const newPassword = "a brand new passphrase"

func resetBody(tok, pw string) string {
	b, _ := json.Marshal(map[string]string{"token": tok, "password": pw})
	return string(b)
}

func changeBody(current, next string) string {
	b, _ := json.Marshal(map[string]string{"current_password": current, "new_password": next})
	return string(b)
}

// requestReset asks for a reset link for email and returns its token.
func (f fixture) requestReset(t *testing.T, email string) string {
	t.Helper()
	before := len(f.emailsTo(email))
	res := f.do(t, http.MethodPost, "/v1/password-resets", `{"email":"`+email+`"}`)
	if res.status != http.StatusAccepted {
		t.Fatalf("requesting a reset: status %d, body %s", res.status, res.body)
	}
	emails := f.emailsTo(email)
	if len(emails) != before+1 {
		t.Fatalf("got %d new emails, want 1 reset email", len(emails)-before)
	}
	page, tok := linkIn(t, emails[len(emails)-1])
	if page != testAppURL+"/reset-password" {
		t.Fatalf("reset link page = %s", page)
	}
	return tok
}

func (f fixture) passwordHash(t *testing.T, email string) *string {
	t.Helper()
	var h *string
	if err := f.pool.QueryRow(context.Background(), `SELECT password_hash FROM auth.users WHERE lower(email) = lower($1)`, email).Scan(&h); err != nil {
		t.Fatal(err)
	}
	return h
}

func (f fixture) canLogIn(t *testing.T, email, pw string) int {
	t.Helper()
	return f.do(t, http.MethodPost, "/v1/sessions", credentials(email, pw, "web")).status
}

func TestPasswordReset(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	a := f.signUp(t, testEmail)
	b := f.logIn(t, testEmail)
	f.clock.advance(emailtoken.Cooldown)

	tok := f.requestReset(t, testEmail)
	m := f.emailsTo(testEmail)[len(f.emailsTo(testEmail))-1]
	if m.Subject != "Reset your password for Example" || !strings.Contains(m.Text, "30 minutes") {
		t.Errorf("reset email = %q:\n%s", m.Subject, m.Text)
	}

	res := f.do(t, http.MethodPost, "/v1/password-resets/confirm", resetBody(tok, newPassword))
	if res.status != http.StatusNoContent {
		t.Fatalf("status = %d, body %s; want 204", res.status, res.body)
	}

	// Every session ended.
	for name, tok := range map[string]string{"first": a.Token, "second": b.Token} {
		if got := f.status(t, tok); got != http.StatusUnauthorized {
			t.Errorf("%s session after a reset: status %d, want 401", name, got)
		}
	}
	if got := f.canLogIn(t, testEmail, testPassword); got != http.StatusUnauthorized {
		t.Errorf("old password: status %d, want 401", got)
	}
	if got := f.canLogIn(t, testEmail, newPassword); got != http.StatusCreated {
		t.Errorf("new password: status %d, want 201", got)
	}
	// The reset proved control of the email.
	if f.verifiedAt(t, testEmail) == nil {
		t.Error("email not verified by the reset")
	}
	// A notice was sent.
	emails := f.emailsTo(testEmail)
	if last := emails[len(emails)-1]; last.Subject != "Your Example password was changed" || !strings.Contains(last.Text, testAppURL+"/reset-password") {
		t.Errorf("last email = %q, want the password changed notice", last.Subject)
	}
	// The link works once.
	if res := f.do(t, http.MethodPost, "/v1/password-resets/confirm", resetBody(tok, "yet another passphrase")); res.status != http.StatusUnprocessableEntity || res.errorCode(t) != "token_invalid_or_expired" {
		t.Errorf("reused link: status %d, body %s", res.status, res.body)
	}
}

func TestPasswordResetRequestLooksTheSame(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	f.signUp(t, testEmail)
	f.clock.advance(emailtoken.Cooldown)

	known := f.do(t, http.MethodPost, "/v1/password-resets", `{"email":"ADA@example.com"}`, withHeader("X-Request-ID", "x"))
	unknown := f.do(t, http.MethodPost, "/v1/password-resets", `{"email":"nobody@example.com"}`, withHeader("X-Request-ID", "x"))
	if known.status != http.StatusAccepted || unknown.status != http.StatusAccepted || len(known.body) != 0 || len(unknown.body) != 0 {
		t.Errorf("known: %d %q, unknown: %d %q; want 202 with no body for both", known.status, known.body, unknown.status, unknown.body)
	}
	if n := len(f.emailsTo("nobody@example.com")); n != 0 {
		t.Errorf("unknown address got %d emails", n)
	}

	// Within the cooldown nothing more is sent, and the response is the same.
	again := f.do(t, http.MethodPost, "/v1/password-resets", `{"email":"ada@example.com"}`, withHeader("X-Request-ID", "x"))
	if again.status != http.StatusAccepted {
		t.Errorf("within the cooldown: status %d", again.status)
	}
	if n := len(f.emailsTo(testEmail)); n != 2 {
		t.Errorf("%d emails, want 2 (verification and one reset)", n)
	}

	if res := f.do(t, http.MethodPost, "/v1/password-resets", `{"email":"not an email"}`); res.status != http.StatusUnprocessableEntity {
		t.Errorf("invalid email: status %d, want 422", res.status)
	}
}

func TestPasswordResetRejects(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	f.signUp(t, testEmail)
	verifyTok := f.emailTokenOf(t, testEmail, 0)
	f.clock.advance(emailtoken.Cooldown)
	tok := f.requestReset(t, testEmail)
	f.breach.set(map[string]bool{"password123456": true}, nil)

	type detail struct{ field, code string }
	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantCode   string
		wantDetail *detail
	}{
		{"short password", resetBody(tok, "short"), 422, "validation_failed", &detail{"password", "too_short"}},
		{"breached password", resetBody(tok, "password123456"), 422, "validation_failed", &detail{"password", "breached"}},
		{"missing token", resetBody("", newPassword), 422, "validation_failed", &detail{"token", "required"}},
		{"unknown token", resetBody(uuid.NewString(), newPassword), 422, "token_invalid_or_expired", nil},
		{"verification token", resetBody(verifyTok, newPassword), 422, "token_invalid_or_expired", nil},
		{"unknown field", `{"token":"x","password":"y","email":"z"}`, 400, "bad_request", nil},
	}
	for _, tt := range tests {
		res := f.do(t, http.MethodPost, "/v1/password-resets/confirm", tt.body)
		if res.status != tt.wantStatus || res.errorCode(t) != tt.wantCode {
			t.Errorf("%s: status %d, body %s; want %d %s", tt.name, res.status, res.body, tt.wantStatus, tt.wantCode)
			continue
		}
		if tt.wantDetail != nil {
			var e errorJSON
			_ = json.Unmarshal(res.body, &e)
			if len(e.Error.Details) != 1 || e.Error.Details[0].Field != tt.wantDetail.field || e.Error.Details[0].Code != tt.wantDetail.code {
				t.Errorf("%s: details = %+v, want %+v", tt.name, e.Error.Details, *tt.wantDetail)
			}
		}
	}

	// None of those changed the password or used up the link.
	if got := f.canLogIn(t, testEmail, testPassword); got != http.StatusCreated {
		t.Errorf("original password after rejected resets: status %d, want 201", got)
	}
	if res := f.do(t, http.MethodPost, "/v1/password-resets/confirm", resetBody(tok, newPassword)); res.status != http.StatusNoContent {
		t.Errorf("link after rejected attempts: status %d, body %s; want 204", res.status, res.body)
	}
}

// emailTokenOf returns the token in the i-th email sent to addr.
func (f fixture) emailTokenOf(t *testing.T, addr string, i int) string {
	t.Helper()
	emails := f.emailsTo(addr)
	if len(emails) <= i {
		t.Fatalf("only %d emails to %s", len(emails), addr)
	}
	_, tok := linkIn(t, emails[i])
	return tok
}

func TestPasswordResetExpires(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	f.signUp(t, testEmail)
	f.clock.advance(emailtoken.Cooldown)
	tok := f.requestReset(t, testEmail)

	f.clock.advance(30 * time.Minute)
	res := f.do(t, http.MethodPost, "/v1/password-resets/confirm", resetBody(tok, newPassword))
	if res.status != http.StatusUnprocessableEntity || res.errorCode(t) != "token_invalid_or_expired" {
		t.Errorf("status %d, body %s; want 422 token_invalid_or_expired", res.status, res.body)
	}
}

// TestResetTakesBackSquattedAccount: someone signed up with the victim's
// address and a password they know. A reset from the victim's inbox gives
// the account to the victim.
func TestResetTakesBackSquattedAccount(t *testing.T) {
	t.Parallel()
	f := verifyFirst(t)
	const victim = "victim@example.com"
	const squatterPassword = "squatter's password"
	f.do(t, http.MethodPost, "/v1/users", credentials(victim, squatterPassword, "web"))
	f.clock.advance(emailtoken.Cooldown)

	tok := f.requestReset(t, victim)
	if res := f.do(t, http.MethodPost, "/v1/password-resets/confirm", resetBody(tok, newPassword)); res.status != http.StatusNoContent {
		t.Fatalf("reset: status %d, body %s", res.status, res.body)
	}
	if got := f.canLogIn(t, victim, newPassword); got != http.StatusCreated {
		t.Errorf("victim logging in: status %d, want 201", got)
	}
	if got := f.canLogIn(t, victim, squatterPassword); got != http.StatusUnauthorized {
		t.Errorf("squatter logging in: status %d, want 401", got)
	}
}

func TestResetAddsPasswordToOAuthOnlyAccount(t *testing.T) {
	t.Parallel()
	f := verifyFirst(t)
	const email = "oauth@example.com"
	if _, err := f.pool.Exec(context.Background(),
		`INSERT INTO auth.users (id, email, email_verified_at) VALUES ($1, $2, now())`, uuid.Must(uuid.NewV7()), email); err != nil {
		t.Fatal(err)
	}
	tok := f.requestReset(t, email)
	if res := f.do(t, http.MethodPost, "/v1/password-resets/confirm", resetBody(tok, newPassword)); res.status != http.StatusNoContent {
		t.Fatalf("reset: status %d, body %s", res.status, res.body)
	}
	if got := f.canLogIn(t, email, newPassword); got != http.StatusCreated {
		t.Errorf("logging in with the new password: status %d, want 201", got)
	}
}

func TestChangePassword(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	current := f.signUp(t, testEmail)
	other := f.logIn(t, testEmail)

	res := f.do(t, http.MethodPost, "/v1/users/me/password", changeBody(testPassword, newPassword), withToken(current.Token))
	if res.status != http.StatusNoContent {
		t.Fatalf("status %d, body %s; want 204", res.status, res.body)
	}
	if got := f.status(t, current.Token); got != http.StatusOK {
		t.Errorf("current session: status %d, want 200", got)
	}
	if got := f.status(t, other.Token); got != http.StatusUnauthorized {
		t.Errorf("other session: status %d, want 401", got)
	}
	if got := f.canLogIn(t, testEmail, newPassword); got != http.StatusCreated {
		t.Errorf("new password: status %d, want 201", got)
	}
	if got := f.canLogIn(t, testEmail, testPassword); got != http.StatusUnauthorized {
		t.Errorf("old password: status %d, want 401", got)
	}
	emails := f.emailsTo(testEmail)
	if last := emails[len(emails)-1]; last.Subject != "Your Example password was changed" {
		t.Errorf("last email = %q, want the password changed notice", last.Subject)
	}
}

func TestChangePasswordRejects(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)
	f.breach.set(map[string]bool{"password123456": true}, nil)
	before := *f.passwordHash(t, testEmail)

	tests := []struct {
		name        string
		body        string
		wantDetails string
	}{
		{"wrong current password", changeBody("not my password", newPassword), "current_password:incorrect"},
		{"missing current password", changeBody("", newPassword), "current_password:required"},
		{"short new password", changeBody(testPassword, "short"), "new_password:too_short"},
		{"breached new password", changeBody(testPassword, "password123456"), "new_password:breached"},
	}
	for _, tt := range tests {
		res := f.do(t, http.MethodPost, "/v1/users/me/password", tt.body, withToken(l.Token))
		var e errorJSON
		_ = json.Unmarshal(res.body, &e)
		var got []string
		for _, d := range e.Error.Details {
			got = append(got, d.Field+":"+d.Code)
		}
		if res.status != http.StatusUnprocessableEntity || strings.Join(got, ",") != tt.wantDetails {
			t.Errorf("%s: status %d, body %s; want 422 with %s", tt.name, res.status, res.body, tt.wantDetails)
		}
	}
	if after := *f.passwordHash(t, testEmail); after != before {
		t.Error("password changed by a rejected request")
	}
	if got := f.status(t, l.Token); got != http.StatusOK {
		t.Errorf("session after rejected changes: status %d, want 200", got)
	}

	if res := f.do(t, http.MethodPost, "/v1/users/me/password", changeBody(testPassword, newPassword)); res.status != http.StatusUnauthorized {
		t.Errorf("without a session: status %d, want 401", res.status)
	}
}

func TestChangePasswordWithoutCurrentPassword(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)
	// The account loses its password, as if it only used OAuth.
	if _, err := f.pool.Exec(context.Background(), `UPDATE auth.users SET password_hash = NULL`); err != nil {
		t.Fatal(err)
	}
	res := f.do(t, http.MethodPost, "/v1/users/me/password", changeBody("anything at all", newPassword), withToken(l.Token))
	wantError(t, "changing password", res, 409, "password_not_set")
	if f.passwordHash(t, testEmail) != nil {
		t.Error("a password was set without a reset")
	}
}

func TestBreachedPasswordOnSignUp(t *testing.T) {
	t.Parallel()
	f := verifyFirst(t)
	f.breach.set(map[string]bool{"password123456": true}, nil)
	res := f.do(t, http.MethodPost, "/v1/users", credentials(testEmail, "password123456", "web"))
	if res.status != http.StatusUnprocessableEntity || !strings.Contains(string(res.body), `"field":"password","code":"breached"`) {
		t.Errorf("status %d, body %s; want 422 with password breached", res.status, res.body)
	}
	if n := f.userCount(t); n != 0 {
		t.Errorf("%d users created with a breached password", n)
	}
}

func TestBreachCheckFailsOpen(t *testing.T) {
	t.Parallel()
	f := verifyFirst(t)
	f.breach.set(nil, errors.New("api.pwnedpasswords.com: timeout"))
	if res := f.do(t, http.MethodPost, "/v1/users", credentials(testEmail, testPassword, "web")); res.status != http.StatusAccepted {
		t.Errorf("sign-up with the breach check failing: status %d, body %s; want 202", res.status, res.body)
	}
	if !strings.Contains(f.logs.String(), "breached-password check skipped") {
		t.Errorf("skipped check wasn't logged:\n%s", f.logs)
	}
}

func TestDisableBreachCheck(t *testing.T) {
	t.Parallel()
	pool := testdb.New(t)
	cfg := Config{DB: pool, Mailer: &mailtest.Recorder{}, AppURL: testAppURL, AppName: "Example", EncryptionKey: testEncryptionKey}
	on, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.DisableBreachCheck = true
	off, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if on.breach == nil || off.breach != nil {
		t.Errorf("breach checker on = %v, off = %v; want it on by default and off when disabled", on.breach, off.breach)
	}
}

func TestPasswordFlowsKeepSecretsOutOfLogs(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)
	f.do(t, http.MethodPost, "/v1/users/me/password", changeBody(testPassword, newPassword), withToken(l.Token))
	f.clock.advance(emailtoken.Cooldown)
	tok := f.requestReset(t, testEmail)
	f.do(t, http.MethodPost, "/v1/password-resets/confirm", resetBody(tok, "the final passphrase"))

	logs := f.logs.String()
	if !strings.Contains(logs, "auth: password reset") || !strings.Contains(logs, "auth: password changed") {
		t.Fatalf("events weren't logged:\n%s", logs)
	}
	for _, secret := range []string{testEmail, testPassword, newPassword, "the final passphrase", tok} {
		if strings.Contains(logs, secret) {
			t.Errorf("logs contain %q", secret)
		}
	}
	if ok, _ := password.Verify("the final passphrase", *f.passwordHash(t, testEmail)); !ok {
		t.Error("final password not set")
	}
}

// TestPasswordResetCancelsEmailChange is the account recovery case: someone
// with the password asks to move the account to their own address, and
// the owner resets the password. The change link must stop working, or
// confirming it would hand them the account.
func TestPasswordResetCancelsEmailChange(t *testing.T) {
	t.Parallel()
	f := verifyFirst(t)
	l := f.verifiedUser(t, testEmail)
	const attacker = "mallory@example.com"
	if res := f.requestEmailChange(t, l.Token, attacker); res.status != http.StatusAccepted {
		t.Fatalf("requesting the change: status %d, body %s", res.status, res.body)
	}
	change := f.emailTokenOf(t, attacker, 0)
	f.clock.advance(emailtoken.Cooldown)

	reset := f.requestReset(t, testEmail)
	if res := f.do(t, http.MethodPost, "/v1/password-resets/confirm", resetBody(reset, newPassword)); res.status != http.StatusNoContent {
		t.Fatalf("reset: status %d, body %s", res.status, res.body)
	}
	wantError(t, "email change after the reset", f.confirmEmailChange(t, change), 422, "token_invalid_or_expired")
	if f.canLogIn(t, testEmail, newPassword) != http.StatusCreated {
		t.Error("the account's email changed")
	}
}

// TestPasswordChangeCancelsEmailLinks checks that changing the password
// stops links sent before it from working: a reset link someone else
// asked for, and an email change.
func TestPasswordChangeCancelsEmailLinks(t *testing.T) {
	t.Parallel()
	f := verifyFirst(t)
	l := f.verifiedUser(t, testEmail)
	const attacker = "mallory@example.com"
	if res := f.requestEmailChange(t, l.Token, attacker); res.status != http.StatusAccepted {
		t.Fatalf("requesting the change: status %d, body %s", res.status, res.body)
	}
	change := f.emailTokenOf(t, attacker, 0)
	f.clock.advance(emailtoken.Cooldown)
	reset := f.requestReset(t, testEmail)

	if res := f.do(t, http.MethodPost, "/v1/users/me/password", changeBody(testPassword, newPassword), withToken(l.Token)); res.status != http.StatusNoContent {
		t.Fatalf("change: status %d, body %s", res.status, res.body)
	}
	wantError(t, "reset link after the change", f.do(t, http.MethodPost, "/v1/password-resets/confirm", resetBody(reset, "yet another passphrase")), 422, "token_invalid_or_expired")
	wantError(t, "email change after the change", f.confirmEmailChange(t, change), 422, "token_invalid_or_expired")
	if f.canLogIn(t, testEmail, newPassword) != http.StatusCreated {
		t.Error("the new password doesn't work")
	}
}

// TestPasswordResetTakesBackSquattedAccount is a squatter who signed up
// with Ada's address, and linked GitHub and turned on 2FA before either
// needed a verified email. Ada's reset must remove both, and not ask for
// the squatter's 2FA code.
func TestPasswordResetTakesBackSquattedAccount(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{AllowUnverifiedLogin: true})
	squatter := f.signUp(t, testEmail)
	f.verifyByToken(t, squatter.Token)
	if res := f.linkGitHub(t, squatter.Token, testPassword, 7); res.status != http.StatusCreated {
		t.Fatalf("linking: status %d, body %s", res.status, res.body)
	}
	f.enableTwoFactorUnverified(t, squatter.Token)
	f.clock.advance(emailtoken.Cooldown)

	reset := f.requestReset(t, testEmail)
	if res := f.do(t, http.MethodPost, "/v1/password-resets/confirm", resetBody(reset, newPassword)); res.status != http.StatusNoContent {
		t.Fatalf("reset: status %d, body %s; want 204 without a 2FA code", res.status, res.body)
	}
	var linked int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM auth.oauth_accounts WHERE user_id = $1`, squatter.User.ID).Scan(&linked); err != nil || linked != 0 {
		t.Errorf("%d linked providers (%v), want the squatter's removed", linked, err)
	}
	if got := f.canLogIn(t, testEmail, newPassword); got != http.StatusCreated {
		t.Errorf("logging in: status %d, want 201 without the squatter's 2FA", got)
	}
	authURL, verifier := f.startFlow(t, providerGitHub, "web")
	code, state := f.github.Authorize(authURL, oauthtest.GitHubUser{ID: 7, Emails: []oauthtest.GitHubEmail{{Email: "mallory@example.com", Primary: true, Verified: true}}})
	if l := loginOf(t, f.complete(t, state, code, verifier)); l.User.ID == squatter.User.ID {
		t.Error("the squatter's GitHub still logs in to the account")
	}
}

// TestPasswordResetOfVerifiedAccountKeepsProviders checks that only a
// takeback removes linked providers: an ordinary reset keeps them.
func TestPasswordResetOfVerifiedAccountKeepsProviders(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{AllowUnverifiedLogin: true})
	l := f.verifiedUser(t, testEmail)
	if res := f.linkGitHub(t, l.Token, testPassword, 7); res.status != http.StatusCreated {
		t.Fatalf("linking: status %d, body %s", res.status, res.body)
	}
	f.clock.advance(emailtoken.Cooldown)
	reset := f.requestReset(t, testEmail)
	if res := f.do(t, http.MethodPost, "/v1/password-resets/confirm", resetBody(reset, newPassword)); res.status != http.StatusNoContent {
		t.Fatalf("reset: status %d, body %s", res.status, res.body)
	}
	var linked int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM auth.oauth_accounts WHERE user_id = $1`, l.User.ID).Scan(&linked); err != nil || linked != 1 {
		t.Errorf("%d linked providers (%v), want 1", linked, err)
	}
}

// TestEmailLinkRequestsDontWaitForTheAccount checks that asking for a
// reset or verification link answers without touching the account, so the
// response takes the same time whether or not the address has one
// (standards/auth.md §9). The test holds the account's row lock: before the
// fix, the request made the link while answering, so it waited for the
// lock until its deadline and failed.
func TestEmailLinkRequestsDontWaitForTheAccount(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name, path, subject string
	}{
		{"password reset", "/v1/password-resets", "Reset your password for Example"},
		{"verification", "/v1/email-verifications", "Verify your email for Example"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := verifyFirst(t)
			if res := f.do(t, http.MethodPost, "/v1/users", credentials(testEmail, testPassword, "web")); res.status != http.StatusAccepted {
				t.Fatalf("sign up: status %d, body %s", res.status, res.body)
			}
			f.clock.advance(emailtoken.Cooldown)
			before := len(f.emailsTo(testEmail))

			ctx := context.Background()
			tx, err := f.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			if _, err := tx.Exec(ctx, `SELECT 1 FROM auth.users WHERE email = $1 FOR UPDATE`, testEmail); err != nil {
				t.Fatal(err)
			}

			// A deadline, so the old behavior fails instead of hanging.
			reqCtx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			r := httptest.NewRequestWithContext(reqCtx, http.MethodPost, tt.path, strings.NewReader(`{"email":"`+testEmail+`"}`))
			r.RemoteAddr = "203.0.113.50:5000"
			w := httptest.NewRecorder()
			// Not f.do: it waits for the background work, which is waiting
			// for the lock this test holds.
			f.mux.ServeHTTP(w, r)
			if w.Code != http.StatusAccepted || w.Body.Len() != 0 {
				t.Errorf("with the account locked: status %d, body %q; want 202 with no body, without waiting", w.Code, w.Body)
			}

			// Once the account is free, the link is sent.
			if err := tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			emails := f.emailsTo(testEmail)
			if len(emails) != before+1 {
				t.Fatalf("%d emails after the request, want %d", len(emails), before+1)
			}
			if got := emails[len(emails)-1].Subject; got != tt.subject {
				t.Errorf("subject = %q, want %q", got, tt.subject)
			}
		})
	}
}
