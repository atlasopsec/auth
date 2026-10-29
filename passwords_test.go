package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/atlasopsec/auth/internal/emailtoken"
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
