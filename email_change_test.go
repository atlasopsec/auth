package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/atlasopsec/auth/internal/emailtoken"
)

const newEmail = "ada.new@example.com"

// verifiedUser signs up and verifies email in a verify first fixture, and
// returns the resulting login.
func (f fixture) verifiedUser(t *testing.T, email string) loginJSON {
	t.Helper()
	f.do(t, http.MethodPost, "/v1/users", credentials(email, testPassword, "web"))
	_, tok := linkIn(t, f.emailsTo(email)[0])
	res := f.do(t, http.MethodPost, "/v1/email-verifications/confirm", confirmBody(tok, testPassword))
	if res.status != http.StatusCreated {
		t.Fatalf("verifying %s: status %d, body %s", email, res.status, res.body)
	}
	var l loginJSON
	if err := json.Unmarshal(res.body, &l); err != nil {
		t.Fatal(err)
	}
	return l
}

func emailChangeBody(email, current string) string {
	b, _ := json.Marshal(map[string]string{"email": email, "current_password": current})
	return string(b)
}

func (f fixture) requestEmailChange(t *testing.T, tok, email string) response {
	t.Helper()
	return f.do(t, http.MethodPost, "/v1/email-changes", emailChangeBody(email, testPassword), withToken(tok))
}

func (f fixture) confirmEmailChange(t *testing.T, tok string) response {
	t.Helper()
	return f.do(t, http.MethodPost, "/v1/email-changes/confirm", `{"token":"`+tok+`"}`)
}

func TestEmailChange(t *testing.T) {
	t.Parallel()
	f := verifyFirst(t)
	l := f.verifiedUser(t, testEmail)
	other := f.logIn(t, testEmail)
	f.clock.advance(emailtoken.Cooldown)
	// A reset link already sent to the old address must stop working.
	resetTok := f.requestReset(t, testEmail)
	sentToOld := len(f.emailsTo(testEmail))

	res := f.requestEmailChange(t, l.Token, " "+newEmail+" ")
	if res.status != http.StatusAccepted || len(res.body) != 0 {
		t.Fatalf("request: status %d, body %q; want 202 with no body", res.status, res.body)
	}
	emails := f.emailsTo(newEmail)
	if len(emails) != 1 {
		t.Fatalf("new address got %d emails, want 1", len(emails))
	}
	page, tok := linkIn(t, emails[0])
	if page != testAppURL+"/confirm-email-change" || emails[0].Subject != "Confirm your new email for Example" || !strings.Contains(emails[0].Text, "1 hour") {
		t.Errorf("confirmation email = %q, link page %s:\n%s", emails[0].Subject, page, emails[0].Text)
	}
	// Nothing changes until the new address is confirmed.
	if got := f.status(t, l.Token); got != http.StatusOK {
		t.Errorf("session before confirming: status %d, want 200", got)
	}
	if got := f.canLogIn(t, testEmail, testPassword); got != http.StatusCreated {
		t.Errorf("old email before confirming: status %d, want 201", got)
	}

	f.clock.advance(10 * time.Minute)
	if res := f.confirmEmailChange(t, tok); res.status != http.StatusNoContent {
		t.Fatalf("confirm: status %d, body %s; want 204", res.status, res.body)
	}

	for name, tok := range map[string]string{"current": l.Token, "other": other.Token} {
		if got := f.status(t, tok); got != http.StatusUnauthorized {
			t.Errorf("%s session after the change: status %d, want 401", name, got)
		}
	}
	if got := f.canLogIn(t, testEmail, testPassword); got != http.StatusUnauthorized {
		t.Errorf("old email: status %d, want 401", got)
	}
	if got := f.canLogIn(t, newEmail, testPassword); got != http.StatusCreated {
		t.Errorf("new email: status %d, want 201", got)
	}
	if at := f.verifiedAt(t, newEmail); at == nil || !at.Equal(f.clock.now()) {
		t.Errorf("email_verified_at = %v, want the time of the change", at)
	}
	old := f.emailsTo(testEmail)
	if len(old) != sentToOld+1 || old[len(old)-1].Subject != "Your Example email was changed" {
		t.Errorf("old address got %d new emails (last %q), want the changed notice", len(old)-sentToOld, old[len(old)-1].Subject)
	}
	if strings.Contains(old[len(old)-1].Text, newEmail) {
		t.Error("the notice to the old address reveals the new one")
	}
	if res := f.do(t, http.MethodPost, "/v1/password-resets/confirm", resetBody(resetTok, newPassword)); res.status != http.StatusUnprocessableEntity {
		t.Errorf("reset link sent to the old address: status %d, want 422", res.status)
	}
	if res := f.confirmEmailChange(t, tok); res.status != http.StatusUnprocessableEntity || res.errorCode(t) != "token_invalid_or_expired" {
		t.Errorf("reused link: status %d, body %s", res.status, res.body)
	}
}

func TestEmailChangeRejects(t *testing.T) {
	t.Parallel()
	f := verifyFirst(t)
	l := f.verifiedUser(t, testEmail)

	tests := []struct {
		name        string
		body        string
		wantDetails string
	}{
		{"wrong password", emailChangeBody(newEmail, "not my password"), "current_password:incorrect"},
		{"missing password", emailChangeBody(newEmail, ""), "current_password:required"},
		{"invalid email", emailChangeBody("not an email", testPassword), "email:invalid_format"},
		{"same email", emailChangeBody("ADA@example.com", testPassword), "email:unchanged"},
	}
	for _, tt := range tests {
		res := f.do(t, http.MethodPost, "/v1/email-changes", tt.body, withToken(l.Token))
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
	if n := len(f.emailsTo(newEmail)); n != 0 {
		t.Errorf("new address got %d emails from rejected requests", n)
	}
	if res := f.do(t, http.MethodPost, "/v1/email-changes", emailChangeBody(newEmail, testPassword)); res.status != http.StatusUnauthorized {
		t.Errorf("without a session: status %d, want 401", res.status)
	}
}

func TestEmailChangeRequiresVerifiedEmail(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{}) // AllowUnverifiedLogin: logged in, but unverified
	l := f.signUp(t, testEmail)
	res := f.requestEmailChange(t, l.Token, newEmail)
	if res.status != http.StatusForbidden || res.errorCode(t) != "email_not_verified" {
		t.Errorf("status %d, body %s; want 403 email_not_verified", res.status, res.body)
	}
	if n := len(f.emailsTo(newEmail)); n != 0 {
		t.Errorf("new address got %d emails", n)
	}
}

func TestEmailChangeToTakenAddress(t *testing.T) {
	t.Parallel()
	f := verifyFirst(t)
	l := f.verifiedUser(t, testEmail)
	const taken = "grace@example.com"
	f.verifiedUser(t, taken)
	f.clock.advance(emailtoken.Cooldown)

	free := f.requestEmailChange(t, l.Token, newEmail)
	f.clock.advance(emailtoken.Cooldown)
	takenRes := f.requestEmailChange(t, l.Token, strings.ToUpper(taken))
	if takenRes.status != free.status || string(takenRes.body) != string(free.body) {
		t.Errorf("taken address: status %d, body %q; free address: status %d, body %q; want the same",
			takenRes.status, takenRes.body, free.status, free.body)
	}

	// The taken address's owner is told, and no change link exists for it.
	got := f.emailsTo(taken)
	if last := got[len(got)-1]; last.Subject != "Sign-up attempt for Example" {
		t.Errorf("taken address's last email = %q, want the sign-up attempt notice", last.Subject)
	}
	var tokens int
	if err := f.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM auth.email_tokens WHERE kind = 'change_email' AND lower(new_email) = lower($1)`, taken).Scan(&tokens); err != nil {
		t.Fatal(err)
	}
	if tokens != 0 {
		t.Errorf("%d change tokens for a taken address, want 0", tokens)
	}
}

func TestEmailChangeWhenAddressTakenMeanwhile(t *testing.T) {
	t.Parallel()
	f := verifyFirst(t)
	l := f.verifiedUser(t, testEmail)
	f.requestEmailChange(t, l.Token, newEmail)
	_, tok := linkIn(t, f.emailsTo(newEmail)[0])

	// Someone signs up with the new address before the link is used.
	f.do(t, http.MethodPost, "/v1/users", credentials(newEmail, "someone else's password", "web"))

	res := f.confirmEmailChange(t, tok)
	if res.status != http.StatusUnprocessableEntity || res.errorCode(t) != "token_invalid_or_expired" {
		t.Errorf("status %d, body %s; want 422 token_invalid_or_expired", res.status, res.body)
	}
	if got := f.status(t, l.Token); got != http.StatusOK {
		t.Errorf("session after the failed change: status %d, want 200", got)
	}
	if got := f.canLogIn(t, testEmail, testPassword); got != http.StatusCreated {
		t.Errorf("original email after the failed change: status %d, want 201", got)
	}
}

func TestEmailChangeLinkExpiresAndChecksKind(t *testing.T) {
	t.Parallel()
	f := verifyFirst(t)
	l := f.verifiedUser(t, testEmail)
	f.clock.advance(emailtoken.Cooldown)
	resetTok := f.requestReset(t, testEmail)
	f.requestEmailChange(t, l.Token, newEmail)
	_, tok := linkIn(t, f.emailsTo(newEmail)[0])

	if res := f.confirmEmailChange(t, resetTok); res.status != http.StatusUnprocessableEntity {
		t.Errorf("reset token: status %d, want 422", res.status)
	}
	if res := f.do(t, http.MethodPost, "/v1/email-changes/confirm", `{"token":""}`); res.status != http.StatusUnprocessableEntity || res.errorCode(t) != "validation_failed" {
		t.Errorf("empty token: status %d, body %s; want 422 validation_failed", res.status, res.body)
	}
	f.clock.advance(time.Hour)
	if res := f.confirmEmailChange(t, tok); res.status != http.StatusUnprocessableEntity || res.errorCode(t) != "token_invalid_or_expired" {
		t.Errorf("expired link: status %d, body %s", res.status, res.body)
	}
	if got := f.canLogIn(t, testEmail, testPassword); got != http.StatusCreated {
		t.Errorf("original email: status %d, want 201", got)
	}
}

func TestEmailChangeCooldown(t *testing.T) {
	t.Parallel()
	f := verifyFirst(t)
	l := f.verifiedUser(t, testEmail)
	for range 3 {
		if res := f.requestEmailChange(t, l.Token, newEmail); res.status != http.StatusAccepted {
			t.Fatalf("status %d, want 202", res.status)
		}
	}
	if n := len(f.emailsTo(newEmail)); n != 1 {
		t.Errorf("%d emails within the cooldown, want 1", n)
	}
}

func TestEmailChangeKeepsSecretsOutOfLogs(t *testing.T) {
	t.Parallel()
	f := verifyFirst(t)
	l := f.verifiedUser(t, testEmail)
	f.requestEmailChange(t, l.Token, newEmail)
	_, tok := linkIn(t, f.emailsTo(newEmail)[0])
	f.confirmEmailChange(t, tok)

	logs := f.logs.String()
	if !strings.Contains(logs, "auth: email changed") {
		t.Fatalf("change wasn't logged:\n%s", logs)
	}
	for _, secret := range []string{testEmail, newEmail, testPassword, tok} {
		if strings.Contains(logs, secret) {
			t.Errorf("logs contain %q", secret)
		}
	}
}

func TestEmailChangeConfirmedConcurrently(t *testing.T) {
	t.Parallel()
	f := verifyFirst(t)
	l := f.verifiedUser(t, testEmail)
	f.requestEmailChange(t, l.Token, newEmail)
	_, tok := linkIn(t, f.emailsTo(newEmail)[0])
	before := len(f.emailsTo(testEmail))

	const n = 5
	statuses := make(chan int, n)
	for range n {
		go func() { statuses <- f.confirmEmailChange(t, tok).status }()
	}
	succeeded := 0
	for range n {
		switch s := <-statuses; s {
		case http.StatusNoContent:
			succeeded++
		case http.StatusUnprocessableEntity:
		default:
			t.Errorf("status %d", s)
		}
	}
	if succeeded != 1 {
		t.Errorf("%d concurrent confirmations succeeded, want 1", succeeded)
	}
	if got := len(f.emailsTo(testEmail)) - before; got != 1 {
		t.Errorf("old address got %d notices, want 1", got)
	}
}
