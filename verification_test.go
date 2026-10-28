package auth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/atlasopsec/auth/internal/emailtoken"
	"github.com/atlasopsec/auth/internal/testdb"
	"github.com/atlasopsec/auth/internal/token"
	"github.com/atlasopsec/auth/mail"
	"github.com/atlasopsec/auth/mail/mailtest"
)

// verifyFirst returns a fixture with the default behavior: verify first.
func verifyFirst(t *testing.T) fixture {
	t.Helper()
	return setupWith(t, Config{})
}

var linkPattern = regexp.MustCompile(`(https://app\.example\.com/[a-z-]+)#token=([A-Za-z0-9_-]+)`)

// emailsTo returns the emails sent to addr, oldest first.
func (f fixture) emailsTo(addr string) []mail.Message {
	var out []mail.Message
	for _, m := range f.sent() {
		if m.To == addr {
			out = append(out, m)
		}
	}
	return out
}

// linkIn returns the page and token of the link in m.
func linkIn(t *testing.T, m mail.Message) (page, tok string) {
	t.Helper()
	match := linkPattern.FindStringSubmatch(m.Text)
	if match == nil {
		t.Fatalf("no link in email %q:\n%s", m.Subject, m.Text)
	}
	return match[1], match[2]
}

func (f fixture) verifiedAt(t *testing.T, email string) *time.Time {
	t.Helper()
	var at *time.Time
	if err := f.pool.QueryRow(context.Background(),
		`SELECT email_verified_at FROM auth.users WHERE lower(email) = lower($1)`, email).Scan(&at); err != nil {
		t.Fatal(err)
	}
	return at
}

func confirmBody(tok, pw string) string {
	b, _ := json.Marshal(map[string]string{"token": tok, "password": pw, "client": "web"})
	return string(b)
}

func TestVerifyFirstSignUp(t *testing.T) {
	t.Parallel()
	var hooked int
	f := setupWith(t, Config{Hooks: Hooks{OnUserCreated: func(context.Context, pgx.Tx, User) error { hooked++; return nil }}})

	res := f.do(t, http.MethodPost, "/v1/users", credentials(testEmail, testPassword, "web"))
	if res.status != http.StatusAccepted {
		t.Fatalf("status = %d, body %s; want 202", res.status, res.body)
	}
	if diff := cmp.Diff(`{"verification_required":true}`+"\n", string(res.body)); diff != "" {
		t.Errorf("body (-want +got):\n%s", diff)
	}
	if f.userCount(t) != 1 || hooked != 1 {
		t.Errorf("users = %d, hook calls = %d; want the account created", f.userCount(t), hooked)
	}
	if at := f.verifiedAt(t, testEmail); at != nil {
		t.Errorf("email_verified_at = %v, want unverified", at)
	}
	var sessions int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM auth.sessions`).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 {
		t.Errorf("%d sessions after a verify first sign-up, want 0", sessions)
	}

	emails := f.emailsTo(testEmail)
	if len(emails) != 1 {
		t.Fatalf("got %d emails, want 1 verification email", len(emails))
	}
	m := emails[0]
	page, tok := linkIn(t, m)
	if m.Subject != "Verify your email for Example" || page != testAppURL+"/verify-email" || !token.Valid(tok) {
		t.Errorf("email = %q with link %s#token=%s, want a verification link", m.Subject, page, tok)
	}
	if !strings.Contains(m.Text, "24 hours") || !strings.Contains(m.Text, testAppURL+"/reset-password") {
		t.Errorf("email text should give the link lifetime and the reset page:\n%s", m.Text)
	}
	if m.IdempotencyKey == "" {
		t.Error("email has no idempotency key")
	}
}

func TestVerifyFirstSignUpLooksTheSameForExistingAccounts(t *testing.T) {
	t.Parallel()
	f := verifyFirst(t)
	const unverified, verified = "unverified@example.com", "verified@example.com"
	f.do(t, http.MethodPost, "/v1/users", credentials(unverified, testPassword, "web"))
	f.do(t, http.MethodPost, "/v1/users", credentials(verified, testPassword, "web"))
	if _, err := f.pool.Exec(context.Background(), `UPDATE auth.users SET email_verified_at = now() WHERE email = $1`, verified); err != nil {
		t.Fatal(err)
	}
	hashes := map[string]string{}
	for _, e := range []string{unverified, verified} {
		var h string
		if err := f.pool.QueryRow(context.Background(), `SELECT password_hash FROM auth.users WHERE email = $1`, e).Scan(&h); err != nil {
			t.Fatal(err)
		}
		hashes[e] = h
	}
	f.clock.advance(emailtoken.Cooldown)

	const attacker = "attacker password 123"
	var bodies []string
	for _, e := range []string{"new@example.com", unverified, strings.ToUpper(verified)} {
		res := f.do(t, http.MethodPost, "/v1/users", credentials(e, attacker, "web"), withHeader("X-Request-ID", "fixed"))
		if res.status != http.StatusAccepted {
			t.Errorf("%s: status = %d, want 202", e, res.status)
		}
		bodies = append(bodies, string(res.body))
	}
	if bodies[1] != bodies[0] || bodies[2] != bodies[0] {
		t.Errorf("responses differ:\n%s", strings.Join(bodies, ""))
	}

	// Existing accounts are untouched: a sign-up can't replace a password.
	for e, h := range hashes {
		var got string
		if err := f.pool.QueryRow(context.Background(), `SELECT password_hash FROM auth.users WHERE email = $1`, e).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != h {
			t.Errorf("%s: password hash changed by a sign-up attempt", e)
		}
	}
	if n := f.userCount(t); n != 3 {
		t.Errorf("%d users, want 3", n)
	}

	// The unverified owner gets a fresh verification link.
	if got := f.emailsTo(unverified); len(got) != 2 || got[1].Subject != "Verify your email for Example" {
		t.Errorf("emails to the unverified account = %+v, want a second verification email", got)
	}
	// The verified owner is told, with a reset link. (Their first email was
	// the verification email from their own sign-up.)
	got := f.emailsTo(verified)
	if len(got) != 2 || got[1].Subject != "Sign-up attempt for Example" {
		t.Fatalf("emails to the verified account = %+v, want a sign-up attempt notice", got)
	}
	if page, _ := linkIn(t, got[1]); page != testAppURL+"/reset-password" || !strings.Contains(got[1].Text, "30 minutes") {
		t.Errorf("notice link = %s, want a reset link valid for 30 minutes", page)
	}
}

func TestSignUpNoticesRespectCooldown(t *testing.T) {
	t.Parallel()
	f := verifyFirst(t)
	f.do(t, http.MethodPost, "/v1/users", credentials(testEmail, testPassword, "web"))
	for range 3 {
		if res := f.do(t, http.MethodPost, "/v1/users", credentials(testEmail, testPassword, "web")); res.status != http.StatusAccepted {
			t.Fatalf("status = %d, want 202", res.status)
		}
	}
	if got := len(f.emailsTo(testEmail)); got != 1 {
		t.Errorf("%d emails within the cooldown, want 1", got)
	}
}

func TestMailerFailureDoesNotChangeResponse(t *testing.T) {
	t.Parallel()
	f := verifyFirst(t)
	f.mail.Fail(errors.New("provider down"))
	res := f.do(t, http.MethodPost, "/v1/users", credentials(testEmail, testPassword, "web"))
	if res.status != http.StatusAccepted {
		t.Errorf("status = %d, want 202", res.status)
	}
	f.sent()
	if !strings.Contains(f.logs.String(), "sending email failed") {
		t.Errorf("failed send wasn't logged:\n%s", f.logs)
	}
}

func TestLoginBeforeVerifying(t *testing.T) {
	t.Parallel()
	f := verifyFirst(t)
	f.do(t, http.MethodPost, "/v1/users", credentials(testEmail, testPassword, "web"))

	res := f.do(t, http.MethodPost, "/v1/sessions", credentials(testEmail, testPassword, "web"))
	if res.status != http.StatusForbidden || res.errorCode(t) != "email_not_verified" {
		t.Errorf("correct password: status = %d, body %s; want 403 email_not_verified", res.status, res.body)
	}
	// Without the password, it looks like any other failed login.
	res = f.do(t, http.MethodPost, "/v1/sessions", credentials(testEmail, "wrong password here", "web"))
	if res.status != http.StatusUnauthorized || res.errorCode(t) != "invalid_credentials" {
		t.Errorf("wrong password: status = %d, body %s; want 401 invalid_credentials", res.status, res.body)
	}
}

func TestConfirmVerification(t *testing.T) {
	t.Parallel()
	f := verifyFirst(t)
	f.do(t, http.MethodPost, "/v1/users", credentials(testEmail, testPassword, "web"))
	_, tok := linkIn(t, f.emailsTo(testEmail)[0])

	f.clock.advance(time.Hour)
	res := f.do(t, http.MethodPost, "/v1/email-verifications/confirm", confirmBody(tok, testPassword))
	if res.status != http.StatusCreated {
		t.Fatalf("status = %d, body %s; want 201", res.status, res.body)
	}
	var l loginJSON
	if err := json.Unmarshal(res.body, &l); err != nil {
		t.Fatal(err)
	}
	if !l.User.EmailVerified || !token.Valid(l.Token) {
		t.Errorf("response = %+v, want a verified user and a session token", l)
	}
	if at := f.verifiedAt(t, testEmail); at == nil || !at.Equal(f.clock.now()) {
		t.Errorf("email_verified_at = %v, want %v", at, f.clock.now())
	}
	me := f.do(t, http.MethodGet, "/v1/users/me", "", withToken(l.Token))
	if me.status != http.StatusOK || !strings.Contains(string(me.body), `"email_verified":true`) {
		t.Errorf("GET /v1/users/me: status %d, body %s", me.status, me.body)
	}

	// Logging in now works, and the link can't be used again.
	f.logIn(t, testEmail)
	if res := f.do(t, http.MethodPost, "/v1/email-verifications/confirm", confirmBody(tok, testPassword)); res.status != http.StatusUnprocessableEntity || res.errorCode(t) != "token_invalid_or_expired" {
		t.Errorf("reused link: status = %d, body %s; want 422 token_invalid_or_expired", res.status, res.body)
	}
}

func TestConfirmVerificationRejects(t *testing.T) {
	t.Parallel()
	f := verifyFirst(t)
	f.do(t, http.MethodPost, "/v1/users", credentials(testEmail, testPassword, "web"))
	_, tok := linkIn(t, f.emailsTo(testEmail)[0])
	resetTok, _, err := f.auth.tokens.Create(context.Background(), userID(t, f, testEmail), emailtoken.ResetPassword, "")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantCode   string
	}{
		{"wrong password", confirmBody(tok, "wrong password here"), http.StatusUnauthorized, "invalid_credentials"},
		{"unknown token", confirmBody(token.New(), testPassword), http.StatusUnprocessableEntity, "token_invalid_or_expired"},
		{"malformed token", confirmBody("abc", testPassword), http.StatusUnprocessableEntity, "token_invalid_or_expired"},
		{"reset token", confirmBody(resetTok, testPassword), http.StatusUnprocessableEntity, "token_invalid_or_expired"},
		{"missing fields", `{"token":"","password":"","client":"tv"}`, http.StatusUnprocessableEntity, "validation_failed"},
		{"unknown field", `{"token":"x","password":"y","client":"web","email":"z"}`, http.StatusBadRequest, "bad_request"},
	}
	for _, tt := range tests {
		res := f.do(t, http.MethodPost, "/v1/email-verifications/confirm", tt.body)
		if res.status != tt.wantStatus || res.errorCode(t) != tt.wantCode {
			t.Errorf("%s: status = %d, body %s; want %d %s", tt.name, res.status, res.body, tt.wantStatus, tt.wantCode)
		}
	}
	if at := f.verifiedAt(t, testEmail); at != nil {
		t.Errorf("email verified by a failed confirmation")
	}
}

func userID(t *testing.T, f fixture, email string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := f.pool.QueryRow(context.Background(), `SELECT id FROM auth.users WHERE email = $1`, email).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestConfirmVerificationExpires(t *testing.T) {
	t.Parallel()
	f := verifyFirst(t)
	f.do(t, http.MethodPost, "/v1/users", credentials(testEmail, testPassword, "web"))
	_, tok := linkIn(t, f.emailsTo(testEmail)[0])

	f.clock.advance(24 * time.Hour)
	res := f.do(t, http.MethodPost, "/v1/email-verifications/confirm", confirmBody(tok, testPassword))
	if res.status != http.StatusUnprocessableEntity || res.errorCode(t) != "token_invalid_or_expired" {
		t.Errorf("status = %d, body %s; want 422 token_invalid_or_expired", res.status, res.body)
	}
}

func TestConfirmVerificationLocksAfterWrongPasswords(t *testing.T) {
	t.Parallel()
	f := verifyFirst(t)
	f.do(t, http.MethodPost, "/v1/users", credentials(testEmail, testPassword, "web"))
	_, tok := linkIn(t, f.emailsTo(testEmail)[0])

	for i := range emailtoken.MaxFailedAttempts {
		if res := f.do(t, http.MethodPost, "/v1/email-verifications/confirm", confirmBody(tok, "guess number "+string(rune('a'+i)))); res.status != http.StatusUnauthorized {
			t.Fatalf("guess %d: status = %d, want 401", i+1, res.status)
		}
	}
	res := f.do(t, http.MethodPost, "/v1/email-verifications/confirm", confirmBody(tok, testPassword))
	if res.status != http.StatusUnprocessableEntity || res.errorCode(t) != "token_invalid_or_expired" {
		t.Errorf("correct password after %d guesses: status = %d, body %s; want 422 token_invalid_or_expired",
			emailtoken.MaxFailedAttempts, res.status, res.body)
	}
}

// TestSquatterCannotGetAccountVerified is the attack verify first with a
// password closes: someone signs up with another person's address, and
// that person clicks the link in the email they receive.
func TestSquatterCannotGetAccountVerified(t *testing.T) {
	t.Parallel()
	f := verifyFirst(t)
	const victim = "victim@example.com"
	f.do(t, http.MethodPost, "/v1/users", credentials(victim, "squatter's password", "web"))
	_, tok := linkIn(t, f.emailsTo(victim)[0])

	// The victim clicks the link and enters their own password.
	res := f.do(t, http.MethodPost, "/v1/email-verifications/confirm", confirmBody(tok, "victim's own password"))
	if res.status != http.StatusUnauthorized {
		t.Errorf("status = %d, body %s; want 401", res.status, res.body)
	}
	if at := f.verifiedAt(t, victim); at != nil {
		t.Error("the squatter's account was verified")
	}
	if res := f.do(t, http.MethodPost, "/v1/sessions", credentials(victim, "squatter's password", "web")); res.status != http.StatusForbidden {
		t.Errorf("squatter logging in: status = %d, want 403 email_not_verified", res.status)
	}
}

func TestRequestVerification(t *testing.T) {
	t.Parallel()
	f := verifyFirst(t)
	const unverified, verified = "unverified@example.com", "verified@example.com"
	f.do(t, http.MethodPost, "/v1/users", credentials(unverified, testPassword, "web"))
	f.do(t, http.MethodPost, "/v1/users", credentials(verified, testPassword, "web"))
	if _, err := f.pool.Exec(context.Background(), `UPDATE auth.users SET email_verified_at = now() WHERE email = $1`, verified); err != nil {
		t.Fatal(err)
	}
	f.clock.advance(emailtoken.Cooldown)

	for _, e := range []string{"nobody@example.com", unverified, verified} {
		res := f.do(t, http.MethodPost, "/v1/email-verifications", `{"email":"`+e+`"}`)
		if res.status != http.StatusAccepted || len(res.body) != 0 {
			t.Errorf("%s: status = %d, body %q; want 202 with no body", e, res.status, res.body)
		}
	}
	// Within the cooldown: still 202, nothing sent.
	f.do(t, http.MethodPost, "/v1/email-verifications", `{"email":"`+unverified+`"}`)

	if got := len(f.emailsTo(unverified)); got != 2 {
		t.Errorf("unverified account got %d emails, want 2 (sign-up and one resend)", got)
	}
	if got := len(f.emailsTo(verified)); got != 1 {
		t.Errorf("verified account got %d emails, want 1 (sign-up only)", got)
	}
	if got := len(f.emailsTo("nobody@example.com")); got != 0 {
		t.Errorf("unknown address got %d emails, want 0", got)
	}

	// The resent link works, and replaced the first one.
	emails := f.emailsTo(unverified)
	_, first := linkIn(t, emails[0])
	_, second := linkIn(t, emails[1])
	if res := f.do(t, http.MethodPost, "/v1/email-verifications/confirm", confirmBody(first, testPassword)); res.status != http.StatusUnprocessableEntity {
		t.Errorf("first link after a resend: status %d, want 422", res.status)
	}
	if res := f.do(t, http.MethodPost, "/v1/email-verifications/confirm", confirmBody(second, testPassword)); res.status != http.StatusCreated {
		t.Errorf("resent link: status %d, body %s; want 201", res.status, res.body)
	}

	if res := f.do(t, http.MethodPost, "/v1/email-verifications", `{"email":""}`); res.status != http.StatusUnprocessableEntity {
		t.Errorf("empty email: status %d, want 422", res.status)
	}
}

func TestAllowUnverifiedLoginAlsoSendsVerification(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)
	if l.User.EmailVerified {
		t.Error("user verified at sign-up")
	}
	emails := f.emailsTo(testEmail)
	if len(emails) != 1 {
		t.Fatalf("got %d emails, want 1 verification email", len(emails))
	}
	_, tok := linkIn(t, emails[0])
	if res := f.do(t, http.MethodPost, "/v1/email-verifications/confirm", confirmBody(tok, testPassword)); res.status != http.StatusCreated {
		t.Errorf("confirming: status %d, body %s", res.status, res.body)
	}
}

func TestCustomEmails(t *testing.T) {
	t.Parallel()
	var got EmailData
	f := setupWith(t, Config{Emails: Emails{VerifyEmail: func(d EmailData) (string, string, string) {
		got = d
		return "Welcome to Acme", "Click " + d.Link, "<a href=\"" + d.Link + "\">Verify</a>"
	}}})
	f.do(t, http.MethodPost, "/v1/users", credentials(testEmail, testPassword, "web"))
	emails := f.emailsTo(testEmail)
	if len(emails) != 1 {
		t.Fatalf("got %d emails, want 1", len(emails))
	}
	m := emails[0]
	if m.Subject != "Welcome to Acme" || !strings.HasPrefix(m.HTML, "<a href=\""+testAppURL+"/verify-email#token=") {
		t.Errorf("email = %+v, want the custom template", m)
	}
	if got.AppName != "Example" || got.AppURL != testAppURL || got.ExpiresIn != 24*time.Hour {
		t.Errorf("template data = %+v", got)
	}
}

func TestWriterMailerWarns(t *testing.T) {
	t.Parallel()
	var buf syncBuffer
	_, err := New(Config{
		DB:            testdb.New(t),
		Mailer:        mail.NewWriter(&buf),
		AppURL:        "http://localhost:3000",
		AppName:       "Example",
		EncryptionKey: testEncryptionKey,
		Logger:        slog.New(slog.NewTextHandler(&buf, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "never use mail.Writer in production") {
		t.Errorf("no warning logged:\n%s", buf.String())
	}
}

func TestEmailsHaveNoTokensInLogs(t *testing.T) {
	t.Parallel()
	f := verifyFirst(t)
	f.do(t, http.MethodPost, "/v1/users", credentials(testEmail, testPassword, "web"))
	_, tok := linkIn(t, f.emailsTo(testEmail)[0])
	f.do(t, http.MethodPost, "/v1/email-verifications/confirm", confirmBody(tok, testPassword))
	for _, secret := range []string{tok, testEmail, testPassword} {
		if strings.Contains(f.logs.String(), secret) {
			t.Errorf("logs contain %q:\n%s", secret, f.logs)
		}
	}
}

func TestHumanDuration(t *testing.T) {
	t.Parallel()
	for d, want := range map[time.Duration]string{
		30 * time.Minute: "30 minutes",
		time.Minute:      "1 minute",
		time.Hour:        "1 hour",
		24 * time.Hour:   "24 hours",
		90 * time.Minute: "90 minutes",
	} {
		if got := humanDuration(d); got != want {
			t.Errorf("humanDuration(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestEveryEmailCanBeCustomized(t *testing.T) {
	t.Parallel()
	custom := func(name string) func(EmailData) (string, string, string) {
		return func(EmailData) (string, string, string) { return name, "", "" }
	}
	a, err := New(Config{
		DB: testdb.New(t), Mailer: &mailtest.Recorder{}, AppURL: testAppURL, AppName: "Example", EncryptionKey: testEncryptionKey,
		Emails: Emails{
			VerifyEmail:     custom("VerifyEmail"),
			SignUpAttempt:   custom("SignUpAttempt"),
			PasswordReset:   custom("PasswordReset"),
			PasswordChanged: custom("PasswordChanged"),
			EmailChange:     custom("EmailChange"),
			EmailChanged:    custom("EmailChanged"),
			Invitation:      custom("Invitation"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, tmpl := range map[string]func(EmailData) (string, string, string){
		"VerifyEmail":     a.emails.VerifyEmail,
		"SignUpAttempt":   a.emails.SignUpAttempt,
		"PasswordReset":   a.emails.PasswordReset,
		"PasswordChanged": a.emails.PasswordChanged,
		"EmailChange":     a.emails.EmailChange,
		"EmailChanged":    a.emails.EmailChanged,
		"Invitation":      a.emails.Invitation,
	} {
		if subject, _, _ := tmpl(EmailData{}); subject != name {
			t.Errorf("%s uses the default template, want the custom one", name)
		}
	}
}
