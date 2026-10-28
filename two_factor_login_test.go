package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/atlasopsec/auth/internal/emailtoken"
	"github.com/atlasopsec/auth/internal/token"
	"github.com/atlasopsec/auth/internal/totp"
)

type challengeResponse struct {
	TwoFactorRequired bool   `json:"two_factor_required"`
	ChallengeToken    string `json:"challenge_token"`
	ExpiresAt         string `json:"expires_at"`
}

func verifyBody(challenge, code string) string {
	b, _ := json.Marshal(map[string]string{"challenge_token": challenge, "code": code})
	return string(b)
}

func resetCodeBody(tok, pw, code string) string {
	b, _ := json.Marshal(map[string]string{"token": tok, "password": pw, "code": code})
	return string(b)
}

// startChallenge logs in with the password and returns the 2FA challenge.
func (f fixture) startChallenge(t *testing.T, email string) string {
	t.Helper()
	res := f.do(t, http.MethodPost, "/v1/sessions", credentials(email, testPassword, "mobile"))
	return challengeIn(t, res)
}

func challengeIn(t *testing.T, res response) string {
	t.Helper()
	var c challengeResponse
	if res.status != http.StatusOK || json.Unmarshal(res.body, &c) != nil || !c.TwoFactorRequired || !token.Valid(c.ChallengeToken) {
		t.Fatalf("want a 2FA challenge, got status %d, body %s", res.status, res.body)
	}
	return c.ChallengeToken
}

func (f fixture) verify(t *testing.T, challenge, code string) response {
	t.Helper()
	return f.do(t, http.MethodPost, "/v1/two-factor-challenges/verify", verifyBody(challenge, code))
}

// wrongCode returns a code that isn't valid for secret right now.
func (f fixture) wrongCode(secret []byte) string {
	step := totp.Step(f.clock.now())
	valid := map[string]bool{}
	for s := step - totp.Drift; s <= step+totp.Drift; s++ {
		valid[totp.Code(secret, s)] = true
	}
	for i := 0; ; i++ {
		if c := fmt.Sprintf("%06d", i); !valid[c] {
			return c
		}
	}
}

// tripGuessingLimit records enough wrong codes for the user, just now, to
// reach the guessing limit.
func (f fixture) tripGuessingLimit(t *testing.T, userID uuid.UUID) {
	t.Helper()
	for range guessLimit {
		if _, err := f.pool.Exec(context.Background(), `INSERT INTO auth.two_factor_failures (id, user_id, created_at) VALUES ($1, $2, $3)`,
			uuid.Must(uuid.NewV7()), userID, f.clock.now()); err != nil {
			t.Fatal(err)
		}
	}
}

func (f fixture) sessionCount(t *testing.T, userID uuid.UUID) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM auth.sessions WHERE user_id = $1`, userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func wantError(t *testing.T, what string, res response, status int, code string) {
	t.Helper()
	if res.status != status || res.errorCode(t) != code {
		t.Errorf("%s: status %d, body %s; want %d %s", what, res.status, res.body, status, code)
	}
}

func TestLogInWithTwoFactor(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)
	secret, _ := f.enableTwoFactor(t, l.Token)
	sessions := f.sessionCount(t, l.User.ID)

	wantError(t, "wrong password", f.do(t, http.MethodPost, "/v1/sessions", credentials(testEmail, "not my password", "web")), 401, "invalid_credentials")

	res := f.do(t, http.MethodPost, "/v1/sessions", credentials(testEmail, testPassword, "mobile"))
	challenge := challengeIn(t, res)
	var c challengeResponse
	_ = json.Unmarshal(res.body, &c)
	if want := f.clock.now().Add(5 * time.Minute).Format(time.RFC3339); c.ExpiresAt != want {
		t.Errorf("expires_at = %s, want %s", c.ExpiresAt, want)
	}
	if strings.Contains(string(res.body), `"token"`) {
		t.Errorf("challenge response has a session token: %s", res.body)
	}
	if got := f.sessionCount(t, l.User.ID); got != sessions {
		t.Fatalf("%d sessions after the password step, want %d", got, sessions)
	}
	var stored int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM auth.two_factor_challenges WHERE token_hash = $1`, token.Hash(challenge)).Scan(&stored); err != nil || stored != 1 {
		t.Fatalf("challenge stored by hash: count %d, err %v", stored, err)
	}

	res = f.verify(t, challenge, f.code(secret))
	if res.status != http.StatusCreated {
		t.Fatalf("verify: status %d, body %s", res.status, res.body)
	}
	var got loginJSON
	if err := json.Unmarshal(res.body, &got); err != nil {
		t.Fatal(err)
	}
	if got.User.ID != l.User.ID || got.User.Email != testEmail {
		t.Errorf("user = %+v", got.User)
	}
	if f.status(t, got.Token) != http.StatusOK {
		t.Error("the new session doesn't work")
	}
	var client string
	if err := f.pool.QueryRow(context.Background(), `SELECT client FROM auth.sessions WHERE token_hash = $1`, token.Hash(got.Token)).Scan(&client); err != nil || client != "mobile" {
		t.Errorf("session client = %q (%v), want the login request's mobile", client, err)
	}
	if !strings.Contains(f.logs.String(), "auth: user logged in") {
		t.Error("login wasn't logged")
	}

	f.clock.advance(totp.Period)
	wantError(t, "challenge used again", f.verify(t, challenge, f.code(secret)), 401, "two_factor_challenge_invalid")
}

func TestVerifyChallengeRejects(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)
	secret, _ := f.enableTwoFactor(t, l.Token)
	challenge := f.startChallenge(t, testEmail)

	for name, body := range map[string]string{
		"no challenge": verifyBody("", "123456"),
		"no code":      verifyBody(challenge, ""),
	} {
		res := f.do(t, http.MethodPost, "/v1/two-factor-challenges/verify", body)
		wantError(t, name, res, 422, "validation_failed")
	}
	wantError(t, "malformed challenge", f.verify(t, "not-a-token", f.code(secret)), 401, "two_factor_challenge_invalid")
	wantError(t, "unknown challenge", f.verify(t, token.New(), f.code(secret)), 401, "two_factor_challenge_invalid")
	wantError(t, "wrong code", f.verify(t, challenge, f.wrongCode(secret)), 401, "invalid_two_factor_code")
	wantError(t, "unknown recovery code", f.verify(t, challenge, "ABCD-EFGH-IJKL-MNOP"), 401, "invalid_two_factor_code")
	wantError(t, "code from 2 steps ago", f.verify(t, challenge, totp.Code(secret, totp.Step(f.clock.now())-2)), 401, "invalid_two_factor_code")

	// The code is spent by one login, so it can't start another.
	code := f.code(secret)
	if res := f.verify(t, challenge, code); res.status != http.StatusCreated {
		t.Fatalf("right code: status %d, body %s", res.status, res.body)
	}
	wantError(t, "code used by another login", f.verify(t, f.startChallenge(t, testEmail), code), 401, "invalid_two_factor_code")
}

func TestChallengeExpires(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)
	secret, _ := f.enableTwoFactor(t, l.Token)

	challenge := f.startChallenge(t, testEmail)
	f.clock.advance(5*time.Minute - time.Second)
	if res := f.verify(t, challenge, f.code(secret)); res.status != http.StatusCreated {
		t.Errorf("just before expiry: status %d, body %s", res.status, res.body)
	}

	challenge = f.startChallenge(t, testEmail)
	f.clock.advance(5 * time.Minute)
	wantError(t, "at expiry", f.verify(t, challenge, f.code(secret)), 401, "two_factor_challenge_invalid")
}

func TestChallengeAllowsFiveWrongCodes(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)
	secret, _ := f.enableTwoFactor(t, l.Token)

	challenge := f.startChallenge(t, testEmail)
	for i := range 5 {
		wantError(t, fmt.Sprintf("wrong code %d", i+1), f.verify(t, challenge, f.wrongCode(secret)), 401, "invalid_two_factor_code")
	}
	wantError(t, "right code after 5 wrong", f.verify(t, challenge, f.code(secret)), 401, "two_factor_challenge_invalid")
	// Starting over with the password works.
	if res := f.verify(t, f.startChallenge(t, testEmail), f.code(secret)); res.status != http.StatusCreated {
		t.Errorf("new challenge: status %d, body %s", res.status, res.body)
	}
}

func TestRecoveryCodeAtLogin(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)
	_, codes := f.enableTwoFactor(t, l.Token)

	// Typed sloppily: lower case, spaces instead of dashes.
	typed := strings.ToLower(strings.ReplaceAll(codes[4], "-", " "))
	if res := f.verify(t, f.startChallenge(t, testEmail), typed); res.status != http.StatusCreated {
		t.Fatalf("recovery code: status %d, body %s", res.status, res.body)
	}
	emails := f.emailsTo(testEmail)
	last := emails[len(emails)-1]
	if last.Subject != "A recovery code was used for your Example account" || !strings.Contains(last.Text, "You have 9 recovery codes left") {
		t.Errorf("last email = %q:\n%s", last.Subject, last.Text)
	}
	wantError(t, "recovery code used again", f.verify(t, f.startChallenge(t, testEmail), codes[4]), 401, "invalid_two_factor_code")
}

func TestRecoveryCodeUsedSaysHowManyAreLeft(t *testing.T) {
	t.Parallel()
	for left, want := range map[int]string{0: "0 recovery codes", 1: "1 recovery code left", 7: "7 recovery codes"} {
		if _, text, _ := defaultRecoveryCodeUsed(EmailData{AppName: "Example", RecoveryCodesLeft: left}); !strings.Contains(text, "You have "+want) {
			t.Errorf("%d left:\n%s", left, text)
		}
	}
}

func TestGuessingLimit(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)
	secret, _ := f.enableTwoFactor(t, l.Token)
	warning := "Someone is trying to get into your Example account"
	warnings := func() int {
		n := 0
		for _, m := range f.emailsTo(testEmail) {
			if m.Subject == warning {
				n++
			}
		}
		return n
	}

	// 10 wrong codes over two challenges, 5 minutes apart. A third
	// challenge is started before the limit trips.
	first := f.startChallenge(t, testEmail)
	for range 5 {
		f.verify(t, first, f.wrongCode(secret))
	}
	f.clock.advance(5 * time.Minute)
	second, third := f.startChallenge(t, testEmail), f.startChallenge(t, testEmail)
	for i := range 5 {
		if warnings() != 0 {
			t.Fatalf("warned after %d wrong codes", 5+i)
		}
		wantError(t, fmt.Sprintf("wrong code %d", 6+i), f.verify(t, second, f.wrongCode(secret)), 401, "invalid_two_factor_code")
	}
	if got := warnings(); got != 1 {
		t.Errorf("%d warning emails after 10 wrong codes, want 1", got)
	}
	if !strings.Contains(f.logs.String(), "auth: two-factor guessing limit reached") {
		t.Error("reaching the limit wasn't logged")
	}

	// Paused until 15 minutes after the oldest of the 10.
	res := f.do(t, http.MethodPost, "/v1/sessions", credentials(testEmail, testPassword, "web"))
	wantError(t, "logging in while paused", res, 429, "rate_limited")
	if got := res.header.Get("Retry-After"); got != "600" {
		t.Errorf("Retry-After = %q, want 600", got)
	}
	wantError(t, "right code on an earlier challenge while paused", f.verify(t, third, f.code(secret)), 429, "rate_limited")
	if got := warnings(); got != 1 {
		t.Errorf("%d warning emails, want still 1", got)
	}

	f.clock.advance(10*time.Minute - time.Second)
	wantError(t, "a second before the pause ends", f.do(t, http.MethodPost, "/v1/sessions", credentials(testEmail, testPassword, "web")), 429, "rate_limited")
	f.clock.advance(time.Second)
	if res := f.verify(t, f.startChallenge(t, testEmail), f.code(secret)); res.status != http.StatusCreated {
		t.Errorf("after the pause: status %d, body %s", res.status, res.body)
	}
}

func TestGuessingLimitIsPerUser(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	ada := f.signUp(t, testEmail)
	grace := f.signUp(t, "grace@example.com")
	f.enableTwoFactor(t, ada.Token)
	f.enableTwoFactor(t, grace.Token)
	f.tripGuessingLimit(t, ada.User.ID)

	wantError(t, "Ada", f.do(t, http.MethodPost, "/v1/sessions", credentials(testEmail, testPassword, "web")), 429, "rate_limited")
	f.startChallenge(t, "grace@example.com")
}

// TestGuessingLimitCountsOneAtATime checks a code check waits for another
// in progress before checking the limit, so concurrent wrong codes can't
// overshoot it.
func TestGuessingLimitCountsOneAtATime(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)
	secret, _ := f.enableTwoFactor(t, l.Token)
	challenge := f.startChallenge(t, testEmail)
	ctx := context.Background()

	// Another request is recording the wrong code that reaches the limit:
	// it holds the lock but hasn't committed.
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT 1 FROM auth.totp_secrets WHERE user_id = $1 FOR UPDATE`, l.User.ID); err != nil {
		t.Fatal(err)
	}
	for range guessLimit {
		if _, err := tx.Exec(ctx, `INSERT INTO auth.two_factor_failures (id, user_id, created_at) VALUES ($1, $2, $3)`, uuid.Must(uuid.NewV7()), l.User.ID, f.clock.now()); err != nil {
			t.Fatal(err)
		}
	}

	result := make(chan response, 1)
	go func() { result <- f.verify(t, challenge, f.code(secret)) }()
	f.waitForLock(t, result)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	wantError(t, "code checked during another's wrong code", <-result, 429, "rate_limited")
}

// waitForLock waits until a request is blocked on a lock, failing if it
// finishes first.
func (f fixture) waitForLock(t *testing.T, result chan response) {
	t.Helper()
	for waiting := false; !waiting; {
		select {
		case res := <-result:
			t.Fatalf("request finished (status %d, body %s) while another held the lock; want it to wait", res.status, res.body)
		default:
		}
		if err := f.pool.QueryRow(context.Background(), `
			SELECT EXISTS (
				SELECT 1 FROM pg_stat_activity
				WHERE datname = current_database() AND wait_event_type = 'Lock'
			)`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
	}
}

// TestChallengeIsUsedOnce checks two requests can't both use one
// challenge, even with two different recovery codes.
func TestChallengeIsUsedOnce(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)
	_, codes := f.enableTwoFactor(t, l.Token)
	challenge := f.startChallenge(t, testEmail)
	ctx := context.Background()

	// Another request is using the challenge, and hasn't committed.
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `UPDATE auth.two_factor_challenges SET used_at = $1 WHERE token_hash = $2`, f.clock.now(), token.Hash(challenge)); err != nil {
		t.Fatal(err)
	}

	result := make(chan response, 1)
	go func() { result <- f.verify(t, challenge, codes[1]) }()
	f.waitForLock(t, result)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	wantError(t, "challenge used concurrently", <-result, 401, "two_factor_challenge_invalid")
}

func TestPasswordChangeEndsChallenges(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)
	secret, _ := f.enableTwoFactor(t, l.Token)
	challenge := f.startChallenge(t, testEmail)

	if res := f.do(t, http.MethodPost, "/v1/users/me/password", changeBody(testPassword, newPassword), withToken(l.Token)); res.status != http.StatusNoContent {
		t.Fatalf("changing password: status %d, body %s", res.status, res.body)
	}
	wantError(t, "challenge from the old password", f.verify(t, challenge, f.code(secret)), 401, "two_factor_challenge_invalid")
}

func TestVerificationLinkStartsChallenge(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)
	secret, _ := f.enableTwoFactor(t, l.Token)
	link := f.emailTokenOf(t, testEmail, 0)
	body := func(pw string) string {
		b, _ := json.Marshal(map[string]string{"token": link, "password": pw, "client": "web"})
		return string(b)
	}
	sessions := f.sessionCount(t, l.User.ID)

	f.tripGuessingLimit(t, l.User.ID)
	wantError(t, "while paused", f.do(t, http.MethodPost, "/v1/email-verifications/confirm", body(testPassword)), 429, "rate_limited")
	if f.verifiedAt(t, testEmail) != nil {
		t.Fatal("email verified while paused")
	}
	f.clock.advance(guessWindow)

	challenge := challengeIn(t, f.do(t, http.MethodPost, "/v1/email-verifications/confirm", body(testPassword)))
	if f.verifiedAt(t, testEmail) == nil {
		t.Error("email not verified")
	}
	if got := f.sessionCount(t, l.User.ID); got != sessions {
		t.Errorf("%d sessions after the link, want %d", got, sessions)
	}
	res := f.verify(t, challenge, f.code(secret))
	if res.status != http.StatusCreated {
		t.Fatalf("verify: status %d, body %s", res.status, res.body)
	}
	var got loginJSON
	if err := json.Unmarshal(res.body, &got); err != nil || !got.User.EmailVerified {
		t.Errorf("user = %s, want email_verified", res.body)
	}
}

func TestPasswordResetWithTwoFactor(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)
	secret, codes := f.enableTwoFactor(t, l.Token)
	challenge := f.startChallenge(t, testEmail)
	f.clock.advance(emailtoken.Cooldown)
	tok := f.requestReset(t, testEmail)
	oldHash := f.passwordHash(t, testEmail)

	res := f.do(t, http.MethodPost, "/v1/password-resets/confirm", resetBody(tok, newPassword))
	wantError(t, "no code", res, 422, "validation_failed")
	if !strings.Contains(string(res.body), detailJSON("code:required")) {
		t.Errorf("no code: body %s, want code:required", res.body)
	}
	wantError(t, "wrong code", f.do(t, http.MethodPost, "/v1/password-resets/confirm", resetCodeBody(tok, newPassword, f.wrongCode(secret))), 401, "invalid_two_factor_code")
	if got := f.passwordHash(t, testEmail); *got != *oldHash {
		t.Fatal("password changed without the right code")
	}
	if f.status(t, l.Token) != http.StatusOK {
		t.Fatal("sessions ended without the right code")
	}

	if res := f.do(t, http.MethodPost, "/v1/password-resets/confirm", resetCodeBody(tok, newPassword, f.code(secret))); res.status != http.StatusNoContent {
		t.Fatalf("right code: status %d, body %s", res.status, res.body)
	}
	if f.status(t, l.Token) != http.StatusUnauthorized {
		t.Error("sessions survived the reset")
	}
	wantError(t, "challenge from before the reset", f.verify(t, challenge, codes[0]), 401, "two_factor_challenge_invalid")

	// With a recovery code, for someone who lost their phone.
	f.clock.advance(emailtoken.Cooldown)
	tok = f.requestReset(t, testEmail)
	if res := f.do(t, http.MethodPost, "/v1/password-resets/confirm", resetCodeBody(tok, testPassword, codes[0])); res.status != http.StatusNoContent {
		t.Fatalf("recovery code: status %d, body %s", res.status, res.body)
	}
	found := false
	for _, m := range f.emailsTo(testEmail) {
		found = found || strings.Contains(m.Text, "You have 9 recovery codes left")
	}
	if !found {
		t.Error("no recovery-code notice")
	}
}

func TestWrongResetCodesCount(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)
	secret, _ := f.enableTwoFactor(t, l.Token)
	tok := f.requestReset(t, testEmail)

	// Toward the link's 5 attempts...
	for range emailtoken.MaxFailedAttempts {
		f.do(t, http.MethodPost, "/v1/password-resets/confirm", resetCodeBody(tok, newPassword, f.wrongCode(secret)))
	}
	wantError(t, "link after 5 wrong codes", f.do(t, http.MethodPost, "/v1/password-resets/confirm", resetCodeBody(tok, newPassword, f.code(secret))), 422, "token_invalid_or_expired")

	// ...and toward the guessing limit.
	challenge := f.startChallenge(t, testEmail)
	for range guessLimit - emailtoken.MaxFailedAttempts {
		f.verify(t, challenge, f.wrongCode(secret))
	}
	wantError(t, "logging in", f.do(t, http.MethodPost, "/v1/sessions", credentials(testEmail, testPassword, "web")), 429, "rate_limited")
	f.clock.advance(emailtoken.Cooldown)
	tok = f.requestReset(t, testEmail)
	wantError(t, "resetting", f.do(t, http.MethodPost, "/v1/password-resets/confirm", resetCodeBody(tok, newPassword, f.code(secret))), 429, "rate_limited")
}

func TestResetTwoFactor(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)
	f.enableTwoFactor(t, l.Token)
	f.startChallenge(t, testEmail)
	grace := f.signUp(t, "grace@example.com")
	f.startSetup(t, grace.Token)
	ctx := context.Background()

	if err := f.auth.ResetTwoFactor(ctx, l.User.ID); err != nil {
		t.Fatal(err)
	}
	if f.status(t, l.Token) != http.StatusUnauthorized {
		t.Error("sessions survived")
	}
	if f.twoFactorEnabled(t, f.logIn(t, testEmail).Token) {
		t.Error("2FA still on")
	}
	var left int
	if err := f.pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM auth.recovery_codes WHERE user_id = $1) + (SELECT count(*) FROM auth.two_factor_challenges WHERE user_id = $1)`,
		l.User.ID).Scan(&left); err != nil || left != 0 {
		t.Errorf("%d recovery codes and challenges left (%v), want 0", left, err)
	}
	emails := f.emailsTo(testEmail)
	if last := emails[len(emails)-1]; last.Subject != "Two-factor authentication is off for your Example account" {
		t.Errorf("last email = %q, want the 2FA off notice", last.Subject)
	}

	// Users without 2FA are left alone: no email, sessions kept, pending
	// setup kept.
	before := len(f.sent())
	for _, id := range []uuid.UUID{grace.User.ID, uuid.Must(uuid.NewV7())} {
		if err := f.auth.ResetTwoFactor(ctx, id); err != nil {
			t.Errorf("user %s: %v", id, err)
		}
	}
	if f.status(t, grace.Token) != http.StatusOK || len(f.sent()) != before {
		t.Error("a user without 2FA was changed")
	}
	if res := f.do(t, http.MethodPost, "/v1/users/me/two-factor/confirm", codeBody("000000"), withToken(grace.Token)); res.errorCode(t) == "two_factor_setup_not_started" {
		t.Error("pending setup was deleted")
	}
}

func TestTwoFactorLoginKeepsSecretsOutOfLogs(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)
	secret, codes := f.enableTwoFactor(t, l.Token)
	challenge := f.startChallenge(t, testEmail)
	wrong := f.wrongCode(secret)
	f.verify(t, challenge, wrong)
	right := f.code(secret)
	res := f.verify(t, challenge, right)
	var got loginJSON
	_ = json.Unmarshal(res.body, &got)
	f.verify(t, f.startChallenge(t, testEmail), codes[0])

	logs := f.logs.String()
	for _, event := range []string{"auth: two-factor challenge started", "auth: wrong two-factor code", "auth: recovery code used", "auth: user logged in"} {
		if !strings.Contains(logs, event) {
			t.Errorf("%q wasn't logged", event)
		}
	}
	for _, s := range []string{challenge, wrong, right, codes[0], got.Token, totp.EncodeSecret(secret), testPassword} {
		if s != "" && strings.Contains(logs, s) {
			t.Errorf("logs contain %q", s)
		}
	}
}
