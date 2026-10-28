package auth

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/atlasopsec/auth/internal/db"
	"github.com/atlasopsec/auth/internal/recoverycode"
	"github.com/atlasopsec/auth/internal/totp"
)

type setupResponse struct {
	Secret     string `json:"secret"`
	OTPAuthURI string `json:"otpauth_uri"`
}

func pwBody(pw string) string {
	b, _ := json.Marshal(map[string]string{"current_password": pw})
	return string(b)
}

func pwCodeBody(pw, code string) string {
	b, _ := json.Marshal(map[string]string{"current_password": pw, "code": code})
	return string(b)
}

func codeBody(code string) string {
	b, _ := json.Marshal(map[string]string{"code": code})
	return string(b)
}

// startSetup starts 2FA setup and returns the secret.
func (f fixture) startSetup(t *testing.T, tok string) []byte {
	t.Helper()
	res := f.do(t, http.MethodPost, "/v1/users/me/two-factor", pwBody(testPassword), withToken(tok))
	if res.status != http.StatusCreated {
		t.Fatalf("starting 2FA setup: status %d, body %s", res.status, res.body)
	}
	var s setupResponse
	if err := json.Unmarshal(res.body, &s); err != nil {
		t.Fatal(err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s.Secret)
	if err != nil {
		t.Fatalf("secret %q isn't unpadded base32: %v", s.Secret, err)
	}
	return secret
}

// code returns the current TOTP code for secret.
func (f fixture) code(secret []byte) string {
	return totp.Code(secret, totp.Step(f.clock.now()))
}

// enableTwoFactor sets up 2FA and returns the secret and recovery codes.
// It moves the clock past the step it used, so the next code is fresh.
func (f fixture) enableTwoFactor(t *testing.T, tok string) ([]byte, []string) {
	t.Helper()
	secret := f.startSetup(t, tok)
	res := f.do(t, http.MethodPost, "/v1/users/me/two-factor/confirm", codeBody(f.code(secret)), withToken(tok))
	if res.status != http.StatusOK {
		t.Fatalf("confirming 2FA: status %d, body %s", res.status, res.body)
	}
	var r struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if err := json.Unmarshal(res.body, &r); err != nil {
		t.Fatal(err)
	}
	f.clock.advance(totp.Period)
	return secret, r.RecoveryCodes
}

func (f fixture) twoFactorEnabled(t *testing.T, tok string) bool {
	t.Helper()
	var me struct {
		Enabled *bool `json:"two_factor_enabled"`
	}
	res := f.do(t, http.MethodGet, "/v1/users/me", "", withToken(tok))
	if err := json.Unmarshal(res.body, &me); err != nil || me.Enabled == nil {
		t.Fatalf("GET /v1/users/me: %s", res.body)
	}
	return *me.Enabled
}

var recoveryCodeFormat = regexp.MustCompile(`^[A-Z2-7]{4}(-[A-Z2-7]{4}){3}$`)

func TestTwoFactorSetup(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)

	res := f.do(t, http.MethodPost, "/v1/users/me/two-factor", pwBody(testPassword), withToken(l.Token))
	if res.status != http.StatusCreated {
		t.Fatalf("status %d, body %s", res.status, res.body)
	}
	var s setupResponse
	if err := json.Unmarshal(res.body, &s); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s.OTPAuthURI, "otpauth://totp/Example:ada@example.com?") || !strings.Contains(s.OTPAuthURI, "secret="+s.Secret) {
		t.Errorf("otpauth_uri = %s", s.OTPAuthURI)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s.Secret)
	if err != nil || len(secret) != totp.SecretSize {
		t.Fatalf("secret %q: %v", s.Secret, err)
	}
	// Stored encrypted, and not on until confirmed.
	var stored []byte
	if err := f.pool.QueryRow(context.Background(), `SELECT secret_encrypted FROM auth.totp_secrets WHERE user_id = $1`, l.User.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, secret) {
		t.Error("secret stored in plain text")
	}
	if f.twoFactorEnabled(t, l.Token) {
		t.Error("2FA on before confirming")
	}

	res = f.do(t, http.MethodPost, "/v1/users/me/two-factor/confirm", codeBody(f.code(secret)), withToken(l.Token))
	if res.status != http.StatusOK {
		t.Fatalf("confirm: status %d, body %s", res.status, res.body)
	}
	var r struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if err := json.Unmarshal(res.body, &r); err != nil {
		t.Fatal(err)
	}
	if len(r.RecoveryCodes) != recoverycode.Count {
		t.Fatalf("got %d recovery codes, want %d", len(r.RecoveryCodes), recoverycode.Count)
	}
	for _, c := range r.RecoveryCodes {
		if !recoveryCodeFormat.MatchString(c) {
			t.Errorf("recovery code %q has the wrong format", c)
		}
	}
	if !f.twoFactorEnabled(t, l.Token) {
		t.Error("2FA off after confirming")
	}
	// Only hashes of the recovery codes are stored.
	rows, err := f.pool.Query(context.Background(), `SELECT code_hash FROM auth.recovery_codes WHERE user_id = $1`, l.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var h []byte
		if err := rows.Scan(&h); err != nil {
			t.Fatal(err)
		}
		for _, c := range r.RecoveryCodes {
			if bytes.Contains(h, []byte(strings.ReplaceAll(c, "-", ""))) {
				t.Error("recovery code stored in plain text")
			}
		}
		n++
	}
	if n != recoverycode.Count {
		t.Errorf("%d recovery codes stored, want %d", n, recoverycode.Count)
	}
	emails := f.emailsTo(testEmail)
	if last := emails[len(emails)-1]; last.Subject != "Two-factor authentication is on for your Example account" {
		t.Errorf("last email = %q, want the 2FA on notice", last.Subject)
	}
}

func TestTwoFactorSetupRejects(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)

	tests := []struct {
		name       string
		path, body string
		want       int
		wantCode   string
		wantDetail string
	}{
		{"start without password", "/v1/users/me/two-factor", pwBody(""), 422, "validation_failed", "current_password:required"},
		{"start with wrong password", "/v1/users/me/two-factor", pwBody("not my password"), 422, "validation_failed", "current_password:incorrect"},
		{"confirm before starting", "/v1/users/me/two-factor/confirm", codeBody("123456"), 409, "two_factor_setup_not_started", ""},
		{"confirm without code", "/v1/users/me/two-factor/confirm", codeBody(""), 422, "validation_failed", "code:required"},
	}
	for _, tt := range tests {
		res := f.do(t, http.MethodPost, tt.path, tt.body, withToken(l.Token))
		if res.status != tt.want || res.errorCode(t) != tt.wantCode {
			t.Errorf("%s: status %d, body %s; want %d %s", tt.name, res.status, res.body, tt.want, tt.wantCode)
			continue
		}
		if tt.wantDetail != "" && !strings.Contains(string(res.body), detailJSON(tt.wantDetail)) {
			t.Errorf("%s: body %s, want detail %s", tt.name, res.body, tt.wantDetail)
		}
	}
	if res := f.do(t, http.MethodPost, "/v1/users/me/two-factor", pwBody(testPassword)); res.status != http.StatusUnauthorized {
		t.Errorf("not logged in: status %d, want 401", res.status)
	}

	secret := f.startSetup(t, l.Token)
	step := totp.Step(f.clock.now())
	for name, code := range map[string]string{
		"wrong code":            "000000",
		"code from 2 steps ago": totp.Code(secret, step-2),
		"another secret's code": totp.Code(totp.NewSecret(), step),
		"recovery-code shaped":  "ABCD-EFGH-IJKL-MNOP",
	} {
		res := f.do(t, http.MethodPost, "/v1/users/me/two-factor/confirm", codeBody(code), withToken(l.Token))
		if res.status != http.StatusUnprocessableEntity || !strings.Contains(string(res.body), detailJSON("code:incorrect")) {
			t.Errorf("%s: status %d, body %s; want 422 code incorrect", name, res.status, res.body)
		}
	}
	if f.twoFactorEnabled(t, l.Token) {
		t.Fatal("2FA on after rejected codes")
	}

	f.do(t, http.MethodPost, "/v1/users/me/two-factor/confirm", codeBody(f.code(secret)), withToken(l.Token))
	for name, c := range map[string]struct{ path, body string }{
		"start again":   {"/v1/users/me/two-factor", pwBody(testPassword)},
		"confirm again": {"/v1/users/me/two-factor/confirm", codeBody(f.code(secret))},
	} {
		if res := f.do(t, http.MethodPost, c.path, c.body, withToken(l.Token)); res.status != http.StatusConflict || res.errorCode(t) != "two_factor_already_enabled" {
			t.Errorf("%s: status %d, body %s; want 409 two_factor_already_enabled", name, res.status, res.body)
		}
	}
}

// detailJSON turns "field:code" into how the error body spells it.
func detailJSON(fc string) string {
	field, code, _ := strings.Cut(fc, ":")
	return `"field":"` + field + `","code":"` + code + `"`
}

func TestRestartingSetupReplacesTheSecret(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)
	first := f.startSetup(t, l.Token)
	second := f.startSetup(t, l.Token)
	if bytes.Equal(first, second) {
		t.Fatal("restarting setup kept the same secret")
	}
	if res := f.do(t, http.MethodPost, "/v1/users/me/two-factor/confirm", codeBody(f.code(first)), withToken(l.Token)); res.status != http.StatusUnprocessableEntity {
		t.Errorf("code from the replaced secret: status %d, want 422", res.status)
	}
	if res := f.do(t, http.MethodPost, "/v1/users/me/two-factor/confirm", codeBody(f.code(second)), withToken(l.Token)); res.status != http.StatusOK {
		t.Errorf("code from the new secret: status %d, body %s", res.status, res.body)
	}
}

func TestDisableTwoFactor(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)
	secret, _ := f.enableTwoFactor(t, l.Token)

	for name, c := range map[string]struct {
		body, wantDetail string
	}{
		"wrong password": {pwCodeBody("not my password", f.code(secret)), "current_password:incorrect"},
		"wrong code":     {pwCodeBody(testPassword, "000000"), "code:incorrect"},
		"missing both":   {pwCodeBody("", ""), "current_password:required"},
	} {
		res := f.do(t, http.MethodDelete, "/v1/users/me/two-factor", c.body, withToken(l.Token))
		if res.status != http.StatusUnprocessableEntity || !strings.Contains(string(res.body), detailJSON(c.wantDetail)) {
			t.Errorf("%s: status %d, body %s; want 422 with %s", name, res.status, res.body, c.wantDetail)
		}
	}
	if !f.twoFactorEnabled(t, l.Token) {
		t.Fatal("2FA turned off by a rejected request")
	}

	res := f.do(t, http.MethodDelete, "/v1/users/me/two-factor", pwCodeBody(testPassword, f.code(secret)), withToken(l.Token))
	if res.status != http.StatusNoContent {
		t.Fatalf("status %d, body %s", res.status, res.body)
	}
	if f.twoFactorEnabled(t, l.Token) {
		t.Error("2FA still on")
	}
	var left int
	if err := f.pool.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM auth.totp_secrets) + (SELECT count(*) FROM auth.recovery_codes)`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Errorf("%d secrets or recovery codes left after turning 2FA off", left)
	}
	emails := f.emailsTo(testEmail)
	if last := emails[len(emails)-1]; last.Subject != "Two-factor authentication is off for your Example account" {
		t.Errorf("last email = %q, want the 2FA off notice", last.Subject)
	}
	if res := f.do(t, http.MethodDelete, "/v1/users/me/two-factor", pwCodeBody(testPassword, "123456"), withToken(l.Token)); res.status != http.StatusConflict || res.errorCode(t) != "two_factor_not_enabled" {
		t.Errorf("turning off again: status %d, body %s", res.status, res.body)
	}
}

func TestDisableWithRecoveryCode(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)
	_, codes := f.enableTwoFactor(t, l.Token)
	// Typed loosely: lowercase, without dashes.
	loose := strings.ToLower(strings.ReplaceAll(codes[3], "-", ""))
	if res := f.do(t, http.MethodDelete, "/v1/users/me/two-factor", pwCodeBody(testPassword, loose), withToken(l.Token)); res.status != http.StatusNoContent {
		t.Errorf("status %d, body %s", res.status, res.body)
	}
}

func TestRequiredTwoFactorCantBeTurnedOff(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)
	secret, _ := f.enableTwoFactor(t, l.Token)
	if _, err := f.pool.Exec(context.Background(), `UPDATE auth.users SET two_factor_required = true`); err != nil {
		t.Fatal(err)
	}
	res := f.do(t, http.MethodDelete, "/v1/users/me/two-factor", pwCodeBody(testPassword, f.code(secret)), withToken(l.Token))
	if res.status != http.StatusForbidden || res.errorCode(t) != "two_factor_required" {
		t.Errorf("status %d, body %s; want 403 two_factor_required", res.status, res.body)
	}
	if !f.twoFactorEnabled(t, l.Token) {
		t.Error("required 2FA was turned off")
	}
}

func TestRegenerateRecoveryCodes(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)
	secret, old := f.enableTwoFactor(t, l.Token)

	if res := f.do(t, http.MethodPost, "/v1/users/me/two-factor/recovery-codes", pwCodeBody(testPassword, "000000"), withToken(l.Token)); res.status != http.StatusUnprocessableEntity {
		t.Errorf("wrong code: status %d, want 422", res.status)
	}
	res := f.do(t, http.MethodPost, "/v1/users/me/two-factor/recovery-codes", pwCodeBody(testPassword, f.code(secret)), withToken(l.Token))
	if res.status != http.StatusOK {
		t.Fatalf("status %d, body %s", res.status, res.body)
	}
	var r struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if err := json.Unmarshal(res.body, &r); err != nil {
		t.Fatal(err)
	}
	if len(r.RecoveryCodes) != recoverycode.Count || r.RecoveryCodes[0] == old[0] {
		t.Fatalf("new codes = %v", r.RecoveryCodes)
	}
	emails := f.emailsTo(testEmail)
	if last := emails[len(emails)-1]; last.Subject != "New recovery codes for your Example account" {
		t.Errorf("last email = %q", last.Subject)
	}

	// Old codes no longer work; new ones do.
	disable := func(code string) int {
		return f.do(t, http.MethodDelete, "/v1/users/me/two-factor", pwCodeBody(testPassword, code), withToken(l.Token)).status
	}
	if got := disable(old[0]); got != http.StatusUnprocessableEntity {
		t.Errorf("old recovery code: status %d, want 422", got)
	}
	if got := disable(r.RecoveryCodes[0]); got != http.StatusNoContent {
		t.Errorf("new recovery code: status %d, want 204", got)
	}

	if res := f.do(t, http.MethodPost, "/v1/users/me/two-factor/recovery-codes", pwCodeBody(testPassword, "123456"), withToken(l.Token)); res.status != http.StatusConflict {
		t.Errorf("with 2FA off: status %d, want 409", res.status)
	}
}

func TestCodesWorkOnce(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)
	secret, _ := f.enableTwoFactor(t, l.Token)
	regenerate := func(code string) int {
		return f.do(t, http.MethodPost, "/v1/users/me/two-factor/recovery-codes", pwCodeBody(testPassword, code), withToken(l.Token)).status
	}

	code := f.code(secret)
	if got := regenerate(code); got != http.StatusOK {
		t.Fatalf("first use of a TOTP code: status %d", got)
	}
	if got := regenerate(code); got != http.StatusUnprocessableEntity {
		t.Errorf("same TOTP code again: status %d, want 422", got)
	}
	f.clock.advance(totp.Period)
	if got := regenerate(f.code(secret)); got != http.StatusOK {
		t.Errorf("next step's code: status %d, want 200", got)
	}

}

// TestRecoveryCodesWorkOnce checks the code check directly: through HTTP,
// every endpoint in this step that takes a recovery code also replaces or
// deletes them all.
func TestRecoveryCodesWorkOnce(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)
	_, codes := f.enableTwoFactor(t, l.Token)
	check := func(code string) error {
		return f.auth.inTx(context.Background(), func(q *db.Queries) error {
			used, err := f.auth.checkSecondFactor(context.Background(), q, l.User.ID, code)
			if err == nil && !used {
				t.Errorf("%s: accepted, but not as a recovery code", code)
			}
			return err
		})
	}
	if err := check(codes[2]); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if err := check(codes[2]); !errors.Is(err, errBadCode) {
		t.Errorf("second use: error = %v, want errBadCode", err)
	}
	if err := check(codes[3]); err != nil {
		t.Errorf("another unused code: %v", err)
	}
}

func TestSecretIsBoundToItsUser(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	ada := f.signUp(t, testEmail)
	grace := f.signUp(t, "grace@example.com")
	adaSecret, _ := f.enableTwoFactor(t, ada.Token)
	f.enableTwoFactor(t, grace.Token)

	// Someone with database write access copies Ada's encrypted secret
	// onto Grace's row, to use codes they know for Grace's account.
	if _, err := f.pool.Exec(context.Background(), `
		UPDATE auth.totp_secrets SET secret_encrypted = (SELECT secret_encrypted FROM auth.totp_secrets WHERE user_id = $1)
		WHERE user_id = $2`, ada.User.ID, grace.User.ID); err != nil {
		t.Fatal(err)
	}
	res := f.do(t, http.MethodPost, "/v1/users/me/two-factor/recovery-codes", pwCodeBody(testPassword, f.code(adaSecret)), withToken(grace.Token))
	if res.status == http.StatusOK {
		t.Error("a secret copied from another user's row worked")
	}
	if !strings.Contains(f.logs.String(), "decrypting 2FA secret") {
		t.Errorf("failed decryption wasn't logged:\n%s", f.logs)
	}
}

func TestTwoFactorSecretsStayOutOfLogs(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)
	secret, codes := f.enableTwoFactor(t, l.Token)
	f.do(t, http.MethodDelete, "/v1/users/me/two-factor", pwCodeBody(testPassword, codes[0]), withToken(l.Token))

	logs := f.logs.String()
	if !strings.Contains(logs, "auth: two-factor enabled") || !strings.Contains(logs, "auth: two-factor disabled") {
		t.Fatalf("events weren't logged:\n%s", logs)
	}
	for _, s := range append([]string{totp.EncodeSecret(secret), testPassword}, codes...) {
		if strings.Contains(logs, s) {
			t.Errorf("logs contain %q", s)
		}
	}
}

// TestCodeCheckLocksTheSecret checks a code can't be used by two requests
// at once: a check must wait for another in progress, then see its step
// recorded and refuse the same code.
func TestCodeCheckLocksTheSecret(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)
	secret, _ := f.enableTwoFactor(t, l.Token)
	ctx := context.Background()
	code := f.code(secret)

	// Another request is using this code: it holds the lock and has
	// recorded the step, but hasn't committed yet.
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `UPDATE auth.totp_secrets SET last_used_step = $1 WHERE user_id = $2`, totp.Step(f.clock.now()), l.User.ID); err != nil {
		t.Fatal(err)
	}

	result := make(chan response, 1)
	go func() {
		result <- f.do(t, http.MethodPost, "/v1/users/me/two-factor/recovery-codes", pwCodeBody(testPassword, code), withToken(l.Token))
	}()
	for waiting := false; !waiting; {
		select {
		case res := <-result:
			t.Fatalf("code check finished (status %d) while another held the lock; want it to wait", res.status)
		default:
		}
		if err := f.pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_stat_activity
				WHERE datname = current_database() AND wait_event_type = 'Lock'
			)`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if res := <-result; res.status != http.StatusUnprocessableEntity {
		t.Errorf("status %d, body %s; want 422 (code already used)", res.status, res.body)
	}
}
