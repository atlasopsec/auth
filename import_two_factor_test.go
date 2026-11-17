package auth

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/atlasopsec/auth/internal/totp"
)

func TestImportTwoFactor(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	ctx := context.Background()
	by, adminID := adminActor(t, f)
	l := f.user(t, testEmail)
	secret := bytes.Repeat([]byte{0x42}, 20)
	before := len(f.sent())

	if err := f.auth.ImportTwoFactor(ctx, l.User.ID, strings.ToLower(totp.EncodeSecret(secret)), by); err != nil {
		t.Fatalf("ImportTwoFactor() error = %v", err)
	}
	if n := f.sessionCount(t, l.User.ID); n != 0 {
		t.Errorf("%d sessions after turning 2FA on, want 0", n)
	}
	if got := len(f.sent()) - before; got != 0 {
		t.Errorf("sent %d emails, want none", got)
	}
	// Stored encrypted, never as the secret or its base32.
	var stored []byte
	if err := f.pool.QueryRow(ctx, `SELECT secret_encrypted FROM auth.totp_secrets WHERE user_id = $1 AND confirmed_at IS NOT NULL`, l.User.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, secret) || bytes.Contains(stored, []byte(totp.EncodeSecret(secret))) {
		t.Error("secret stored in the clear")
	}

	// The user's existing authenticator app logs them in.
	res := f.do(t, http.MethodPost, "/v1/sessions", credentials(testEmail, testPassword, "web"))
	challenge := challengeIn(t, res)
	if res := f.verify(t, challenge, f.code(secret)); res.status != http.StatusCreated {
		t.Fatalf("verify with the imported secret: status %d, body %s", res.status, res.body)
	}

	// The same secret again changes nothing: sessions stay.
	if err := f.auth.ImportTwoFactor(ctx, l.User.ID, totp.EncodeSecret(secret), by); err != nil {
		t.Fatal(err)
	}
	if n := f.sessionCount(t, l.User.ID); n != 1 {
		t.Errorf("%d sessions after importing the same secret, want 1", n)
	}

	// A new one replaces it: the old app's codes stop working.
	f.clock.advance(totp.Period)
	other := bytes.Repeat([]byte{0x17}, 32)
	if err := f.auth.ImportTwoFactor(ctx, l.User.ID, totp.EncodeSecret(other), by); err != nil {
		t.Fatal(err)
	}
	res = f.do(t, http.MethodPost, "/v1/sessions", credentials(testEmail, testPassword, "web"))
	challenge = challengeIn(t, res)
	wantError(t, "old secret", f.verify(t, challenge, f.code(secret)), 401, "invalid_two_factor_code")
	if res := f.verify(t, challenge, f.code(other)); res.status != http.StatusCreated {
		t.Errorf("verify with the new secret: status %d, body %s", res.status, res.body)
	}

	var n int
	for _, e := range f.eventsOf(t, l.User.ID) {
		if e.Type == EventTwoFactorEnabled && e.ActorID != nil && *e.ActorID == adminID {
			n++
		}
	}
	if n != 2 {
		t.Errorf("%d two_factor_enabled events by the admin, want 2", n)
	}
	if strings.Contains(f.logs.String(), totp.EncodeSecret(secret)) || strings.Contains(f.allEventRows(t), totp.EncodeSecret(other)) {
		t.Error("a secret was logged")
	}
}

func TestImportTwoFactorReplacesPendingSetup(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	l := f.user(t, testEmail)
	pending := f.startSetup(t, l.Token)
	secret := bytes.Repeat([]byte{0x42}, 20)
	if err := f.auth.ImportTwoFactor(context.Background(), l.User.ID, totp.EncodeSecret(secret), Actor{}); err != nil {
		t.Fatal(err)
	}
	res := f.do(t, http.MethodPost, "/v1/sessions", credentials(testEmail, testPassword, "web"))
	challenge := challengeIn(t, res)
	wantError(t, "pending setup's secret", f.verify(t, challenge, f.code(pending)), 401, "invalid_two_factor_code")
	if res := f.verify(t, challenge, f.code(secret)); res.status != http.StatusCreated {
		t.Errorf("verify: status %d, body %s", res.status, res.body)
	}
}

func TestImportTwoFactorRejects(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	ctx := context.Background()
	l := f.user(t, testEmail)
	good := totp.EncodeSecret(bytes.Repeat([]byte{0x42}, 20))

	short := totp.EncodeSecret(bytes.Repeat([]byte{0x42}, 10))
	for name, s := range map[string]string{"empty": "", "80 bits": short, "not base32": "not a secret!"} {
		err := f.auth.ImportTwoFactor(ctx, l.User.ID, s, Actor{})
		if !errors.Is(err, ErrInvalidTwoFactorSecret) {
			t.Errorf("%s: error = %v, want ErrInvalidTwoFactorSecret", name, err)
		}
		if err != nil && s != "" && strings.Contains(err.Error(), s) {
			t.Errorf("%s: error contains the secret", name)
		}
	}
	if err := f.auth.ImportTwoFactor(ctx, uuid.Must(uuid.NewV7()), good, Actor{}); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("no such user: error = %v, want ErrUserNotFound", err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE auth.users SET email_verified_at = NULL WHERE id = $1`, l.User.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.auth.ImportTwoFactor(ctx, l.User.ID, good, Actor{}); !errors.Is(err, ErrEmailNotVerified) {
		t.Errorf("unverified email: error = %v, want ErrEmailNotVerified", err)
	}
	var n int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM auth.totp_secrets`).Scan(&n); err != nil || n != 0 {
		t.Errorf("%d secrets stored (%v) after refused imports, want 0", n, err)
	}
	if n := f.sessionCount(t, l.User.ID); n != 1 {
		t.Errorf("%d sessions, want 1", n)
	}
}
