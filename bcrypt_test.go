package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/atlasopsec/auth/internal/password"
	"github.com/atlasopsec/auth/mail/mailtest"
)

func (f fixture) storedHash(t *testing.T, userID uuid.UUID) string {
	t.Helper()
	var h *string
	if err := f.pool.QueryRow(context.Background(), `SELECT password_hash FROM auth.users WHERE id = $1`, userID).Scan(&h); err != nil {
		t.Fatal(err)
	}
	if h == nil {
		return ""
	}
	return *h
}

func TestBcryptHashes(t *testing.T) {
	t.Parallel()
	f := setupWith(t, Config{AllowBcryptHashes: true, BcryptCost: 4})
	ctx := context.Background()
	hash := bcryptHash(t, testPassword)
	u, err := f.auth.CreateUser(ctx, NewUser{Email: testEmail, PasswordHash: hash}, Actor{})
	if err != nil {
		t.Fatalf("CreateUser() with a bcrypt hash: %v", err)
	}

	// A wrong password fails, and leaves the hash alone.
	res := f.do(t, http.MethodPost, "/v1/sessions", credentials(testEmail, "not the password", "web"))
	if res.status != http.StatusUnauthorized || res.errorCode(t) != "invalid_credentials" {
		t.Fatalf("wrong password: status %d, body %s", res.status, res.body)
	}
	if got := f.storedHash(t, u.ID); got != hash {
		t.Error("hash changed after a wrong password")
	}

	// The right one logs in, and the hash becomes argon2id.
	l := f.logIn(t, testEmail)
	got := f.storedHash(t, u.ID)
	if !strings.HasPrefix(got, "$argon2id$") {
		t.Fatalf("hash after login starts %.10q, want argon2id", got)
	}
	if needs, err := password.NeedsRehash(got, password.DefaultParams); err != nil || needs {
		t.Errorf("new hash NeedsRehash = %v, %v; want the module's settings", needs, err)
	}
	f.logIn(t, testEmail)

	// Endpoints that ask for the current password take it too.
	other := "another long password"
	newHash := bcryptHash(t, other)
	if _, err := f.auth.UpdateUser(ctx, u.ID, UserChanges{PasswordHash: &newHash}, Actor{}); err != nil {
		t.Fatal(err)
	}
	l = f.logInWith(t, testEmail, other)
	body := `{"current_password":"` + other + `","new_password":"a third long password"}`
	if res := f.do(t, http.MethodPost, "/v1/users/me/password", body, withToken(l.Token)); res.status != http.StatusNoContent {
		t.Errorf("password change with a bcrypt current password: status %d, body %s", res.status, res.body)
	}
}

func (f fixture) logInWith(t *testing.T, email, pw string) loginJSON {
	t.Helper()
	res := f.do(t, http.MethodPost, "/v1/sessions", credentials(email, pw, "web"))
	if res.status != http.StatusCreated {
		t.Fatalf("log in: status %d, body %s", res.status, res.body)
	}
	var l loginJSON
	if err := json.Unmarshal(res.body, &l); err != nil {
		t.Fatal(err)
	}
	return l
}

func TestBcryptPHPPrefix(t *testing.T) {
	t.Parallel()
	f := setupWith(t, Config{AllowBcryptHashes: true, BcryptCost: 4})
	h := bcryptHash(t, testPassword)
	if _, err := f.auth.CreateUser(context.Background(), NewUser{Email: testEmail, PasswordHash: "$2y$" + h[4:]}, Actor{}); err != nil {
		t.Fatal(err)
	}
	f.logIn(t, testEmail)
}

func TestBcryptHashesOffByDefault(t *testing.T) {
	t.Parallel()
	f := setupWith(t, Config{})
	ctx := context.Background()
	if _, err := f.auth.CreateUser(ctx, NewUser{Email: testEmail, PasswordHash: bcryptHash(t, testPassword)}, Actor{}); err == nil {
		t.Fatal("CreateUser() accepted a bcrypt hash with AllowBcryptHashes off")
	}
	// A hash left from when the setting was on is a wrong password, not
	// an error, and is logged.
	u, err := f.auth.CreateUser(ctx, NewUser{Email: testEmail}, Actor{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE auth.users SET password_hash = $1 WHERE id = $2`, bcryptHash(t, testPassword), u.ID); err != nil {
		t.Fatal(err)
	}
	res := f.do(t, http.MethodPost, "/v1/sessions", credentials(testEmail, testPassword, "web"))
	if res.status != http.StatusUnauthorized || res.errorCode(t) != "invalid_credentials" {
		t.Errorf("login: status %d, body %s", res.status, res.body)
	}
	if !strings.Contains(f.logs.String(), "AllowBcryptHashes is off") {
		t.Error("no warning logged")
	}
}

func TestBcryptHashRejects(t *testing.T) {
	t.Parallel()
	f := setupWith(t, Config{AllowBcryptHashes: true, BcryptCost: 4})
	h := bcryptHash(t, testPassword)
	for name, bad := range map[string]string{
		"cost too high": h[:4] + "16" + h[6:],
		"truncated":     h[:50],
	} {
		if _, err := f.auth.CreateUser(context.Background(), NewUser{Email: testEmail, PasswordHash: bad}, Actor{}); err == nil {
			t.Errorf("%s: CreateUser() accepted it", name)
		}
	}
}

func TestBcryptConfig(t *testing.T) {
	t.Parallel()
	pool := setupWith(t, Config{}).pool
	base := Config{DB: pool, Mailer: &mailtest.Recorder{}, AppURL: testAppURL, AppName: "Example", EncryptionKey: testEncryptionKey, DisableCleanup: true}
	for name, mod := range map[string]func(*Config){
		"cost without allow": func(c *Config) { c.BcryptCost = 10 },
		"cost too low":       func(c *Config) { c.AllowBcryptHashes, c.BcryptCost = true, 3 },
		"cost too high":      func(c *Config) { c.AllowBcryptHashes, c.BcryptCost = true, 16 },
	} {
		cfg := base
		mod(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: New() = nil error", name)
		}
	}
	cfg := base
	cfg.AllowBcryptHashes = true
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close(context.Background()) })
	if got := a.bcryptDummy.Cost(); got != 10 {
		t.Errorf("default dummy cost %d, want 10", got)
	}
}

// TestRehashKeepsChangesMadeMeanwhile covers a login that checks the old
// hash while UpdateUser sets a new one: the upgrade mustn't put the old
// password back.
func TestRehashKeepsChangesMadeMeanwhile(t *testing.T) {
	t.Parallel()
	f := setupWith(t, Config{AllowBcryptHashes: true, BcryptCost: 4})
	ctx := context.Background()
	u, err := f.auth.CreateUser(ctx, NewUser{Email: testEmail, PasswordHash: bcryptHash(t, testPassword)}, Actor{})
	if err != nil {
		t.Fatal(err)
	}
	stale, err := f.auth.q.GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	newHash := testHash(t, "the new long password")
	if _, err := f.auth.UpdateUser(ctx, u.ID, UserChanges{PasswordHash: &newHash}, Actor{}); err != nil {
		t.Fatal(err)
	}
	r, _ := http.NewRequestWithContext(ctx, http.MethodPost, "/v1/sessions", nil)
	f.auth.rehashIfNeeded(r, stale, testPassword)
	if got := f.storedHash(t, u.ID); got != newHash {
		t.Error("the upgrade at login replaced a hash changed meanwhile")
	}
}
