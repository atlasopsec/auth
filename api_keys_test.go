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

	"github.com/atlasopsec/auth/internal/testdb"
	"github.com/atlasopsec/auth/internal/token"
	"github.com/atlasopsec/auth/mail/mailtest"
	"github.com/atlasopsec/auth/rbac"
)

// keyAppRoles are testAppRoles with a permission keys may not carry.
var keyAppRoles = rbac.Roles{
	"support": {"users:read", "users:ban", "users:delete"},
	"auditor": {"users:read"},
}

// keyPerms are the permissions keys may carry in setupKeys.
var keyPerms = []rbac.Permission{"users:read", "users:ban"}

// setupKeys returns an access fixture with API keys on for keyPerms, and
// GET /v1/users behind Require("users:read").
func setupKeys(t *testing.T) accessFixture {
	t.Helper()
	f := setupAccessWith(t, Config{
		AllowUnverifiedLogin: true,
		OrgRoles:             testOrgRoles,
		AppRoles:             keyAppRoles,
		APIKeyPermissions:    keyPerms,
		APIKeyPrefix:         "example",
	})
	f.mux.Handle("GET /v1/users", f.auth.Require("users:read", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, _ := UserFrom(r.Context())
		_, hasSession := SessionFrom(r.Context())
		k, hasKey := APIKeyFrom(r.Context())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user_id":     u.ID.String(),
			"has_session": hasSession,
			"has_key":     hasKey,
			"key_id":      k.ID.String(),
			"can_read":    Can(r.Context(), "users:read"),
			"can_ban":     Can(r.Context(), "users:ban"),
		})
	})))
	return f
}

// userWithRole signs up email and gives them the app role.
func (f accessFixture) userWithRole(t *testing.T, email, role string) loginJSON {
	t.Helper()
	u := f.signUp(t, email)
	if err := f.auth.SetAppRole(context.Background(), u.User.ID, role, Actor{}); err != nil {
		t.Fatal(err)
	}
	return u
}

func (f accessFixture) newKey(t *testing.T, userID uuid.UUID, perms ...rbac.Permission) (APIKey, string) {
	t.Helper()
	k, key, err := f.auth.CreateAPIKey(context.Background(), userID, NewAPIKey{Name: "Nightly sync", Permissions: perms}, Actor{})
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}
	return k, key
}

func TestNewChecksAPIKeyConfig(t *testing.T) {
	t.Parallel()
	pool := testdb.New(t)
	base := func() Config {
		return Config{DB: pool, Mailer: &mailtest.Recorder{}, AppURL: testAppURL, AppName: "Example", EncryptionKey: testEncryptionKey,
			AppRoles: testAppRoles, DisableCleanup: true}
	}
	bad := map[string]func(*Config){
		"no prefix": func(c *Config) { c.APIKeyPermissions = []rbac.Permission{"users:read"} },
		"bad prefix": func(c *Config) {
			c.APIKeyPermissions, c.APIKeyPrefix = []rbac.Permission{"users:read"}, "Example-Key"
		},
		"permission no app role has": func(c *Config) {
			c.APIKeyPermissions, c.APIKeyPrefix = []rbac.Permission{"invoices:read"}, "example"
		},
		"every permission": func(c *Config) {
			c.APIKeyPermissions, c.APIKeyPrefix = []rbac.Permission{rbac.All}, "example"
		},
		"prefix without permissions": func(c *Config) { c.APIKeyPrefix = "example" },
	}
	for name, change := range bad {
		cfg := base()
		change(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: New() error = nil", name)
		}
	}
	cfg := base()
	cfg.APIKeyPermissions, cfg.APIKeyPrefix = []rbac.Permission{"users:read"}, "example"
	if _, err := New(cfg); err != nil {
		t.Errorf("valid key config: New() error = %v", err)
	}
}

func TestCreateAPIKey(t *testing.T) {
	t.Parallel()
	f := setupKeys(t)
	ctx := context.Background()
	u := f.userWithRole(t, "support@example.com", "support")

	k, key, err := f.auth.CreateAPIKey(ctx, u.User.ID, NewAPIKey{
		Name:        "  Nightly sync  ",
		Permissions: []rbac.Permission{"users:read", "users:read"},
	}, Actor{UserID: &u.User.ID})
	if err != nil {
		t.Fatal(err)
	}
	secret, ok := strings.CutPrefix(key, "example_")
	if !ok || !token.Valid(secret) {
		t.Errorf("key %q isn't the prefix and a token", key)
	}
	if k.Name != "Nightly sync" || k.Hint != secret[:6] || k.UserID != u.User.ID || k.LastUsedAt != nil {
		t.Errorf("key = %+v", k)
	}
	if len(k.Permissions) != 1 || k.Permissions[0] != "users:read" {
		t.Errorf("permissions = %v, want [users:read] once", k.Permissions)
	}
	if want := f.clock.now().Add(DefaultAPIKeyLifetime); !k.ExpiresAt.Equal(want) {
		t.Errorf("expires %v, want %v", k.ExpiresAt, want)
	}

	// Only the hash is stored.
	var stored int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM auth.api_keys WHERE key_hash = $1`, token.Hash(key)).Scan(&stored); err != nil || stored != 1 {
		t.Errorf("rows with the key's hash = %d, err = %v; want 1", stored, err)
	}
	var leaked int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM auth.api_keys WHERE position($1 in name || hint || encode(key_hash, 'escape')) > 0`, secret).Scan(&leaked); err != nil || leaked != 0 {
		t.Errorf("rows containing the key = %d, err = %v; want 0", leaked, err)
	}

	listed, err := f.auth.ListAPIKeys(ctx, u.User.ID)
	if err != nil || len(listed) != 1 || listed[0].ID != k.ID {
		t.Errorf("ListAPIKeys() = %+v, %v; want the new key", listed, err)
	}
	events := f.eventsOf(t, u.User.ID)
	last := events[len(events)-1]
	if last.Type != EventAPIKeyCreated || last.Metadata["api_key_id"] != k.ID.String() || last.Metadata["permissions"] != "users:read" || *last.ActorID != u.User.ID {
		t.Errorf("last event = %+v", last)
	}
	if strings.Contains(f.logs.String(), secret) {
		t.Error("the key is in the logs")
	}
}

func TestCreateAPIKeyRefuses(t *testing.T) {
	t.Parallel()
	f := setupKeys(t)
	ctx := context.Background()
	support := f.userWithRole(t, "support@example.com", "support").User.ID
	auditor := f.userWithRole(t, "auditor@example.com", "auditor").User.ID
	nobody := f.signUp(t, "nobody@example.com").User.ID
	now := f.clock.now()
	read := []rbac.Permission{"users:read"}

	for name, tc := range map[string]struct {
		user uuid.UUID
		key  NewAPIKey
		want error
	}{
		"blank name":                {support, NewAPIKey{Name: "  ", Permissions: read}, ErrInvalidAPIKeyName},
		"long name":                 {support, NewAPIKey{Name: strings.Repeat("é", 101), Permissions: read}, ErrInvalidAPIKeyName},
		"no permissions":            {support, NewAPIKey{Name: "k"}, ErrAPIKeyPermission},
		"permission not for keys":   {support, NewAPIKey{Name: "k", Permissions: []rbac.Permission{"users:delete"}}, ErrAPIKeyPermission},
		"undeclared permission":     {support, NewAPIKey{Name: "k", Permissions: []rbac.Permission{"invoices:read"}}, ErrAPIKeyPermission},
		"permission the role lacks": {auditor, NewAPIKey{Name: "k", Permissions: []rbac.Permission{"users:ban"}}, ErrAPIKeyPermission},
		"no role":                   {nobody, NewAPIKey{Name: "k", Permissions: read}, ErrAPIKeyPermission},
		"expiry in the past":        {support, NewAPIKey{Name: "k", Permissions: read, ExpiresAt: now.Add(-time.Second)}, ErrAPIKeyExpiry},
		"expiry now":                {support, NewAPIKey{Name: "k", Permissions: read, ExpiresAt: now}, ErrAPIKeyExpiry},
		"expiry over a year away":   {support, NewAPIKey{Name: "k", Permissions: read, ExpiresAt: now.Add(MaxAPIKeyLifetime + time.Second)}, ErrAPIKeyExpiry},
		"unknown user":              {uuid.Must(uuid.NewV7()), NewAPIKey{Name: "k", Permissions: read}, ErrUserNotFound},
	} {
		if _, _, err := f.auth.CreateAPIKey(ctx, tc.user, tc.key, Actor{}); !errors.Is(err, tc.want) {
			t.Errorf("%s: error = %v, want %v", name, err, tc.want)
		}
	}

	// A year exactly is allowed, and so is the 10th key, but not the 11th.
	if _, _, err := f.auth.CreateAPIKey(ctx, support, NewAPIKey{Name: "k", Permissions: read, ExpiresAt: now.Add(MaxAPIKeyLifetime)}, Actor{}); err != nil {
		t.Fatalf("a year away: %v", err)
	}
	for range MaxAPIKeys - 1 {
		f.newKey(t, support, "users:read")
	}
	if _, _, err := f.auth.CreateAPIKey(ctx, support, NewAPIKey{Name: "k", Permissions: read}, Actor{}); !errors.Is(err, ErrTooManyAPIKeys) {
		t.Errorf("11th key: error = %v, want ErrTooManyAPIKeys", err)
	}

	off := setupAccess(t)
	u := off.userWithRole(t, testEmail, "support")
	if _, _, err := off.auth.CreateAPIKey(ctx, u.User.ID, NewAPIKey{Name: "k", Permissions: read}, Actor{}); !errors.Is(err, ErrAPIKeysOff) {
		t.Errorf("keys off: error = %v, want ErrAPIKeysOff", err)
	}
}

func TestAPIKeyUnderRequire(t *testing.T) {
	t.Parallel()
	f := setupKeys(t)
	u := f.userWithRole(t, "support@example.com", "support")
	k, key := f.newKey(t, u.User.ID, "users:read")

	res := f.do(t, http.MethodGet, "/v1/users", "", withToken(key))
	if res.status != http.StatusOK {
		t.Fatalf("status %d, body %s", res.status, res.body)
	}
	got := f.seen(t, res)
	want := map[string]any{"user_id": u.User.ID.String(), "has_session": false, "has_key": true, "key_id": k.ID.String(), "can_read": true,
		// The support role may ban, but this key may not.
		"can_ban": false}
	for field, w := range want {
		if got[field] != w {
			t.Errorf("%s = %v, want %v", field, got[field], w)
		}
	}
	// The owner's session still works the same, and isn't a key.
	if got := f.seen(t, f.do(t, http.MethodGet, "/v1/users", "", withToken(u.Token))); got["has_key"] != false || got["has_session"] != true {
		t.Errorf("with the session: %v", got)
	}
}

func TestAPIKeyRefused(t *testing.T) {
	t.Parallel()
	f := setupKeys(t)
	ctx := context.Background()
	u := f.userWithRole(t, "support@example.com", "support")
	_, readKey := f.newKey(t, u.User.ID, "users:read")
	get := func(tok string, path string) response {
		return f.do(t, http.MethodGet, path, "", withToken(tok), fromIP(nextTestIP()))
	}

	unknown := "example_" + token.New()
	for name, tc := range map[string]struct {
		tok, method, path string
		status            int
	}{
		"unknown key":           {unknown, http.MethodGet, "/v1/users", http.StatusUnauthorized},
		"malformed key":         {readKey + "x", http.MethodGet, "/v1/users", http.StatusUnauthorized},
		"key without prefix":    {strings.TrimPrefix(readKey, "example_"), http.MethodGet, "/v1/users", http.StatusUnauthorized},
		"permission not in key": {readKey, http.MethodPost, "/v1/users/" + uuid.NewString() + "/ban", http.StatusForbidden},
		"Authenticated route":   {readKey, http.MethodGet, "/v1/profile", http.StatusUnauthorized},
		"module endpoint":       {readKey, http.MethodGet, "/v1/users/me", http.StatusUnauthorized},
		"listing sessions":      {readKey, http.MethodGet, "/v1/sessions", http.StatusUnauthorized},
	} {
		res := f.do(t, tc.method, tc.path, "", withToken(tc.tok), fromIP(nextTestIP()))
		if res.status != tc.status {
			t.Errorf("%s: status %d, body %s; want %d", name, res.status, res.body, tc.status)
		}
	}
	if f.do(t, http.MethodDelete, "/v1/sessions", "", withToken(readKey)).status != http.StatusUnauthorized {
		t.Error("a key logged its owner out everywhere")
	}

	// A permission removed from the role, or the role taken away, goes from
	// the key at once.
	if err := f.auth.SetAppRole(ctx, u.User.ID, "", Actor{}); err != nil {
		t.Fatal(err)
	}
	if res := get(readKey, "/v1/users"); res.status != http.StatusForbidden || res.errorCode(t) != "forbidden" {
		t.Errorf("owner lost their role: status %d, body %s; want 403", res.status, res.body)
	}
	if err := f.auth.SetAppRole(ctx, u.User.ID, "support", Actor{}); err != nil {
		t.Fatal(err)
	}
	if res := get(readKey, "/v1/users"); res.status != http.StatusOK {
		t.Errorf("role given back: status %d, want 200", res.status)
	}

	// A user who must set up 2FA can't use a key until they have.
	if err := f.auth.SetTwoFactorRequired(ctx, u.User.ID, true, Actor{}); err != nil {
		t.Fatal(err)
	}
	if res := get(readKey, "/v1/users"); res.status != http.StatusForbidden || res.errorCode(t) != "two_factor_setup_required" {
		t.Errorf("2FA required: status %d, body %s; want 403 two_factor_setup_required", res.status, res.body)
	}
	if err := f.auth.SetTwoFactorRequired(ctx, u.User.ID, false, Actor{}); err != nil {
		t.Fatal(err)
	}

	// Expired, and revoked.
	k, soon := f.newKey(t, u.User.ID, "users:read")
	if _, err := f.pool.Exec(ctx, `UPDATE auth.api_keys SET expires_at = $1 WHERE id = $2`, f.clock.now().Add(time.Hour), k.ID); err != nil {
		t.Fatal(err)
	}
	f.clock.advance(time.Hour)
	if res := get(soon, "/v1/users"); res.status != http.StatusUnauthorized {
		t.Errorf("expired key: status %d, want 401", res.status)
	}
	k, revoked := f.newKey(t, u.User.ID, "users:read")
	if err := f.auth.RevokeAPIKey(ctx, u.User.ID, k.ID, Actor{}); err != nil {
		t.Fatal(err)
	}
	if res := get(revoked, "/v1/users"); res.status != http.StatusUnauthorized {
		t.Errorf("revoked key: status %d, want 401", res.status)
	}
	if err := f.auth.RevokeAPIKey(ctx, u.User.ID, k.ID, Actor{}); !errors.Is(err, ErrAPIKeyNotFound) {
		t.Errorf("revoking twice: error = %v, want ErrAPIKeyNotFound", err)
	}
	other := f.userWithRole(t, "other@example.com", "support")
	if err := f.auth.RevokeAPIKey(ctx, other.User.ID, k.ID, Actor{}); !errors.Is(err, ErrAPIKeyNotFound) {
		t.Errorf("revoking someone else's key: error = %v, want ErrAPIKeyNotFound", err)
	}
}

func TestNarrowerKeyConfigApplies(t *testing.T) {
	t.Parallel()
	f := setupKeys(t)
	u := f.userWithRole(t, testEmail, "support")
	_, key := f.newKey(t, u.User.ID, "users:read", "users:ban")

	// The same database and key, after the project changes what keys may
	// carry: with keys off, a key that exists is refused, as by a release
	// without keys; with users:ban no longer allowed, the key loses it.
	for name, tc := range map[string]struct {
		perms  []rbac.Permission
		prefix string
		status int
	}{
		"keys off":              {nil, "", http.StatusUnauthorized},
		"users:ban not allowed": {[]rbac.Permission{"users:read"}, "example", http.StatusForbidden},
		"unchanged":             {keyPerms, "example", http.StatusOK},
	} {
		a, err := New(Config{DB: f.pool, Mailer: &mailtest.Recorder{}, AppURL: testAppURL, AppName: "Example", EncryptionKey: testEncryptionKey,
			AppRoles: keyAppRoles, APIKeyPermissions: tc.perms, APIKeyPrefix: tc.prefix, DisableCleanup: true, Now: f.clock.now})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = a.Close(context.Background()) })
		mux := http.NewServeMux()
		mux.Handle("POST /v1/users/{id}/ban", a.Require("users:ban", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
		g := f
		g.mux = mux
		if res := g.do(t, http.MethodPost, "/v1/users/"+uuid.NewString()+"/ban", "", withToken(key), fromIP(nextTestIP())); res.status != tc.status {
			t.Errorf("%s: status %d, body %s; want %d", name, res.status, res.body, tc.status)
		}
	}
}

func TestWrongAPIKeysAreRateLimited(t *testing.T) {
	t.Parallel()
	f := setupKeys(t)
	u := f.userWithRole(t, testEmail, "support")
	_, key := f.newKey(t, u.User.ID, "users:read")
	ip := nextTestIP()

	for i := range limitLogin.Limit {
		if res := f.do(t, http.MethodGet, "/v1/users", "", withToken("example_"+token.New()), fromIP(ip)); res.status != http.StatusUnauthorized {
			t.Fatalf("wrong key %d: status %d, want 401", i+1, res.status)
		}
	}
	res := f.do(t, http.MethodGet, "/v1/users", "", withToken(key), fromIP(ip))
	if res.status != http.StatusTooManyRequests || res.header.Get("Retry-After") == "" {
		t.Errorf("after %d wrong keys, the right one: status %d, want 429 with Retry-After", limitLogin.Limit, res.status)
	}
	if res := f.do(t, http.MethodGet, "/v1/users", "", withToken(key), fromIP(nextTestIP())); res.status != http.StatusOK {
		t.Errorf("another address: status %d, want 200", res.status)
	}
	// Right keys don't count.
	other := nextTestIP()
	for range limitLogin.Limit + 1 {
		if res := f.do(t, http.MethodGet, "/v1/users", "", withToken(key), fromIP(other)); res.status != http.StatusOK {
			t.Fatalf("right key: status %d, want 200", res.status)
		}
	}
}

func TestAPIKeyLastUse(t *testing.T) {
	t.Parallel()
	f := setupKeys(t)
	ctx := context.Background()
	u := f.userWithRole(t, testEmail, "support")
	_, key := f.newKey(t, u.User.ID, "users:read")
	lastUsed := func() (time.Time, string) {
		t.Helper()
		keys, err := f.auth.ListAPIKeys(ctx, u.User.ID)
		if err != nil || len(keys) != 1 || keys[0].LastUsedAt == nil || keys[0].LastUsedIP == nil {
			t.Fatalf("ListAPIKeys() = %+v, %v; want one used key", keys, err)
		}
		return *keys[0].LastUsedAt, keys[0].LastUsedIP.String()
	}

	f.do(t, http.MethodGet, "/v1/users", "", withToken(key), fromIP("192.0.2.1"))
	first, ip := lastUsed()
	if !first.Equal(f.clock.now()) || ip != "192.0.2.1" {
		t.Errorf("last used %v from %s, want now from 192.0.2.1", first, ip)
	}
	f.clock.advance(30 * time.Second)
	f.do(t, http.MethodGet, "/v1/users", "", withToken(key), fromIP("192.0.2.2"))
	if again, ip := lastUsed(); !again.Equal(first) || ip != "192.0.2.1" {
		t.Errorf("within a minute: last used %v from %s; want unchanged", again, ip)
	}
	f.clock.advance(30 * time.Second)
	f.do(t, http.MethodGet, "/v1/users", "", withToken(key), fromIP("192.0.2.2"))
	if later, ip := lastUsed(); !later.Equal(f.clock.now()) || ip != "192.0.2.2" {
		t.Errorf("a minute later: last used %v from %s; want now from 192.0.2.2", later, ip)
	}
}

func TestAPIKeysEndWithTheAccount(t *testing.T) {
	t.Parallel()
	f := setupKeys(t)
	ctx := context.Background()
	works := func(key string) bool {
		return f.do(t, http.MethodGet, "/v1/users", "", withToken(key), fromIP(nextTestIP())).status == http.StatusOK
	}

	// Logging out everywhere.
	u := f.userWithRole(t, "a@example.com", "support")
	k, key := f.newKey(t, u.User.ID, "users:read")
	if res := f.do(t, http.MethodDelete, "/v1/sessions", "", withToken(u.Token)); res.status != http.StatusNoContent {
		t.Fatalf("log out everywhere: status %d, body %s", res.status, res.body)
	}
	if works(key) {
		t.Error("a key works after logging out everywhere")
	}
	events := f.eventsOf(t, u.User.ID)
	if last := events[len(events)-1]; last.Type != EventAPIKeyRevoked || last.Metadata["api_key_id"] != k.ID.String() {
		t.Errorf("last event = %+v, want the key revoked", last)
	}

	// EndSessions.
	u = f.userWithRole(t, "b@example.com", "support")
	_, key = f.newKey(t, u.User.ID, "users:read")
	if err := f.auth.EndSessions(ctx, u.User.ID, Actor{}); err != nil {
		t.Fatal(err)
	}
	if works(key) {
		t.Error("a key works after EndSessions")
	}

	// RevokeUserAPIKeys.
	u = f.userWithRole(t, "c@example.com", "support")
	_, key = f.newKey(t, u.User.ID, "users:read")
	_, key2 := f.newKey(t, u.User.ID, "users:read")
	if err := f.auth.RevokeUserAPIKeys(ctx, u.User.ID, Actor{}); err != nil {
		t.Fatal(err)
	}
	if works(key) || works(key2) {
		t.Error("a key works after RevokeUserAPIKeys")
	}

	// Deleting the user.
	u = f.userWithRole(t, "d@example.com", "support")
	_, key = f.newKey(t, u.User.ID, "users:read")
	if err := f.auth.DeleteUser(ctx, u.User.ID, Actor{}); err != nil {
		t.Fatal(err)
	}
	if works(key) {
		t.Error("a key works after its owner was deleted")
	}

	// Changing the password doesn't revoke keys.
	u = f.userWithRole(t, "e@example.com", "support")
	_, key = f.newKey(t, u.User.ID, "users:read")
	body := `{"current_password":"` + testPassword + `","new_password":"another long passphrase here"}`
	if res := f.do(t, http.MethodPost, "/v1/users/me/password", body, withToken(u.Token)); res.status != http.StatusNoContent && res.status != http.StatusOK {
		t.Fatalf("changing password: status %d, body %s", res.status, res.body)
	}
	if !works(key) {
		t.Error("a key stopped working after a password change")
	}
}

func TestCleanupDeletesExpiredAPIKeys(t *testing.T) {
	t.Parallel()
	f := setupKeys(t)
	ctx := context.Background()
	u := f.userWithRole(t, testEmail, "support")
	k, _ := f.newKey(t, u.User.ID, "users:read")
	if _, _, err := f.auth.CreateAPIKey(ctx, u.User.ID, NewAPIKey{Name: "long", Permissions: []rbac.Permission{"users:read"}, ExpiresAt: f.clock.now().Add(MaxAPIKeyLifetime)}, Actor{}); err != nil {
		t.Fatal(err)
	}
	f.clock.advance(DefaultAPIKeyLifetime)
	if err := f.auth.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	keys, err := f.auth.ListAPIKeys(ctx, u.User.ID)
	if err != nil || len(keys) != 1 || keys[0].ID == k.ID {
		t.Errorf("after cleanup: %+v, %v; want only the year-long key", keys, err)
	}
}
