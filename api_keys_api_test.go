package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/atlasopsec/auth/rbac"
)

type newKeyResponse struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Hint        string    `json:"hint"`
	Permissions []string  `json:"permissions"`
	CreatedAt   string    `json:"created_at"`
	ExpiresAt   string    `json:"expires_at"`
	LastUsedAt  *string   `json:"last_used_at"`
	LastUsedIP  *string   `json:"last_used_ip"`
	Key         string    `json:"key"`
}

func keyRequest(fields map[string]any) string {
	req := map[string]any{"name": "Nightly sync", "permissions": []string{"users:read"}, "current_password": testPassword}
	for k, v := range fields {
		req[k] = v
	}
	b, _ := json.Marshal(req)
	return string(b)
}

func (f accessFixture) postKey(t *testing.T, tok string, fields map[string]any) response {
	t.Helper()
	return f.do(t, http.MethodPost, "/v1/api-keys", keyRequest(fields), withToken(tok))
}

func TestAPIKeyEndpoints(t *testing.T) {
	t.Parallel()
	f := setupKeys(t)
	u := f.userWithRole(t, testEmail, "support")

	res := f.postKey(t, u.Token, nil)
	if res.status != http.StatusCreated {
		t.Fatalf("create: status %d, body %s", res.status, res.body)
	}
	var created newKeyResponse
	if err := json.Unmarshal(res.body, &created); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(created.Key, "example_") || created.Name != "Nightly sync" || created.Hint != created.Key[len("example_"):][:6] ||
		len(created.Permissions) != 1 || created.LastUsedAt != nil || created.ExpiresAt != f.clock.now().Add(DefaultAPIKeyLifetime).Format(time.RFC3339) {
		t.Errorf("created = %+v", created)
	}
	if res := f.do(t, http.MethodGet, "/v1/users", "", withToken(created.Key)); res.status != http.StatusOK {
		t.Errorf("using the new key: status %d", res.status)
	}

	// The owner is told, with the key's name but never the key.
	sent := f.sent()
	last := sent[len(sent)-1]
	if last.To != testEmail || !strings.Contains(last.Subject, "API key") || !strings.Contains(last.Text, "Nightly sync") || strings.Contains(last.Text, created.Key[len("example_"):]) {
		t.Errorf("email = %+v", last)
	}
	events := f.eventsOf(t, u.User.ID)
	if e := events[len(events)-1]; e.Type != EventAPIKeyCreated || e.ActorID == nil || *e.ActorID != u.User.ID || e.IP == nil {
		t.Errorf("last event = %+v, want api_key_created by the user, with their address", e)
	}

	// The list shows it, without the key.
	res = f.do(t, http.MethodGet, "/v1/api-keys", "", withToken(u.Token))
	if res.status != http.StatusOK || strings.Contains(string(res.body), created.Key[len("example_"):]) {
		t.Fatalf("list: status %d, body %s", res.status, res.body)
	}
	var list struct {
		Data       []newKeyResponse `json:"data"`
		NextCursor *string          `json:"next_cursor"`
	}
	if err := json.Unmarshal(res.body, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Data) != 1 || list.Data[0].ID != created.ID || list.Data[0].LastUsedAt == nil || list.Data[0].LastUsedIP == nil || list.NextCursor != nil {
		t.Errorf("list = %+v", list)
	}

	// Someone else can't see or revoke it.
	other := f.userWithRole(t, "other@example.com", "support")
	if res := f.do(t, http.MethodGet, "/v1/api-keys", "", withToken(other.Token)); !strings.Contains(string(res.body), `"data":[]`) {
		t.Errorf("another user's list: %s", res.body)
	}
	if res := f.do(t, http.MethodDelete, "/v1/api-keys/"+created.ID.String(), "", withToken(other.Token)); res.status != http.StatusNotFound {
		t.Errorf("another user revoking: status %d, want 404", res.status)
	}
	if res := f.do(t, http.MethodDelete, "/v1/api-keys/not-an-id", "", withToken(u.Token)); res.status != http.StatusNotFound {
		t.Errorf("bad ID: status %d, want 404", res.status)
	}

	// A key can't manage keys.
	if res := f.postKey(t, created.Key, nil); res.status != http.StatusUnauthorized {
		t.Errorf("creating a key with a key: status %d, want 401", res.status)
	}
	if res := f.do(t, http.MethodGet, "/v1/api-keys", "", withToken(created.Key)); res.status != http.StatusUnauthorized {
		t.Errorf("listing keys with a key: status %d, want 401", res.status)
	}
	if res := f.do(t, http.MethodDelete, "/v1/api-keys/"+created.ID.String(), "", withToken(created.Key)); res.status != http.StatusUnauthorized {
		t.Errorf("revoking with a key: status %d, want 401", res.status)
	}

	// Revoking.
	if res := f.do(t, http.MethodDelete, "/v1/api-keys/"+created.ID.String(), "", withToken(u.Token)); res.status != http.StatusNoContent {
		t.Fatalf("revoke: status %d, body %s", res.status, res.body)
	}
	if res := f.do(t, http.MethodGet, "/v1/users", "", withToken(created.Key)); res.status != http.StatusUnauthorized {
		t.Errorf("revoked key: status %d, want 401", res.status)
	}
	if res := f.do(t, http.MethodDelete, "/v1/api-keys/"+created.ID.String(), "", withToken(u.Token)); res.status != http.StatusNotFound {
		t.Errorf("revoking twice: status %d, want 404", res.status)
	}
}

func TestCreateAPIKeyEndpointRefuses(t *testing.T) {
	t.Parallel()
	f := setupKeys(t)
	support := f.userWithRole(t, "support@example.com", "support")
	auditor := f.userWithRole(t, "auditor@example.com", "auditor")
	now := f.clock.now()

	for name, tc := range map[string]struct {
		tok    string
		fields map[string]any
		field  string
	}{
		"no password":               {support.Token, map[string]any{"current_password": ""}, "current_password"},
		"wrong password":            {support.Token, map[string]any{"current_password": "not the password at all"}, "current_password"},
		"blank name":                {support.Token, map[string]any{"name": " "}, "name"},
		"no permissions":            {support.Token, map[string]any{"permissions": []string{}}, "permissions"},
		"permission not for keys":   {support.Token, map[string]any{"permissions": []string{"users:delete"}}, "permissions"},
		"permission the role lacks": {auditor.Token, map[string]any{"permissions": []string{"users:ban"}}, "permissions"},
		"expiry in the past":        {support.Token, map[string]any{"expires_at": now.Add(-time.Hour)}, "expires_at"},
		"expiry too far":            {support.Token, map[string]any{"expires_at": now.Add(MaxAPIKeyLifetime + time.Hour)}, "expires_at"},
	} {
		res := f.postKey(t, tc.tok, tc.fields)
		if res.status != http.StatusUnprocessableEntity {
			t.Errorf("%s: status %d, body %s; want 422", name, res.status, res.body)
			continue
		}
		var e errorJSON
		_ = json.Unmarshal(res.body, &e)
		if len(e.Error.Details) == 0 || e.Error.Details[0].Field != tc.field {
			t.Errorf("%s: details %+v, want %s first", name, e.Error.Details, tc.field)
		}
	}
	if res := f.do(t, http.MethodGet, "/v1/api-keys", "", withToken(support.Token)); !strings.Contains(string(res.body), `"data":[]`) {
		t.Errorf("refused requests made keys: %s", res.body)
	}

	// The 11th key.
	for range MaxAPIKeys {
		f.newKey(t, support.User.ID, "users:read")
	}
	if res := f.postKey(t, support.Token, nil); res.status != http.StatusConflict || res.errorCode(t) != "too_many_api_keys" {
		t.Errorf("11th key: status %d, body %s; want 409 too_many_api_keys", res.status, res.body)
	}

	// With keys off, there are no key endpoints.
	off := setupAccess(t)
	u := off.userWithRole(t, testEmail, "support")
	if res := off.postKey(t, u.Token, nil); res.status != http.StatusNotFound && res.status != http.StatusMethodNotAllowed {
		t.Errorf("keys off: status %d, want no such endpoint", res.status)
	}
}

func TestCreateAPIKeyNeedsTwoFactorCode(t *testing.T) {
	t.Parallel()
	f := setupKeys(t)
	u := f.userWithRole(t, testEmail, "support")
	secret, _ := f.enableTwoFactor(t, u.Token)

	for name, tc := range map[string]struct {
		code, want string
	}{
		"no code":    {"", "required"},
		"wrong code": {f.wrongCode(secret), "incorrect"},
	} {
		res := f.postKey(t, u.Token, map[string]any{"code": tc.code})
		var e errorJSON
		_ = json.Unmarshal(res.body, &e)
		if res.status != http.StatusUnprocessableEntity || len(e.Error.Details) != 1 || e.Error.Details[0].Field != "code" || e.Error.Details[0].Code != tc.want {
			t.Errorf("%s: status %d, body %s; want 422 code %s", name, res.status, res.body, tc.want)
		}
	}
	if res := f.postKey(t, u.Token, map[string]any{"code": f.code(secret)}); res.status != http.StatusCreated {
		t.Errorf("right code: status %d, body %s", res.status, res.body)
	}
}

func TestAPIKeyExpiryNotices(t *testing.T) {
	t.Parallel()
	f := setupKeys(t)
	ctx := context.Background()
	u := f.userWithRole(t, testEmail, "support")
	now := f.clock.now()
	create := func(name string, lifetime time.Duration) {
		t.Helper()
		if _, _, err := f.auth.CreateAPIKey(ctx, u.User.ID, NewAPIKey{Name: name, Permissions: []rbac.Permission{"users:read"}, ExpiresAt: now.Add(lifetime)}, Actor{}); err != nil {
			t.Fatal(err)
		}
	}
	create("Month key", 30*24*time.Hour)
	create("Week key", 7*24*time.Hour)
	create("Year key", MaxAPIKeyLifetime)
	notices := func() []string {
		t.Helper()
		var names []string
		for _, m := range f.sent() {
			if strings.Contains(m.Subject, "expires soon") {
				names = append(names, strings.SplitN(strings.SplitN(m.Text, "Name: ", 2)[1], "\n", 2)[0])
			}
		}
		return names
	}

	if err := f.auth.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if got := notices(); len(got) != 0 {
		t.Errorf("at once: notices for %v, want none (the week key was made that short)", got)
	}
	f.clock.advance(17 * 24 * time.Hour)
	for range 2 {
		if err := f.auth.Cleanup(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if got := notices(); len(got) != 1 || got[0] != "Month key" {
		t.Errorf("after 17 days: notices for %v, want the month key once", got)
	}
}
