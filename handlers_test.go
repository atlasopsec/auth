package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/atlasopsec/auth/internal/password"
	"github.com/atlasopsec/auth/internal/testdb"
	"github.com/atlasopsec/auth/internal/token"
	"github.com/atlasopsec/auth/mail"
	"github.com/atlasopsec/auth/mail/mailtest"
)

const (
	testEmail    = "ada@example.com"
	testPassword = "correct horse battery staple"
	day          = 24 * time.Hour
)

// clock is a fake time source tests move forward explicitly.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// syncBuffer collects log output from concurrent handlers.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type fixture struct {
	pool   *pgxpool.Pool
	clock  *clock
	auth   *Auth
	mux    *http.ServeMux
	logs   *syncBuffer
	mail   *mailtest.Recorder
	breach *fakeBreach
}

// proxyAddr is the test Next.js server, trusted to forward client details.
const proxyAddr = "10.0.0.5:4000"

// setup returns a fixture in the step 3 behavior, where sign-up logs the
// user in immediately (AllowUnverifiedLogin).
func setup(t *testing.T, hooks Hooks) fixture {
	t.Helper()
	return setupWith(t, Config{Hooks: hooks, AllowUnverifiedLogin: true})
}

// setupWith returns a fixture using cfg, with the database, clock, logger,
// mailer, and app details filled in.
func setupWith(t *testing.T, cfg Config) fixture {
	t.Helper()
	pool := testdb.NewMigrated(t)
	c := &clock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	logs := &syncBuffer{}
	rec := &mailtest.Recorder{}
	cfg.DB = pool
	cfg.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	cfg.Logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg.Now = c.now
	cfg.Mailer = rec
	cfg.AppURL = testAppURL
	cfg.AppName = "Example"
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	// Never call the real Have I Been Pwned API from tests.
	breach := &fakeBreach{}
	if a.breach != nil {
		a.breach = breach
	}
	t.Cleanup(func() {
		if err := a.Close(context.Background()); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	mux := http.NewServeMux()
	a.Register(mux)
	// A project's own protected route.
	mux.Handle("GET /v1/things", a.Authenticated(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := UserFrom(r.Context())
		s, sok := SessionFrom(r.Context())
		if !ok || !sok {
			http.Error(w, "no user in context", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"user_id": u.ID.String(), "session_id": s.ID.String()})
	})))
	return fixture{pool: pool, clock: c, auth: a, mux: mux, logs: logs, mail: rec, breach: breach}
}

// fakeBreach is a breach checker that reports the passwords in breached,
// or fails with err.
type fakeBreach struct {
	mu       sync.Mutex
	breached map[string]bool
	err      error
}

func (f *fakeBreach) Breached(_ context.Context, pw string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.breached[pw], f.err
}

func (f *fakeBreach) set(breached map[string]bool, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.breached, f.err = breached, err
}

const testAppURL = "https://app.example.com"

// sent waits for emails being sent in the background, then returns every
// email sent so far.
func (f fixture) sent() []mail.Message {
	f.auth.sender.Wait()
	return f.mail.Messages()
}

type response struct {
	status int
	header http.Header
	body   []byte
}

type errorJSON struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
		Details   []struct {
			Field string `json:"field"`
			Code  string `json:"code"`
		} `json:"details"`
	} `json:"error"`
}

func (r response) errorCode(t *testing.T) string {
	t.Helper()
	var e errorJSON
	if err := json.Unmarshal(r.body, &e); err != nil {
		t.Fatalf("decoding error body %s: %v", r.body, err)
	}
	return e.Error.Code
}

type reqOpt func(*http.Request)

func withHeader(k, v string) reqOpt { return func(r *http.Request) { r.Header.Set(k, v) } }
func withToken(tok string) reqOpt   { return withHeader("Authorization", "Bearer "+tok) }

func (f fixture) do(t *testing.T, method, path, body string, opts ...reqOpt) response {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequestWithContext(t.Context(), method, path, rd)
	r.RemoteAddr = "203.0.113.50:5000"
	for _, o := range opts {
		o(r)
	}
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	return response{status: w.Code, header: w.Header(), body: w.Body.Bytes()}
}

func credentials(email, pw, client string) string {
	b, _ := json.Marshal(map[string]string{"email": email, "password": pw, "client": client})
	return string(b)
}

type loginJSON struct {
	User struct {
		ID            uuid.UUID `json:"id"`
		Email         string    `json:"email"`
		EmailVerified bool      `json:"email_verified"`
		CreatedAt     string    `json:"created_at"`
	} `json:"user"`
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

func (f fixture) signUp(t *testing.T, email string) loginJSON {
	t.Helper()
	res := f.do(t, http.MethodPost, "/v1/users", credentials(email, testPassword, "web"))
	if res.status != http.StatusCreated {
		t.Fatalf("sign up: status %d, body %s", res.status, res.body)
	}
	var l loginJSON
	if err := json.Unmarshal(res.body, &l); err != nil {
		t.Fatal(err)
	}
	return l
}

func (f fixture) logIn(t *testing.T, email string) loginJSON {
	t.Helper()
	res := f.do(t, http.MethodPost, "/v1/sessions", credentials(email, testPassword, "mobile"))
	if res.status != http.StatusCreated {
		t.Fatalf("log in: status %d, body %s", res.status, res.body)
	}
	var l loginJSON
	if err := json.Unmarshal(res.body, &l); err != nil {
		t.Fatal(err)
	}
	return l
}

func (f fixture) userCount(t *testing.T) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM auth.users`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestNew(t *testing.T) {
	t.Parallel()
	pool := testdb.New(t)
	// valid has only the required fields.
	valid := func() Config {
		return Config{DB: pool, Mailer: &mailtest.Recorder{}, AppURL: "https://app.example.com", AppName: "Example"}
	}
	if _, err := New(valid()); err != nil {
		t.Fatalf("New() with the required fields: error = %v", err)
	}

	tests := []struct {
		name   string
		change func(*Config)
	}{
		{"no DB", func(c *Config) { c.DB = nil }},
		{"invalid trusted proxy", func(c *Config) { c.TrustedProxies = []netip.Prefix{{}} }},
		{"no mailer", func(c *Config) { c.Mailer = nil }},
		{"no app name", func(c *Config) { c.AppName = " " }},
		{"no app URL", func(c *Config) { c.AppURL = "" }},
		{"relative app URL", func(c *Config) { c.AppURL = "/app" }},
		{"http app URL", func(c *Config) { c.AppURL = "http://app.example.com" }},
		{"other scheme", func(c *Config) { c.AppURL = "ftp://app.example.com" }},
		{"app URL with query", func(c *Config) { c.AppURL = "https://app.example.com/?x=1" }},
		{"app URL with fragment", func(c *Config) { c.AppURL = "https://app.example.com/#x" }},
		{"app URL with user info", func(c *Config) { c.AppURL = "https://user:pw@app.example.com" }},
	}
	for _, tt := range tests {
		cfg := valid()
		tt.change(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("New() with %s: error = nil, want an error", tt.name)
		}
	}

	for _, u := range []string{"http://localhost:3000", "http://127.0.0.1:3000/", "https://example.com/app/"} {
		cfg := valid()
		cfg.AppURL = u
		if _, err := New(cfg); err != nil {
			t.Errorf("New() with app URL %q: error = %v", u, err)
		}
	}
}

func TestSignUp(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})

	res := f.do(t, http.MethodPost, "/v1/users", credentials("  Ada@Example.com ", testPassword, "web"),
		func(r *http.Request) { r.RemoteAddr = proxyAddr },
		withHeader("X-Forwarded-For", "198.51.100.23"),
		withHeader("X-Forwarded-User-Agent", "Browser/1.0"),
		withHeader("User-Agent", "node"))
	if res.status != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", res.status, res.body)
	}
	var got loginJSON
	if err := json.Unmarshal(res.body, &got); err != nil {
		t.Fatal(err)
	}
	if got.User.Email != "Ada@Example.com" || got.User.EmailVerified || got.User.CreatedAt != "2026-01-01T12:00:00Z" {
		t.Errorf("user = %+v, want the trimmed email, unverified, created now", got.User)
	}
	if !token.Valid(got.Token) {
		t.Errorf("token %q isn't a valid token", got.Token)
	}
	if got.ExpiresAt != "2026-01-31T12:00:00Z" {
		t.Errorf("expires_at = %s, want 30 days from now", got.ExpiresAt)
	}

	var hash string
	if err := f.pool.QueryRow(context.Background(),
		`SELECT password_hash FROM auth.users WHERE id = $1`, got.User.ID).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if ok, err := password.Verify(testPassword, hash); err != nil || !ok {
		t.Errorf("stored hash doesn't verify the password: ok = %v, err = %v", ok, err)
	}

	var ip, ua, client string
	if err := f.pool.QueryRow(context.Background(),
		`SELECT host(ip), user_agent, client FROM auth.sessions WHERE user_id = $1`, got.User.ID).Scan(&ip, &ua, &client); err != nil {
		t.Fatal(err)
	}
	if ip != "198.51.100.23" || ua != "Browser/1.0" || client != "web" {
		t.Errorf("session (ip, user_agent, client) = (%s, %s, %s), want the forwarded client's details", ip, ua, client)
	}

	// The token works straight away.
	if res := f.do(t, http.MethodGet, "/v1/users/me", "", withToken(got.Token)); res.status != http.StatusOK {
		t.Errorf("GET /v1/users/me with the new token: status %d", res.status)
	}
}

func TestSignUpValidation(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})

	type field struct{ Field, Code string }
	tests := []struct {
		name              string
		email, pw, client string
		want              []field
	}{
		{"missing everything", "", "", "", []field{{"email", "required"}, {"password", "required"}, {"client", "required"}}},
		{"blank email", "   ", testPassword, "web", []field{{"email", "required"}}},
		{"no at sign", "ada.example.com", testPassword, "web", []field{{"email", "invalid_format"}}},
		{"no domain dot", "ada@localhost", testPassword, "web", []field{{"email", "invalid_format"}}},
		{"display name", "Ada <ada@example.com>", testPassword, "web", []field{{"email", "invalid_format"}}},
		{"two addresses", "a@example.com, b@example.com", testPassword, "web", []field{{"email", "invalid_format"}}},
		{"too long email", strings.Repeat("a", 243) + "@example.com", testPassword, "web", []field{{"email", "too_long"}}},
		{"short password", testEmail, "elevenchars", "web", []field{{"password", "too_short"}}},
		{"long password", testEmail, strings.Repeat("a", password.MaxLength+1), "web", []field{{"password", "too_long"}}},
		{"unknown client", testEmail, testPassword, "desktop", []field{{"client", "invalid_value"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			res := f.do(t, http.MethodPost, "/v1/users", credentials(tt.email, tt.pw, tt.client))
			if res.status != http.StatusUnprocessableEntity || res.errorCode(t) != "validation_failed" {
				t.Fatalf("status = %d, body %s; want 422 validation_failed", res.status, res.body)
			}
			var e errorJSON
			_ = json.Unmarshal(res.body, &e)
			var got []field
			for _, d := range e.Error.Details {
				got = append(got, field{d.Field, d.Code})
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("details (-want +got):\n%s", diff)
			}
		})
	}
	if n := f.userCount(t); n != 0 {
		t.Errorf("%d users created by invalid sign-ups, want 0", n)
	}
}

func TestSignUpAcceptsMaxLengthEmail(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	email := strings.Repeat("a", 242) + "@example.com" // 254 characters
	f.signUp(t, email)
}

func TestSignUpEmailTaken(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	f.signUp(t, testEmail)

	res := f.do(t, http.MethodPost, "/v1/users", credentials("ADA@example.COM", testPassword, "web"))
	if res.status != http.StatusConflict || res.errorCode(t) != "email_taken" {
		t.Fatalf("status = %d, body %s; want 409 email_taken", res.status, res.body)
	}
	if n := f.userCount(t); n != 1 {
		t.Errorf("%d users, want 1", n)
	}
}

func TestMalformedRequests(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	tests := []struct {
		name       string
		path       string
		body       string
		wantStatus int
		wantCode   string
	}{
		{"misspelled field", "/v1/users", `{"email":"ada@example.com","pasword":"correct horse battery staple","client":"web"}`, http.StatusBadRequest, "bad_request"},
		{"malformed JSON", "/v1/users", `{"email":`, http.StatusBadRequest, "bad_request"},
		{"wrong type", "/v1/sessions", `{"email":1}`, http.StatusBadRequest, "bad_request"},
		{"empty body", "/v1/sessions", ``, http.StatusBadRequest, "bad_request"},
		{"too large", "/v1/sessions", `{"email":"` + strings.Repeat("a", 70<<10) + `"}`, http.StatusRequestEntityTooLarge, "payload_too_large"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			res := f.do(t, http.MethodPost, tt.path, tt.body)
			if res.status != tt.wantStatus || res.errorCode(t) != tt.wantCode {
				t.Errorf("status = %d, body %s; want %d %s", res.status, res.body, tt.wantStatus, tt.wantCode)
			}
		})
	}
}

func TestOnUserCreated(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var fail bool
	var seen []User
	f := setup(t, Hooks{OnUserCreated: func(ctx context.Context, tx pgx.Tx, u User) error {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, u)
		if _, err := tx.Exec(ctx, `INSERT INTO public.profiles (user_id) VALUES ($1)`, u.ID); err != nil {
			return err
		}
		if fail {
			return errors.New("profile service unavailable")
		}
		return nil
	}})
	if _, err := f.pool.Exec(context.Background(), `CREATE TABLE public.profiles (user_id uuid PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	profiles := func() int {
		var n int
		if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM public.profiles`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	created := f.signUp(t, testEmail)
	if len(seen) != 1 || seen[0].ID != created.User.ID || seen[0].Email != testEmail {
		t.Errorf("hook saw %+v, want the new user", seen)
	}
	if profiles() != 1 {
		t.Errorf("hook's row wasn't committed with the user")
	}

	// A failing hook cancels the whole sign-up, including its own writes.
	mu.Lock()
	fail = true
	mu.Unlock()
	res := f.do(t, http.MethodPost, "/v1/users", credentials("grace@example.com", testPassword, "web"))
	if res.status != http.StatusInternalServerError || res.errorCode(t) != "internal_error" {
		t.Fatalf("status = %d, body %s; want 500 internal_error", res.status, res.body)
	}
	if strings.Contains(string(res.body), "profile service") {
		t.Errorf("response leaks the internal error: %s", res.body)
	}
	if n := f.userCount(t); n != 1 {
		t.Errorf("%d users after a failed hook, want 1", n)
	}
	if profiles() != 1 {
		t.Errorf("failed hook's row was committed")
	}
	var sessions int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM auth.sessions`).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != 1 {
		t.Errorf("%d sessions after a failed hook, want 1", sessions)
	}
}

func TestLogIn(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	created := f.signUp(t, testEmail)

	res := f.do(t, http.MethodPost, "/v1/sessions", credentials(" ADA@example.com", testPassword, "mobile"),
		withHeader("User-Agent", "ExampleApp/2.0"), withHeader("X-Forwarded-User-Agent", "Spoofed/1.0"))
	if res.status != http.StatusCreated {
		t.Fatalf("status = %d, body %s; want 201", res.status, res.body)
	}
	var got loginJSON
	if err := json.Unmarshal(res.body, &got); err != nil {
		t.Fatal(err)
	}
	if got.User.ID != created.User.ID || !token.Valid(got.Token) || got.Token == created.Token {
		t.Errorf("login = %+v, want the same user with a new token", got)
	}

	var ip, ua, client string
	if err := f.pool.QueryRow(context.Background(),
		`SELECT host(ip), user_agent, client FROM auth.sessions WHERE token_hash = $1`, token.Hash(got.Token)).Scan(&ip, &ua, &client); err != nil {
		t.Fatal(err)
	}
	// Not from a trusted proxy, so forwarded headers are ignored.
	if ip != "203.0.113.50" || ua != "ExampleApp/2.0" || client != "mobile" {
		t.Errorf("session (ip, user_agent, client) = (%s, %s, %s), want the direct client's details", ip, ua, client)
	}
}

func TestLogInFailuresLookAlike(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	f.signUp(t, testEmail)
	// An account that only signs in with OAuth has no password.
	if _, err := f.pool.Exec(context.Background(),
		`INSERT INTO auth.users (id, email) VALUES ($1, 'oauth@example.com')`, uuid.Must(uuid.NewV7())); err != nil {
		t.Fatal(err)
	}

	tests := []struct{ name, email, pw string }{
		{"unknown email", "nobody@example.com", testPassword},
		{"wrong password", testEmail, testPassword + "!"},
		{"password differing only in case", testEmail, strings.ToUpper(testPassword)},
		{"OAuth-only account", "oauth@example.com", testPassword},
		{"OAuth-only account, empty-looking password", "oauth@example.com", " "},
	}
	var bodies []string
	for _, tt := range tests {
		res := f.do(t, http.MethodPost, "/v1/sessions", credentials(tt.email, tt.pw, "web"), withHeader("X-Request-ID", "fixed"))
		if res.status != http.StatusUnauthorized || res.errorCode(t) != "invalid_credentials" {
			t.Errorf("%s: status = %d, body %s; want 401 invalid_credentials", tt.name, res.status, res.body)
		}
		bodies = append(bodies, string(res.body))
	}
	for i, b := range bodies[1:] {
		if b != bodies[0] {
			t.Errorf("%s response differs from %s:\n%s\n%s", tests[i+1].name, tests[0].name, b, bodies[0])
		}
	}
}

func TestLogInValidation(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	res := f.do(t, http.MethodPost, "/v1/sessions", credentials(" ", "", "tablet"))
	if res.status != http.StatusUnprocessableEntity || res.errorCode(t) != "validation_failed" {
		t.Fatalf("status = %d, body %s; want 422 validation_failed", res.status, res.body)
	}
	var e errorJSON
	_ = json.Unmarshal(res.body, &e)
	var fields []string
	for _, d := range e.Error.Details {
		fields = append(fields, d.Field+":"+d.Code)
	}
	if diff := cmp.Diff([]string{"email:required", "password:required", "client:invalid_value"}, fields); diff != "" {
		t.Errorf("details (-want +got):\n%s", diff)
	}
}

func TestLogInUpgradesOldHash(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	created := f.signUp(t, testEmail)

	weak := password.DefaultParams
	weak.Memory = 8 * 1024
	old, err := password.Hash(testPassword, weak)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(context.Background(), `UPDATE auth.users SET password_hash = $1 WHERE id = $2`, old, created.User.ID); err != nil {
		t.Fatal(err)
	}

	f.logIn(t, testEmail)

	var hash string
	if err := f.pool.QueryRow(context.Background(), `SELECT password_hash FROM auth.users WHERE id = $1`, created.User.ID).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if needs, err := password.NeedsRehash(hash, password.DefaultParams); err != nil || needs {
		t.Errorf("hash after login = %s, want it upgraded to the default parameters", hash)
	}
	if ok, err := password.Verify(testPassword, hash); err != nil || !ok {
		t.Errorf("upgraded hash doesn't verify the password: ok = %v, err = %v", ok, err)
	}
}

func TestAuthenticatedRejects(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)
	revoked := f.logIn(t, testEmail)
	if res := f.do(t, http.MethodDelete, "/v1/sessions/current", "", withToken(revoked.Token)); res.status != http.StatusNoContent {
		t.Fatalf("logging out: status %d", res.status)
	}

	tests := []struct {
		name string
		auth string
	}{
		{"no header", ""},
		{"wrong scheme", "Basic " + l.Token},
		{"no token", "Bearer "},
		{"token without scheme", l.Token},
		{"malformed token", "Bearer not-a-token"},
		{"unknown token", "Bearer " + token.New()},
		{"revoked token", "Bearer " + revoked.Token},
	}
	for _, path := range []string{"/v1/users/me", "/v1/things", "/v1/sessions"} {
		for _, tt := range tests {
			var opts []reqOpt
			if tt.auth != "" {
				opts = append(opts, withHeader("Authorization", tt.auth))
			}
			res := f.do(t, http.MethodGet, path, "", opts...)
			if res.status != http.StatusUnauthorized || res.errorCode(t) != "unauthenticated" {
				t.Errorf("%s, %s: status = %d, body %s; want 401 unauthenticated", path, tt.name, res.status, res.body)
			}
			if got := res.header.Get("WWW-Authenticate"); got != "Bearer" {
				t.Errorf("%s, %s: WWW-Authenticate = %q, want Bearer", path, tt.name, got)
			}
		}
	}

	// The scheme is case-insensitive.
	if res := f.do(t, http.MethodGet, "/v1/things", "", withHeader("Authorization", "bearer "+l.Token)); res.status != http.StatusOK {
		t.Errorf("lowercase bearer: status %d, want 200", res.status)
	}
}

func TestAuthenticatedExpiry(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)

	f.clock.advance(30*day - time.Second)
	if res := f.do(t, http.MethodGet, "/v1/things", "", withToken(l.Token)); res.status != http.StatusOK {
		t.Fatalf("just before idle expiry: status %d, want 200", res.status)
	}
	// That use extended the session; leaving it unused for 30 days ends it.
	f.clock.advance(30 * day)
	if res := f.do(t, http.MethodGet, "/v1/things", "", withToken(l.Token)); res.status != http.StatusUnauthorized {
		t.Errorf("after idle expiry: status %d, want 401", res.status)
	}
}

func TestAuthenticatedProvidesUser(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)

	res := f.do(t, http.MethodGet, "/v1/things", "", withToken(l.Token))
	if res.status != http.StatusOK {
		t.Fatalf("status %d, body %s", res.status, res.body)
	}
	var got map[string]string
	if err := json.Unmarshal(res.body, &got); err != nil {
		t.Fatal(err)
	}
	var sessionID uuid.UUID
	if err := f.pool.QueryRow(context.Background(), `SELECT id FROM auth.sessions WHERE token_hash = $1`, token.Hash(l.Token)).Scan(&sessionID); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"user_id": l.User.ID.String(), "session_id": sessionID.String()}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("context (-want +got):\n%s", diff)
	}
}

func TestUserFromOutsideAuthenticated(t *testing.T) {
	t.Parallel()
	if _, ok := UserFrom(context.Background()); ok {
		t.Error("UserFrom() ok = true outside Authenticated")
	}
	if _, ok := SessionFrom(context.Background()); ok {
		t.Error("SessionFrom() ok = true outside Authenticated")
	}
}

func TestMe(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	l := f.signUp(t, testEmail)

	res := f.do(t, http.MethodGet, "/v1/users/me", "", withToken(l.Token))
	if res.status != http.StatusOK {
		t.Fatalf("status %d", res.status)
	}
	want := `{"id":"` + l.User.ID.String() + `","email":"ada@example.com","email_verified":false,"created_at":"2026-01-01T12:00:00Z"}` + "\n"
	if diff := cmp.Diff(want, string(res.body)); diff != "" {
		t.Errorf("body (-want +got):\n%s", diff)
	}
}

type sessionListJSON struct {
	Data []struct {
		ID         uuid.UUID `json:"id"`
		Client     string    `json:"client"`
		IP         *string   `json:"ip"`
		UserAgent  *string   `json:"user_agent"`
		LastUsedAt string    `json:"last_used_at"`
		ExpiresAt  string    `json:"expires_at"`
		CreatedAt  string    `json:"created_at"`
		IsCurrent  bool      `json:"is_current"`
	} `json:"data"`
	NextCursor *string `json:"next_cursor"`
}

func (f fixture) listSessions(t *testing.T, tok string) sessionListJSON {
	t.Helper()
	res := f.do(t, http.MethodGet, "/v1/sessions", "", withToken(tok))
	if res.status != http.StatusOK {
		t.Fatalf("listing sessions: status %d, body %s", res.status, res.body)
	}
	var l sessionListJSON
	if err := json.Unmarshal(res.body, &l); err != nil {
		t.Fatal(err)
	}
	return l
}

func TestListSessions(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	web := f.signUp(t, testEmail)
	f.clock.advance(time.Hour)
	mobile := f.logIn(t, testEmail)
	f.signUp(t, "grace@example.com") // someone else's session

	res := f.do(t, http.MethodGet, "/v1/sessions", "", withToken(web.Token))
	if !strings.Contains(string(res.body), `"next_cursor":null`) || !strings.Contains(string(res.body), `"user_agent":null`) {
		t.Errorf("body %s: want next_cursor and empty user_agent present as null", res.body)
	}

	l := f.listSessions(t, web.Token)
	if len(l.Data) != 2 {
		t.Fatalf("got %d sessions, want 2: %+v", len(l.Data), l.Data)
	}
	// Most recently used first.
	if l.Data[0].Client != "mobile" || l.Data[0].IsCurrent || l.Data[1].Client != "web" || !l.Data[1].IsCurrent {
		t.Errorf("sessions = %+v, want mobile (not current) then web (current)", l.Data)
	}
	if l.Data[1].IP == nil || *l.Data[1].IP != "203.0.113.50" || l.Data[1].CreatedAt != "2026-01-01T12:00:00Z" {
		t.Errorf("web session = %+v, want its IP and creation time", l.Data[1])
	}

	if l := f.listSessions(t, mobile.Token); !l.Data[0].IsCurrent || l.Data[1].IsCurrent {
		t.Errorf("from the mobile session, is_current = %v, %v; want true, false", l.Data[0].IsCurrent, l.Data[1].IsCurrent)
	}
}

func (f fixture) status(t *testing.T, tok string) int {
	t.Helper()
	return f.do(t, http.MethodGet, "/v1/things", "", withToken(tok)).status
}

func TestLogOut(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	a := f.signUp(t, testEmail)
	b := f.logIn(t, testEmail)

	if res := f.do(t, http.MethodDelete, "/v1/sessions/current", "", withToken(a.Token)); res.status != http.StatusNoContent {
		t.Fatalf("status %d, body %s", res.status, res.body)
	}
	if got := f.status(t, a.Token); got != http.StatusUnauthorized {
		t.Errorf("logged-out token: status %d, want 401", got)
	}
	if got := f.status(t, b.Token); got != http.StatusOK {
		t.Errorf("other session: status %d, want 200", got)
	}
}

func TestEndSession(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	mine := f.signUp(t, testEmail)
	other := f.logIn(t, testEmail)
	theirs := f.signUp(t, "grace@example.com")

	idOf := func(tok string) string {
		var id uuid.UUID
		if err := f.pool.QueryRow(context.Background(), `SELECT id FROM auth.sessions WHERE token_hash = $1`, token.Hash(tok)).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id.String()
	}

	tests := []struct{ name, id string }{
		{"another user's session", idOf(theirs.Token)},
		{"nonexistent session", uuid.Must(uuid.NewV7()).String()},
		{"not a UUID", "abc"},
	}
	for _, tt := range tests {
		res := f.do(t, http.MethodDelete, "/v1/sessions/"+tt.id, "", withToken(mine.Token))
		if res.status != http.StatusNotFound || res.errorCode(t) != "not_found" {
			t.Errorf("%s: status = %d, body %s; want 404 not_found", tt.name, res.status, res.body)
		}
	}
	if got := f.status(t, theirs.Token); got != http.StatusOK {
		t.Errorf("another user's session after the attempt: status %d, want 200", got)
	}

	if res := f.do(t, http.MethodDelete, "/v1/sessions/"+idOf(other.Token), "", withToken(mine.Token)); res.status != http.StatusNoContent {
		t.Fatalf("ending my other session: status %d, body %s", res.status, res.body)
	}
	if got := f.status(t, other.Token); got != http.StatusUnauthorized {
		t.Errorf("ended session: status %d, want 401", got)
	}
	if got := f.status(t, mine.Token); got != http.StatusOK {
		t.Errorf("current session: status %d, want 200", got)
	}
}

func TestLogOutEverywhere(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	a := f.signUp(t, testEmail)
	b := f.logIn(t, testEmail)
	theirs := f.signUp(t, "grace@example.com")

	if res := f.do(t, http.MethodDelete, "/v1/sessions", "", withToken(a.Token)); res.status != http.StatusNoContent {
		t.Fatalf("status %d, body %s", res.status, res.body)
	}
	for name, tok := range map[string]string{"current": a.Token, "other": b.Token} {
		if got := f.status(t, tok); got != http.StatusUnauthorized {
			t.Errorf("%s session: status %d, want 401", name, got)
		}
	}
	if got := f.status(t, theirs.Token); got != http.StatusOK {
		t.Errorf("another user's session: status %d, want 200", got)
	}
}

func TestResponseHeaders(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})

	res := f.do(t, http.MethodPost, "/v1/sessions", credentials(testEmail, testPassword, "web"), withHeader("X-Request-ID", "trace-42"))
	if got := res.header.Get("X-Request-ID"); got != "trace-42" {
		t.Errorf("X-Request-ID = %q, want trace-42", got)
	}
	var e errorJSON
	if err := json.Unmarshal(res.body, &e); err != nil || e.Error.RequestID != "trace-42" {
		t.Errorf("error request_id = %q, want trace-42", e.Error.RequestID)
	}

	l := f.signUp(t, testEmail)
	for _, path := range []string{"/v1/users/me", "/v1/sessions"} {
		res := f.do(t, http.MethodGet, path, "", withToken(l.Token))
		if got := res.header.Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s: Cache-Control = %q, want no-store", path, got)
		}
		if res.header.Get("X-Request-ID") == "" {
			t.Errorf("%s: no X-Request-ID", path)
		}
		if got := res.header.Get("Content-Type"); got != "application/json" {
			t.Errorf("%s: Content-Type = %q", path, got)
		}
	}
	if res := f.do(t, http.MethodGet, "/v1/things", ""); res.header.Get("X-Request-ID") == "" {
		t.Error("project route behind Authenticated: no X-Request-ID on 401")
	}
}

func TestLogsHaveNoSecrets(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	signed := f.signUp(t, testEmail)
	logged := f.logIn(t, testEmail)
	f.do(t, http.MethodPost, "/v1/sessions", credentials(testEmail, "wrong password here", "web"))
	f.do(t, http.MethodDelete, "/v1/sessions/current", "", withToken(logged.Token))

	logs := f.logs.String()
	if !strings.Contains(logs, signed.User.ID.String()) {
		t.Fatalf("logs don't mention the user ID; is logging wired up?\n%s", logs)
	}
	for _, secret := range []string{testEmail, testPassword, "wrong password here", signed.Token, logged.Token} {
		if strings.Contains(logs, secret) {
			t.Errorf("logs contain %q:\n%s", secret, logs)
		}
	}
}

func TestPublic(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	called := false
	h := f.auth.Public(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	if !called {
		t.Error("Public() handler wasn't called for a logged-out request")
	}
}
