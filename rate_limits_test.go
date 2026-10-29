package auth

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/atlasopsec/auth/internal/token"
)

func wantRateLimited(t *testing.T, what string, res response) {
	t.Helper()
	wantError(t, what, res, 429, "rate_limited")
	if s, err := strconv.Atoi(res.header.Get("Retry-After")); err != nil || s < 1 {
		t.Errorf("%s: Retry-After = %q, want a number of seconds", what, res.header.Get("Retry-After"))
	}
}

// TestLoginRateLimit checks every way to log in shares one per-IP limit.
func TestLoginRateLimit(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{})
	// Each login is for a different email, so the per-account delays
	// (login_failures_test.go) stay out of the way.
	n := 0
	wrongLogin := func() string {
		n++
		return credentials(fmt.Sprintf("user%d@example.com", n), "not my password", "web")
	}
	routes := []struct{ path, body string }{
		{"/v1/sessions", ""},
		{"/v1/email-verifications/confirm", `{"token":"x","password":"y","client":"web"}`},
		{"/v1/password-resets/confirm", resetBody("x", newPassword)},
		{"/v1/two-factor-challenges/verify", verifyBody(token.New(), "123456")},
		{"/v1/oauth-flows/complete", completeBody(token.New(), "code", token.New())},
		{"/v1/apple-sign-ins", appleBody("not-a-jwt", "nonce")},
	}
	for _, route := range routes {
		ip := nextTestIP()
		body := func(r struct{ path, body string }) string {
			if r.body == "" {
				return wrongLogin()
			}
			return r.body
		}
		for i := range limitLogin.Limit {
			if res := f.do(t, http.MethodPost, route.path, body(route), fromIP(ip)); res.status == http.StatusTooManyRequests {
				t.Fatalf("%s: request %d limited, want %d allowed", route.path, i+1, limitLogin.Limit)
			}
		}
		wantRateLimited(t, route.path+" over the limit", f.do(t, http.MethodPost, route.path, body(route), fromIP(ip)))
		// They share the limit.
		other := routes[0]
		if route.path == other.path {
			other = routes[1]
		}
		wantRateLimited(t, route.path+" then "+other.path, f.do(t, http.MethodPost, other.path, body(other), fromIP(ip)))
		if res := f.do(t, http.MethodPost, route.path, body(route), fromIP(nextTestIP())); res.status == http.StatusTooManyRequests {
			t.Errorf("%s: another IP was limited", route.path)
		}
	}

	ip := nextTestIP()
	for range limitLogin.Limit + 1 {
		f.do(t, http.MethodPost, "/v1/sessions", wrongLogin(), fromIP(ip))
	}
	f.clock.advance(limitLogin.Window)
	if res := f.do(t, http.MethodPost, "/v1/sessions", wrongLogin(), fromIP(ip)); res.status == http.StatusTooManyRequests {
		t.Error("still limited in the next window")
	}
}

func TestSignUpRateLimit(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	signUp := func(i int, ip string) response {
		return f.do(t, http.MethodPost, "/v1/users", credentials(fmt.Sprintf("user%d@example.com", i), testPassword, "web"), fromIP(ip))
	}
	// Addresses in one IPv6 /64 count together.
	for i := range limitSignUp.Limit {
		if res := signUp(i, fmt.Sprintf("2001:db8:1:2::%x", i+1)); res.status != http.StatusCreated {
			t.Fatalf("sign-up %d: status %d, body %s", i+1, res.status, res.body)
		}
	}
	wantRateLimited(t, "same /64", signUp(100, "2001:db8:1:2:ffff::1"))
	if res := signUp(101, "2001:db8:1:3::1"); res.status != http.StatusCreated {
		t.Errorf("another /64: status %d, body %s", res.status, res.body)
	}
}

func TestEmailRateLimits(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	reset := func(addr, ip string) response {
		return f.do(t, http.MethodPost, "/v1/password-resets", `{"email":"`+addr+`"}`, fromIP(ip))
	}
	verify := func(addr, ip string) response {
		return f.do(t, http.MethodPost, "/v1/email-verifications", `{"email":"`+addr+`"}`, fromIP(ip))
	}

	// Per IP, across endpoints and addresses.
	ip := nextTestIP()
	for i := range limitEmailIP.Limit {
		send := reset
		if i%2 == 1 {
			send = verify
		}
		if res := send(fmt.Sprintf("someone%d@example.com", i), ip); res.status != http.StatusAccepted {
			t.Fatalf("request %d: status %d, body %s", i+1, res.status, res.body)
		}
	}
	wantRateLimited(t, "per IP", reset("another@example.com", ip))

	// Per address, from many IPs, whether or not it has an account.
	for i := range limitEmailAddress.Limit {
		if res := reset("Target@example.com", nextTestIP()); res.status != http.StatusAccepted {
			t.Fatalf("request %d: status %d, body %s", i+1, res.status, res.body)
		}
	}
	wantRateLimited(t, "per address", verify("target@example.com", nextTestIP()))
	f.clock.advance(limitEmailAddress.Window)
	if res := reset("target@example.com", nextTestIP()); res.status != http.StatusAccepted {
		t.Errorf("the next day: status %d, body %s", res.status, res.body)
	}
}

// TestEmailRateLimitsCoverEverySender checks each endpoint that emails an
// address counts toward that address's limit.
func TestEmailRateLimitsCoverEverySender(t *testing.T) {
	t.Parallel()
	f := setupOrgs(t, Config{})
	tm := f.team(t)
	owner := tm.users[OwnerRole].Token
	const target = "target@example.com"
	use := func(n int) {
		for range n {
			f.do(t, http.MethodPost, "/v1/password-resets", `{"email":"`+target+`"}`, fromIP(nextTestIP()))
		}
	}
	senders := map[string]func() response{
		"sign-up": func() response {
			return f.do(t, http.MethodPost, "/v1/users", credentials(target, testPassword, "web"), fromIP(nextTestIP()))
		},
		"email change": func() response {
			return f.do(t, http.MethodPost, "/v1/email-changes", emailChangeBody(target, testPassword), withToken(owner), fromIP(nextTestIP()))
		},
		"invitation": func() response {
			return f.do(t, http.MethodPost, tm.path("/invitations"), `{"email":"`+target+`","role":"viewer"}`, withToken(owner), fromIP(nextTestIP()))
		},
	}
	use(limitEmailAddress.Limit)
	for name, send := range senders {
		wantRateLimited(t, name, send())
	}
}

func TestOAuthStartRateLimit(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{AllowUnverifiedLogin: true})
	v := f.verifiedUser(t, testEmail)
	ip := nextTestIP()
	for i := range limitOAuthStart.Limit {
		if res := f.do(t, http.MethodPost, "/v1/oauth-flows", startBody(providerGoogle, "web", challengeOf(token.New())), fromIP(ip)); res.status != http.StatusCreated {
			t.Fatalf("start %d: status %d, body %s", i+1, res.status, res.body)
		}
	}
	wantRateLimited(t, "starting a flow", f.do(t, http.MethodPost, "/v1/oauth-flows", startBody(providerGoogle, "web", challengeOf(token.New())), fromIP(ip)))
	wantRateLimited(t, "starting a link", f.do(t, http.MethodPost, "/v1/users/me/oauth-accounts", linkBody(providerGitHub, challengeOf(token.New()), testPassword), withToken(v.Token), fromIP(ip)))
}

// TestWrongCodeRateLimit checks wrong 2FA codes from one IP, across users,
// are limited, on top of each user's own guessing limit.
func TestWrongCodeRateLimit(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	ip := nextTestIP()
	logIn := func(email string) string {
		return challengeIn(t, f.do(t, http.MethodPost, "/v1/sessions", credentials(email, testPassword, "mobile"), fromIP(ip)))
	}
	secrets := map[string][]byte{}
	for i := range 4 {
		email := fmt.Sprintf("user%d@example.com", i)
		secrets[email], _ = f.enableTwoFactor(t, f.signUp(t, email).Token)
	}
	// 30 wrong codes: 10 for each of three users, in batches that stay
	// under the login limit and each user's own limit.
	for i := range 3 {
		email := fmt.Sprintf("user%d@example.com", i)
		for range 2 {
			ch := logIn(email)
			for range 5 {
				f.do(t, http.MethodPost, "/v1/two-factor-challenges/verify", verifyBody(ch, f.wrongCode(secrets[email])), fromIP(ip))
			}
		}
		f.clock.advance(limitLogin.Window)
	}

	// A fourth user, right code, same IP: refused without checking.
	ch := logIn("user3@example.com")
	wantRateLimited(t, "right code from the IP", f.do(t, http.MethodPost, "/v1/two-factor-challenges/verify", verifyBody(ch, f.code(secrets["user3@example.com"])), fromIP(ip)))
	if res := f.verify(t, ch, f.code(secrets["user3@example.com"])); res.status != http.StatusCreated {
		t.Errorf("from another IP: status %d, body %s", res.status, res.body)
	}
}

func TestCleanup(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{AllowUnverifiedLogin: true})
	ctx := context.Background()
	count := func(table string) int {
		t.Helper()
		var n int
		if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM auth.`+table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	addFailure := func(userID uuid.UUID) {
		t.Helper()
		if _, err := f.pool.Exec(ctx, `INSERT INTO auth.two_factor_failures (id, user_id, created_at) VALUES ($1, $2, $3)`, uuid.Must(uuid.NewV7()), userID, f.clock.now()); err != nil {
			t.Fatal(err)
		}
	}
	// One of each, in rows that will expire: a session, an email token
	// from sign-up, a 2FA challenge and failure, an OAuth flow, and
	// rate-limit windows.
	ada := f.signUp(t, testEmail)
	f.enableTwoFactor(t, ada.Token)
	f.startChallenge(t, testEmail)
	addFailure(ada.User.ID)
	f.startFlow(t, providerGoogle, "web")
	f.clock.advance(91 * day)

	// And a live one of each. Starting a challenge or a flow clears out
	// spent ones itself, so these come from another user, or the
	// database.
	grace := f.signUp(t, "grace@example.com")
	f.enableTwoFactor(t, grace.Token)
	f.startChallenge(t, "grace@example.com")
	addFailure(ada.User.ID)
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO auth.oauth_flows (id, state_hash, provider, purpose, client, client_challenge, pkce_verifier_encrypted, nonce, expires_at)
		VALUES ($1, $2, 'google', 'login', 'web', $2, '\x00', 'n', $3)`,
		uuid.Must(uuid.NewV7()), token.Hash(token.New()), f.clock.now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	tables := []string{"sessions", "email_tokens", "two_factor_challenges", "two_factor_failures", "oauth_flows", "rate_limits"}
	before := map[string]int{}
	for _, table := range tables {
		before[table] = count(table)
	}
	if err := f.auth.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	for _, table := range tables {
		got := count(table)
		if got >= before[table] {
			t.Errorf("%s: %d rows before cleanup, %d after; want the expired ones gone", table, before[table], got)
		}
		if got == 0 {
			t.Errorf("%s: the live rows were deleted too", table)
		}
	}
	if f.status(t, grace.Token) != http.StatusOK {
		t.Error("the live session was deleted")
	}
}

func TestCleanupRunsInBackground(t *testing.T) {
	t.Parallel()
	f := setupWith(t, Config{DisableCleanup: true})
	ctx := context.Background()
	if f.auth.stopCleanup != nil {
		t.Fatal("cleanup is running though disabled")
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO auth.rate_limits (id, key, window_start, expires_at, count) VALUES ($1, 'old', $2, $2, 1)`,
		uuid.Must(uuid.NewV7()), f.clock.now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	ran := make(chan struct{}, 1)
	f.auth.afterCleanup = func() {
		select {
		case ran <- struct{}{}:
		default:
		}
	}
	f.auth.startCleanup(time.Millisecond, time.Hour)
	<-ran
	var n int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM auth.rate_limits`).Scan(&n); err != nil || n != 0 {
		t.Errorf("%d rate-limit rows left (%v), want the ended one deleted", n, err)
	}
}
