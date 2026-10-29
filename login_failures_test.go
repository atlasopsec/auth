package auth

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestLoginDelay(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		failures, threshold int
		want                time.Duration
	}{
		{0, 5, 0},
		{5, 5, 0},
		{6, 5, time.Second},
		{7, 5, 2 * time.Second},
		{15, 5, 512 * time.Second},
		{16, 5, maxLoginDelay},
		{1000, 5, maxLoginDelay},
		{20, 20, 0},
		{21, 20, time.Second},
	} {
		if got := loginDelay(tt.failures, tt.threshold); got != tt.want {
			t.Errorf("loginDelay(%d, %d) = %v, want %v", tt.failures, tt.threshold, got, tt.want)
		}
	}
}

func (f fixture) tryLogIn(t *testing.T, email, pw, ip string) response {
	t.Helper()
	return f.do(t, http.MethodPost, "/v1/sessions", credentials(email, pw, "web"), fromIP(ip))
}

func wantRetryAfter(t *testing.T, what string, res response, seconds int) {
	t.Helper()
	wantError(t, what, res, 429, "rate_limited")
	if got := res.header.Get("Retry-After"); got != strconv.Itoa(seconds) {
		t.Errorf("%s: Retry-After = %q, want %d", what, got, seconds)
	}
}

func TestFailedLoginsSlowDown(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	f.signUp(t, testEmail)
	ip := nextTestIP()

	// 5 failures are free; the 6th makes the next attempt wait 1 second.
	for i := range 6 {
		wantError(t, fmt.Sprintf("wrong password %d", i+1), f.tryLogIn(t, testEmail, "not my password", ip), 401, "invalid_credentials")
	}
	// Even the right password isn't checked while waiting.
	wantRetryAfter(t, "right password too soon", f.tryLogIn(t, testEmail, testPassword, ip), 1)
	f.clock.advance(time.Second)
	wantError(t, "wrong password 7", f.tryLogIn(t, testEmail, "not my password", ip), 401, "invalid_credentials")
	wantRetryAfter(t, "after the 7th", f.tryLogIn(t, testEmail, "not my password", ip), 2)

	// Another IP isn't slowed by this one's failures.
	if res := f.tryLogIn(t, testEmail, testPassword, nextTestIP()); res.status != http.StatusCreated {
		t.Errorf("from another IP: status %d, body %s", res.status, res.body)
	}

	// The right password, once allowed, clears this IP's count.
	f.clock.advance(2 * time.Second)
	if res := f.tryLogIn(t, testEmail, testPassword, ip); res.status != http.StatusCreated {
		t.Fatalf("right password after waiting: status %d, body %s", res.status, res.body)
	}
	for i := range accountIPThreshold + 1 {
		wantError(t, fmt.Sprintf("after success, wrong password %d", i+1), f.tryLogIn(t, testEmail, "not my password", ip), 401, "invalid_credentials")
	}
}

func TestFailedLoginsFromManyIPs(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	f.signUp(t, testEmail)
	// 20 failures from anywhere are free; the 21st makes the next attempt
	// wait 1 second.
	for i := range 21 {
		wantError(t, fmt.Sprintf("wrong password %d", i+1), f.tryLogIn(t, testEmail, "not my password", nextTestIP()), 401, "invalid_credentials")
	}
	wantRetryAfter(t, "right password from a new IP", f.tryLogIn(t, testEmail, testPassword, nextTestIP()), 1)
	if res := f.tryLogIn(t, "grace@example.com", testPassword, nextTestIP()); res.status == http.StatusTooManyRequests {
		t.Error("another account was slowed down")
	}
}

// TestFailedLoginsLookTheSame checks the delays don't reveal whether an
// account exists.
func TestFailedLoginsLookTheSame(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	f.signUp(t, testEmail)
	run := func(email string) []string {
		ip := nextTestIP()
		var got []string
		for range accountIPThreshold + 3 {
			res := f.tryLogIn(t, email, "not my password", ip)
			got = append(got, fmt.Sprintf("%d %s", res.status, res.header.Get("Retry-After")))
		}
		return got
	}
	real, unknown := run(testEmail), run("nobody@example.com")
	if fmt.Sprint(real) != fmt.Sprint(unknown) {
		t.Errorf("real account: %v\nunknown email: %v", real, unknown)
	}
}

func TestFailedLoginsStartOver(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	f.signUp(t, testEmail)
	ip := nextTestIP()
	for range accountIPThreshold {
		f.tryLogIn(t, testEmail, "not my password", ip)
	}
	f.clock.advance(loginFailureReset)
	// Counted from 1 again, so no delay after this one.
	f.tryLogIn(t, testEmail, "not my password", ip)
	if res := f.tryLogIn(t, testEmail, testPassword, ip); res.status != http.StatusCreated {
		t.Errorf("status %d, body %s; want the count to have started over", res.status, res.body)
	}
}

func TestWrongCurrentPasswordLimit(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	ada := f.signUp(t, testEmail)
	grace := f.signUp(t, "grace@example.com")
	start := func(tok, pw string) response {
		return f.do(t, http.MethodPost, "/v1/users/me/two-factor", pwBody(pw), withToken(tok))
	}

	for i := range limitWrongPassword.Limit {
		wantDetail(t, fmt.Sprintf("wrong password %d", i+1), start(ada.Token, "not my password"), "current_password:incorrect")
		// Right passwords don't count.
		if i == limitWrongPassword.Limit-1 {
			break
		}
		if res := start(ada.Token, testPassword); res.status != http.StatusCreated {
			t.Fatalf("right password: status %d, body %s", res.status, res.body)
		}
	}
	wantRateLimited(t, "right password after 10 wrong", start(ada.Token, testPassword))
	wantRateLimited(t, "another endpoint", f.do(t, http.MethodPost, "/v1/users/me/password", changeBody(testPassword, newPassword), withToken(ada.Token)))
	if res := start(grace.Token, testPassword); res.status != http.StatusCreated {
		t.Errorf("another user: status %d, body %s", res.status, res.body)
	}
}

func TestCleanupLoginFailures(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	ctx := context.Background()
	f.tryLogIn(t, "old@example.com", "x", nextTestIP())
	f.clock.advance(loginFailureReset)
	f.tryLogIn(t, "new@example.com", "x", nextTestIP())
	// Waiting, though its count is old: kept until the wait is over.
	if _, err := f.pool.Exec(ctx, `INSERT INTO auth.login_failures (id, key, failures, last_failed_at, next_allowed_at) VALUES ($1, 'waiting', 30, $2, $3)`,
		uuid.Must(uuid.NewV7()), f.clock.now().Add(-2*loginFailureReset), f.clock.now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	if err := f.auth.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM auth.login_failures`).Scan(&n); err != nil || n != 3 {
		t.Errorf("%d rows left (%v), want 3: the new email's two, and the waiting one", n, err)
	}
}
