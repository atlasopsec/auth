package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/atlasopsec/auth/internal/db"
	"github.com/atlasopsec/auth/internal/ratelimit"
)

// Failed logins slow down further attempts instead of locking the account
// (the auth standard §9; docs/api.md §10). After threshold failures for a
// key, each further failure makes the next attempt wait, doubling from 1
// second up to maxLoginDelay.
const (
	// accountIPThreshold counts failures for one email from one IP.
	accountIPThreshold = 5
	// accountThreshold counts failures for one email from everywhere,
	// against attacks spread over many addresses.
	accountThreshold = 20
	// loginFailureReset starts a key's count over after an hour without
	// failures.
	loginFailureReset = time.Hour
	maxLoginDelay     = 15 * time.Minute
)

// loginKeys returns the keys a login attempt for email from ip counts
// against: per account and IP, and per account. The email is hashed and
// need not have an account.
func loginKeys(email, ip string) (accountIP, account string) {
	h := ratelimit.Email(email)
	return "account-ip:" + h + ":" + ip, "account:" + h
}

// loginDelay is how long to wait after the failures-th failure, for a key
// with the given threshold.
func loginDelay(failures, threshold int) time.Duration {
	over := failures - threshold
	if over <= 0 {
		return 0
	}
	// 1s after the first failure over the threshold, then 2s, 4s...
	if over > 11 {
		return maxLoginDelay
	}
	return min(time.Second<<(over-1), maxLoginDelay)
}

// loginWait returns how long a login attempt for email from ip must still
// wait, or 0.
func (a *Auth) loginWait(ctx context.Context, email, ip string) (time.Duration, error) {
	accountIP, account := loginKeys(email, ip)
	waits, err := a.q.GetLoginWaits(ctx, []string{accountIP, account})
	if err != nil {
		return 0, fmt.Errorf("reading login delays: %w", err)
	}
	now := a.now()
	var wait time.Duration
	for _, until := range waits {
		wait = max(wait, until.Sub(now))
	}
	return wait, nil
}

// recordLoginFailure counts a wrong password for email from ip, and sets
// how long the next attempt must wait.
func (a *Auth) recordLoginFailure(ctx context.Context, email, ip string) error {
	accountIP, account := loginKeys(email, ip)
	now := a.now().UTC().Truncate(time.Microsecond)
	for _, k := range []struct {
		key       string
		threshold int
	}{{accountIP, accountIPThreshold}, {account, accountThreshold}} {
		id, err := uuid.NewV7()
		if err != nil {
			return fmt.Errorf("generating login failure ID: %w", err)
		}
		n, err := a.q.RecordLoginFailure(ctx, db.RecordLoginFailureParams{ID: id, Key: k.key, Now: now, ResetBefore: now.Add(-loginFailureReset)})
		if err != nil {
			return fmt.Errorf("recording login failure: %w", err)
		}
		if err := a.q.SetLoginNextAllowed(ctx, db.SetLoginNextAllowedParams{Key: k.key, NextAllowedAt: now.Add(loginDelay(int(n), k.threshold)), Now: now}); err != nil {
			return fmt.Errorf("setting login delay: %w", err)
		}
	}
	return nil
}

// clearLoginFailures forgets the failures for email from ip after a
// correct password. Failures from elsewhere still count.
func (a *Auth) clearLoginFailures(ctx context.Context, email, ip string) error {
	accountIP, _ := loginKeys(email, ip)
	if err := a.q.DeleteLoginFailures(ctx, accountIP); err != nil {
		return fmt.Errorf("clearing login failures: %w", err)
	}
	return nil
}
