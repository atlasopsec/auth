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

// loginKey is a login failure key and the failures it allows before
// delaying.
type loginKey struct {
	key       string
	threshold int
}

// loginKeys returns the keys a login attempt for email from ip counts
// against: per account and IP, and per account. With a valid device token
// (device is its key, from deviceKey), the per-account key is replaced by
// the device's own, so others' failures can't delay the owner. The email
// is hashed and need not have an account.
func loginKeys(email, ip, device string) []loginKey {
	h := ratelimit.Email(email)
	keys := []loginKey{{"account-ip:" + h + ":" + ip, accountIPThreshold}}
	if device != "" {
		return append(keys, loginKey{device, deviceThreshold})
	}
	return append(keys, loginKey{"account:" + h, accountThreshold})
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

// loginWait returns how long a login attempt for email from ip, with the
// device token key device or "", must still wait, or 0.
func (a *Auth) loginWait(ctx context.Context, email, ip, device string) (time.Duration, error) {
	var keys []string
	for _, k := range loginKeys(email, ip, device) {
		keys = append(keys, k.key)
	}
	waits, err := a.q.GetLoginWaits(ctx, keys)
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

// recordLoginFailure counts a wrong password for email from ip, with the
// device token key device or "", and sets how long the next attempt must
// wait.
func (a *Auth) recordLoginFailure(ctx context.Context, email, ip, device string) error {
	now := a.now().UTC().Truncate(time.Microsecond)
	for _, k := range loginKeys(email, ip, device) {
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

// clearLoginFailures forgets the failures for email from ip, and for the
// device token key device if it's set, after a correct password. Failures
// from elsewhere still count.
func (a *Auth) clearLoginFailures(ctx context.Context, email, ip, device string) error {
	forget := []string{loginKeys(email, ip, device)[0].key}
	if device != "" {
		forget = append(forget, device)
	}
	for _, k := range forget {
		if err := a.q.DeleteLoginFailures(ctx, k); err != nil {
			return fmt.Errorf("clearing login failures: %w", err)
		}
	}
	return nil
}
