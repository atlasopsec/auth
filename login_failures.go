package auth

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

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

// loginClaim is a login attempt, counted as a failure before its password
// is checked. See claimLoginAttempt.
type loginClaim struct {
	email, ip, device string
	keys              []loginKey
	// at is when the attempt was counted; before holds each key's row as
	// it was then, if it had one.
	at     time.Time
	before map[string]db.GetLoginFailuresForUpdateRow
}

// claimLoginAttempt checks whether a login attempt for email from ip, with
// the device token key device or "", may be checked yet. If it must still
// wait, it returns how long. Otherwise it counts the attempt as a failure
// straight away, under the keys' row locks, so attempts sent at once can't
// all be checked before any is counted: the first one over a threshold
// makes the rest wait. A correct password then undoes it with
// loginSucceeded.
func (a *Auth) claimLoginAttempt(ctx context.Context, email, ip, device string) (time.Duration, *loginClaim, error) {
	c := &loginClaim{
		email: email, ip: ip, device: device,
		keys:   loginKeys(email, ip, device),
		at:     a.now().UTC().Truncate(time.Microsecond),
		before: map[string]db.GetLoginFailuresForUpdateRow{},
	}
	// Taking the locks in key order means two attempts can't deadlock.
	slices.SortFunc(c.keys, func(x, y loginKey) int { return strings.Compare(x.key, y.key) })
	var wait time.Duration
	err := a.withTx(ctx, func(tx pgx.Tx) error {
		q := db.New(tx)
		rows, err := q.GetLoginFailuresForUpdate(ctx, keyNames(c.keys))
		if err != nil {
			return fmt.Errorf("reading login delays: %w", err)
		}
		for _, row := range rows {
			c.before[row.Key] = row
			wait = max(wait, row.NextAllowedAt.Sub(c.at))
		}
		if wait > 0 {
			return nil
		}
		for _, k := range c.keys {
			id, err := uuid.NewV7()
			if err != nil {
				return fmt.Errorf("generating login failure ID: %w", err)
			}
			n, err := q.RecordLoginFailure(ctx, db.RecordLoginFailureParams{ID: id, Key: k.key, Now: c.at, ResetBefore: c.at.Add(-loginFailureReset)})
			if err != nil {
				return fmt.Errorf("recording login failure: %w", err)
			}
			if err := q.SetLoginNextAllowed(ctx, db.SetLoginNextAllowedParams{Key: k.key, NextAllowedAt: c.at.Add(loginDelay(int(n), k.threshold)), Now: c.at}); err != nil {
				return fmt.Errorf("setting login delay: %w", err)
			}
		}
		return nil
	})
	if err != nil || wait > 0 {
		return wait, nil, err
	}
	return 0, c, nil
}

func keyNames(keys []loginKey) []string {
	names := make([]string, len(keys))
	for i, k := range keys {
		names[i] = k.key
	}
	return names
}

// loginSucceeded undoes a claimed attempt whose password was right. It
// forgets the failures for the email from that IP, and for the device
// token if one was sent. The account-wide count, which failures from
// elsewhere also add to, only loses the one this attempt added.
func (a *Auth) loginSucceeded(ctx context.Context, c *loginClaim) error {
	forget := []string{loginKeys(c.email, c.ip, c.device)[0].key}
	if c.device != "" {
		forget = append(forget, c.device)
	}
	var undo []loginKey
	for _, k := range c.keys {
		if !slices.Contains(forget, k.key) {
			undo = append(undo, k)
		}
	}
	return a.withTx(ctx, func(tx pgx.Tx) error {
		q := db.New(tx)
		rows, err := q.GetLoginFailuresForUpdate(ctx, keyNames(undo))
		if err != nil {
			return fmt.Errorf("reading login failures: %w", err)
		}
		for _, row := range rows {
			if err := c.undo(ctx, q, row, undo, a.now().UTC().Truncate(time.Microsecond)); err != nil {
				return err
			}
		}
		for _, k := range forget {
			if err := q.DeleteLoginFailures(ctx, k); err != nil {
				return fmt.Errorf("clearing login failures: %w", err)
			}
		}
		return nil
	})
}

// undo takes the claimed failure back out of row, which is locked.
func (c *loginClaim) undo(ctx context.Context, q *db.Queries, row db.GetLoginFailuresForUpdateRow, keys []loginKey, now time.Time) error {
	failures := row.Failures - 1
	if failures <= 0 {
		if err := q.DeleteLoginFailures(ctx, row.Key); err != nil {
			return fmt.Errorf("clearing login failures: %w", err)
		}
		return nil
	}
	set := db.SetLoginFailureParams{Key: row.Key, Failures: failures, LastFailedAt: row.LastFailedAt, Now: now}
	before, existed := c.before[row.Key]
	if existed && row.LastFailedAt.Equal(c.at) && before.Failures == failures {
		// Nothing else failed since: put the row back as it was.
		set.LastFailedAt, set.NextAllowedAt = before.LastFailedAt, before.NextAllowedAt
	} else {
		// Others failed since, or the count had started over. The delay is
		// the one the latest failure would have set without this attempt.
		i := slices.IndexFunc(keys, func(k loginKey) bool { return k.key == row.Key })
		set.NextAllowedAt = row.LastFailedAt.Add(loginDelay(int(failures), keys[i].threshold))
		if set.NextAllowedAt.After(row.NextAllowedAt) {
			set.NextAllowedAt = row.NextAllowedAt
		}
	}
	if err := q.SetLoginFailure(ctx, set); err != nil {
		return fmt.Errorf("undoing login failure: %w", err)
	}
	return nil
}
