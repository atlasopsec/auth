// Package ratelimit counts requests in fixed time windows, stored in
// Postgres so every API instance shares the counts.
//
// A limit of "10 per hour" counts per clock hour. Near the boundary of two
// windows up to twice the limit can get through in a short burst: the
// trade for a single atomic statement per check.
package ratelimit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/atlasopsec/auth/internal/db"
)

// Rule is one limit: at most Limit requests per Window for each subject.
type Rule struct {
	// Name identifies the limit in keys, e.g. "login:ip".
	Name   string
	Limit  int
	Window time.Duration
}

// Limiter counts requests against rules.
type Limiter struct {
	q   *db.Queries
	now func() time.Time
}

// New returns a Limiter using conn. now supplies the current time; pass
// time.Now outside tests.
func New(conn db.DBTX, now func() time.Time) *Limiter {
	return &Limiter{q: db.New(conn), now: now}
}

// Hit counts one more request by subject under rule, and reports whether
// it's within the limit. Over the limit, retryAfter is how long until the
// window ends.
func (l *Limiter) Hit(ctx context.Context, rule Rule, subject string) (ok bool, retryAfter time.Duration, err error) {
	now, start, end := l.window(rule)
	id, err := uuid.NewV7()
	if err != nil {
		return false, 0, fmt.Errorf("ratelimit: generating ID: %w", err)
	}
	n, err := l.q.HitRateLimit(ctx, db.HitRateLimitParams{
		ID: id, Key: key(rule, subject), WindowStart: start, ExpiresAt: end, Now: now,
	})
	if err != nil {
		return false, 0, fmt.Errorf("ratelimit: counting %s: %w", rule.Name, err)
	}
	if int(n) > rule.Limit {
		return false, end.Sub(now), nil
	}
	return true, 0, nil
}

// Reached reports whether subject has already used up rule's limit, without
// counting a request. It's for limits on failures, which are counted with
// Hit only once a request has failed.
func (l *Limiter) Reached(ctx context.Context, rule Rule, subject string) (reached bool, retryAfter time.Duration, err error) {
	now, start, end := l.window(rule)
	n, err := l.q.GetRateLimitCount(ctx, db.GetRateLimitCountParams{Key: key(rule, subject), WindowStart: start})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, 0, nil
	}
	if err != nil {
		return false, 0, fmt.Errorf("ratelimit: reading %s: %w", rule.Name, err)
	}
	if int(n) >= rule.Limit {
		return true, end.Sub(now), nil
	}
	return false, 0, nil
}

// DeleteEnded removes the counters of windows that have ended, and returns
// how many were removed.
func (l *Limiter) DeleteEnded(ctx context.Context) (int64, error) {
	n, err := l.q.DeleteEndedRateLimits(ctx, l.now().UTC().Truncate(time.Microsecond))
	if err != nil {
		return 0, fmt.Errorf("ratelimit: deleting ended windows: %w", err)
	}
	return n, nil
}

// window returns the current time and the bounds of rule's current window.
// Windows are aligned to the Unix epoch, so every instance agrees on them.
func (l *Limiter) window(rule Rule) (now, start, end time.Time) {
	now = l.now().UTC().Truncate(time.Microsecond)
	start = time.Unix(0, 0).UTC().Add(now.Sub(time.Unix(0, 0)).Truncate(rule.Window))
	return now, start, start.Add(rule.Window)
}

func key(rule Rule, subject string) string {
	return rule.Name + ":" + subject
}

// IP returns the subject for a client address: the address itself for
// IPv4, and its /64 for IPv6, since one device can use many addresses in
// its block.
func IP(ip *netip.Addr) string {
	if ip == nil {
		return "unknown"
	}
	addr := ip.Unmap()
	if addr.Is6() {
		return netip.PrefixFrom(addr, 64).Masked().String()
	}
	return addr.String()
}

// Email returns the subject for an email address: the SHA-256 of its
// lower-case form, so the table holds no addresses.
func Email(email string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return hex.EncodeToString(sum[:])
}
