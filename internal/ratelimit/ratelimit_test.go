package ratelimit_test

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/atlasopsec/auth/internal/ratelimit"
	"github.com/atlasopsec/auth/internal/testdb"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

var rule = ratelimit.Rule{Name: "test", Limit: 3, Window: time.Hour}

func TestHit(t *testing.T) {
	t.Parallel()
	c := &clock{t: time.Date(2026, 1, 1, 12, 15, 0, 0, time.UTC)}
	l := ratelimit.New(testdb.NewMigrated(t), c.now)
	ctx := context.Background()

	for i := range rule.Limit {
		if ok, _, err := l.Hit(ctx, rule, "a"); err != nil || !ok {
			t.Fatalf("hit %d: ok %v, err %v; want allowed", i+1, ok, err)
		}
	}
	ok, retry, err := l.Hit(ctx, rule, "a")
	if err != nil || ok {
		t.Fatalf("hit over the limit: ok %v, err %v; want refused", ok, err)
	}
	if retry != 45*time.Minute {
		t.Errorf("retry after %v, want 45m, when the clock hour ends", retry)
	}
	if ok, _, _ := l.Hit(ctx, rule, "b"); !ok {
		t.Error("another subject was refused")
	}
	if ok, _, _ := l.Hit(ctx, ratelimit.Rule{Name: "other", Limit: 3, Window: time.Hour}, "a"); !ok {
		t.Error("another rule was refused")
	}

	c.set(time.Date(2026, 1, 1, 13, 0, 0, 0, time.UTC))
	if ok, _, _ := l.Hit(ctx, rule, "a"); !ok {
		t.Error("refused in the next window")
	}
}

func TestHitIsAtomic(t *testing.T) {
	t.Parallel()
	c := &clock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	l := ratelimit.New(testdb.NewMigrated(t), c.now)
	many := ratelimit.Rule{Name: "many", Limit: 20, Window: time.Hour}

	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for range 50 {
		wg.Go(func() {
			ok, _, err := l.Hit(context.Background(), many, "a")
			if err != nil {
				t.Error(err)
			}
			if ok {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if allowed != many.Limit {
		t.Errorf("%d of 50 concurrent hits allowed, want exactly %d", allowed, many.Limit)
	}
}

func TestReached(t *testing.T) {
	t.Parallel()
	c := &clock{t: time.Date(2026, 1, 1, 12, 50, 0, 0, time.UTC)}
	l := ratelimit.New(testdb.NewMigrated(t), c.now)
	ctx := context.Background()

	for i := range rule.Limit {
		reached, _, err := l.Reached(ctx, rule, "a")
		if err != nil || reached {
			t.Fatalf("after %d hits: reached %v, err %v; want not reached", i, reached, err)
		}
		_, _, _ = l.Hit(ctx, rule, "a")
	}
	reached, retry, err := l.Reached(ctx, rule, "a")
	if err != nil || !reached || retry != 10*time.Minute {
		t.Errorf("at the limit: reached %v, retry %v, err %v; want reached, 10m", reached, retry, err)
	}
	// Checking doesn't count.
	for range 5 {
		_, _, _ = l.Reached(ctx, rule, "b")
	}
	if reached, _, _ := l.Reached(ctx, rule, "b"); reached {
		t.Error("checking counted as hits")
	}
}

func TestDeleteEnded(t *testing.T) {
	t.Parallel()
	c := &clock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	pool := testdb.NewMigrated(t)
	l := ratelimit.New(pool, c.now)
	ctx := context.Background()
	_, _, _ = l.Hit(ctx, rule, "old")
	c.set(c.now().Add(time.Hour))
	_, _, _ = l.Hit(ctx, rule, "current")

	if n, err := l.DeleteEnded(ctx); err != nil || n != 1 {
		t.Errorf("DeleteEnded = %d, %v; want 1 (the ended window only)", n, err)
	}
	var left int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM auth.rate_limits WHERE key = 'test:current'`).Scan(&left); err != nil || left != 1 {
		t.Errorf("current window rows = %d (%v), want 1", left, err)
	}
}

func TestSubjects(t *testing.T) {
	t.Parallel()
	ip := func(s string) *netip.Addr {
		a := netip.MustParseAddr(s)
		return &a
	}
	for in, want := range map[string]string{
		"203.0.113.7":                "203.0.113.7",
		"::ffff:203.0.113.7":         "203.0.113.7",
		"2001:db8:aaaa:bbbb:1:2:3:4": "2001:db8:aaaa:bbbb::/64",
		"2001:db8:aaaa:bbbb:ffff::9": "2001:db8:aaaa:bbbb::/64",
		"2001:db8:aaaa:cccc:1:2:3:4": "2001:db8:aaaa:cccc::/64",
	} {
		if got := ratelimit.IP(ip(in)); got != want {
			t.Errorf("IP(%s) = %s, want %s", in, got, want)
		}
	}
	if ratelimit.IP(nil) != "unknown" {
		t.Error("IP(nil) isn't unknown")
	}
	a, b := ratelimit.Email(" Ada@Example.com"), ratelimit.Email("ada@example.com")
	if a != b || len(a) != 64 || a == "ada@example.com" {
		t.Errorf("Email: %q and %q, want the same 64-character hash", a, b)
	}
}
