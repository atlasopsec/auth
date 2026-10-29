package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/atlasopsec/auth/internal/db"
)

// Cleanup deletes what has expired: sessions, email links, 2FA challenges
// and old wrong-code records, OAuth flows, ended rate-limit windows and
// login delays, and security events over a year old. Apart from the
// events, they're already refused, so this only frees space.
//
// A background job runs it every hour, unless Config.DisableCleanup is
// set; then call it on your own schedule. Running it from several API
// instances at once is harmless.
func (a *Auth) Cleanup(ctx context.Context) error {
	now := a.now().UTC().Truncate(time.Microsecond)
	var errs []error
	for _, step := range []struct {
		what string
		del  func() (int64, error)
	}{
		{"sessions", func() (int64, error) { return a.sessions.DeleteExpired(ctx) }},
		{"email tokens", func() (int64, error) { return a.tokens.DeleteSpent(ctx) }},
		{"2FA challenges", func() (int64, error) {
			return a.q.DeleteEndedTwoFactorChallenges(ctx, db.DeleteEndedTwoFactorChallengesParams{Now: now, MaxFailedAttempts: maxChallengeAttempts})
		}},
		{"2FA failures", func() (int64, error) { return a.q.DeleteTwoFactorFailuresBefore(ctx, now.Add(-guessWindow)) }},
		{"OAuth flows", func() (int64, error) { return a.q.DeleteSpentOAuthFlows(ctx, now) }},
		{"rate limits", func() (int64, error) { return a.limiter.DeleteEnded(ctx) }},
		{"security events", func() (int64, error) { return a.q.DeleteAuthEventsBefore(ctx, now.Add(-eventRetention)) }},
		{"login failures", func() (int64, error) {
			return a.q.DeleteOldLoginFailures(ctx, db.DeleteOldLoginFailuresParams{ResetBefore: now.Add(-loginFailureReset), Now: now})
		}},
	} {
		n, err := step.del()
		if err != nil {
			// The rest still run: each table is independent.
			errs = append(errs, fmt.Errorf("deleting %s: %w", step.what, err))
			continue
		}
		if n > 0 {
			a.log.DebugContext(ctx, "auth: cleaned up", slog.String("what", step.what), slog.Int64("deleted", n))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("auth: cleanup: %w", err)
	}
	return nil
}

// Cleanup runs first a few minutes after start, so deploys don't run it
// in a burst, and then every hour.
const (
	cleanupFirst = 5 * time.Minute
	cleanupEvery = time.Hour
)

// startCleanup runs Cleanup in the background, first after first and then
// every every, until Close.
func (a *Auth) startCleanup(first, every time.Duration) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	a.stopCleanup = func() {
		cancel()
		<-done
	}
	go func() {
		defer close(done)
		timer := time.NewTimer(first)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			if err := a.Cleanup(ctx); err != nil && ctx.Err() == nil {
				a.log.ErrorContext(ctx, "auth: cleanup failed", slog.String("error", err.Error()))
			}
			if a.afterCleanup != nil {
				a.afterCleanup()
			}
			timer.Reset(every)
		}
	}()
}
