// Package background runs work after an endpoint has responded.
//
// Endpoints that mustn't reveal whether an account exists use it for the
// work only an existing account needs, such as creating an email link. The
// response then takes the same time either way, because what's left in it
// doesn't depend on the account.
package background

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
)

// ErrClosed is returned by Close if it was already called.
var ErrClosed = errors.New("background: already closed")

// Group runs functions in goroutines and waits for them on Close. The zero
// value isn't usable; call New.
type Group struct {
	log *slog.Logger

	mu      sync.Mutex
	idle    *sync.Cond
	running int
	closed  bool
}

// New returns a Group that logs panics in its functions to log.
func New(log *slog.Logger) *Group {
	g := &Group{log: log}
	g.idle = sync.NewCond(&g.mu)
	return g
}

// Go runs fn in a new goroutine and returns true. After Close it doesn't
// run fn, and returns false. A panic in fn is logged instead of crashing
// the process, as net/http does for a handler.
func (g *Group) Go(fn func()) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return false
	}
	g.running++
	go func() {
		defer g.done()
		defer func() {
			if v := recover(); v != nil {
				g.log.Error("auth: background work panicked", slog.String("panic", fmt.Sprint(v)))
			}
		}()
		fn()
	}()
	return true
}

func (g *Group) done() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.running--
	if g.running == 0 {
		g.idle.Broadcast()
	}
}

// Wait blocks until every function started so far has returned. It's for
// tests; servers use Close. Unlike a sync.WaitGroup, it's safe to call
// while other goroutines call Go.
func (g *Group) Wait() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for g.running > 0 {
		g.idle.Wait()
	}
}

// Close stops accepting functions and waits for the running ones to
// return, until ctx is done.
func (g *Group) Close(ctx context.Context) error {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return ErrClosed
	}
	g.closed = true
	g.mu.Unlock()

	done := make(chan struct{})
	go func() {
		g.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
