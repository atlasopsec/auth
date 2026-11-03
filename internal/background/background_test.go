package background

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newGroup() (*Group, *syncBuffer) {
	logs := &syncBuffer{}
	return New(slog.New(slog.NewTextHandler(logs, nil))), logs
}

func TestWaitWaitsForEveryFunction(t *testing.T) {
	t.Parallel()
	g, _ := newGroup()
	const n = 20
	var ran atomic.Int32
	for range n {
		if !g.Go(func() { ran.Add(1) }) {
			t.Fatal("Go() = false before Close")
		}
	}
	g.Wait()
	if got := ran.Load(); got != n {
		t.Errorf("%d functions had run after Wait, want %d", got, n)
	}
	// Waiting with nothing running returns at once.
	g.Wait()
}

func TestGoDoesNotWaitForTheFunction(t *testing.T) {
	t.Parallel()
	g, _ := newGroup()
	release := make(chan struct{})
	if !g.Go(func() { <-release }) {
		t.Fatal("Go() = false")
	}
	// Reaching here means Go returned while fn was still blocked.
	close(release)
	g.Wait()
}

func TestCloseWaitsAndThenRefuses(t *testing.T) {
	t.Parallel()
	g, _ := newGroup()
	release := make(chan struct{})
	finished := false
	g.Go(func() {
		<-release
		finished = true
	})

	closed := make(chan error, 1)
	go func() { closed <- g.Close(context.Background()) }()
	close(release)
	if err := <-closed; err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !finished {
		t.Error("Close returned before the running function did")
	}
	if g.Go(func() { t.Error("a function ran after Close") }) {
		t.Error("Go() after Close = true, want false")
	}
	if err := g.Close(context.Background()); !errors.Is(err, ErrClosed) {
		t.Errorf("second Close() = %v, want ErrClosed", err)
	}
}

func TestCloseGivesUpWhenTheContextEnds(t *testing.T) {
	t.Parallel()
	g, _ := newGroup()
	release := make(chan struct{})
	defer close(release)
	g.Go(func() { <-release })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := g.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Close() with a stuck function = %v, want context.Canceled", err)
	}
}

func TestPanicIsLoggedNotFatal(t *testing.T) {
	t.Parallel()
	g, logs := newGroup()
	g.Go(func() { panic("boom") })
	g.Wait()
	if s := logs.String(); !strings.Contains(s, "auth: background work panicked") || !strings.Contains(s, "boom") {
		t.Errorf("logs = %q, want the panic logged", s)
	}
	// The group still works.
	ran := false
	g.Go(func() { ran = true })
	g.Wait()
	if !ran {
		t.Error("the group stopped working after a panic")
	}
}
