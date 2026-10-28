package sender

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/atlasopsec/auth/mail"
	"github.com/atlasopsec/auth/mail/mailtest"
)

// flaky fails the first n sends, then delivers to a Recorder.
type flaky struct {
	mu       sync.Mutex
	failures int
	attempts int
	rec      mailtest.Recorder
	// attempted, if set, receives a value after each attempt.
	attempted chan struct{}
}

func (f *flaky) Send(ctx context.Context, m mail.Message) error {
	f.mu.Lock()
	f.attempts++
	fail := f.attempts <= f.failures
	f.mu.Unlock()
	if f.attempted != nil {
		defer func() { f.attempted <- struct{}{} }()
	}
	if fail {
		return errors.New("provider unavailable")
	}
	return f.rec.Send(ctx, m)
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func newSender(m mail.Mailer, backoff ...time.Duration) (*Sender, *syncBuffer) {
	logs := &syncBuffer{}
	s := New(m, slog.New(slog.NewTextHandler(logs, nil)))
	s.backoff = backoff
	return s, logs
}

var msg = mail.Message{To: "ada@example.com", Subject: "Reset", Text: "https://app.example.com/reset#token=SECRET", IdempotencyKey: "key-1"}

func TestSendDelivers(t *testing.T) {
	t.Parallel()
	var rec mailtest.Recorder
	s, _ := newSender(&rec, 0, 0)
	s.Send(msg)
	if err := s.Close(t.Context()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if diff := cmp.Diff([]mail.Message{msg}, rec.Messages()); diff != "" {
		t.Errorf("sent (-want +got):\n%s", diff)
	}
}

func TestSendRetries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		failures     int
		wantAttempts int
		wantSent     int
	}{
		{"first attempt works", 0, 1, 1},
		{"works on a retry", 2, 3, 1},
		{"gives up after three attempts", 5, 3, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := &flaky{failures: tt.failures}
			s, logs := newSender(f, 0, 0)
			s.Send(msg)
			if err := s.Close(t.Context()); err != nil {
				t.Fatalf("Close() error = %v", err)
			}
			if f.attempts != tt.wantAttempts {
				t.Errorf("attempts = %d, want %d", f.attempts, tt.wantAttempts)
			}
			if got := len(f.rec.Messages()); got != tt.wantSent {
				t.Errorf("sent %d messages, want %d", got, tt.wantSent)
			}
			failed := strings.Contains(logs.String(), "sending email failed")
			if failed != (tt.wantSent == 0) {
				t.Errorf("failure logged = %v, want %v; logs:\n%s", failed, tt.wantSent == 0, logs)
			}
		})
	}
}

func TestFailureLogHasNoSecrets(t *testing.T) {
	t.Parallel()
	s, logs := newSender(&flaky{failures: 3}, 0, 0)
	s.Send(msg)
	if err := s.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "key-1") {
		t.Fatalf("log doesn't identify the message:\n%s", logs)
	}
	for _, secret := range []string{msg.To, "SECRET"} {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("log contains %q:\n%s", secret, logs)
		}
	}
}

func TestCloseSkipsBackoff(t *testing.T) {
	t.Parallel()
	f := &flaky{failures: 1, attempted: make(chan struct{}, 2)}
	s, _ := newSender(f, time.Hour, time.Hour)
	s.Send(msg)
	<-f.attempted // the first attempt failed; the retry is waiting an hour

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if err := s.Close(ctx); err != nil {
		t.Fatalf("Close() error = %v, want the retry to run without waiting", err)
	}
	if got := len(f.rec.Messages()); got != 1 {
		t.Errorf("sent %d messages, want 1", got)
	}
}

// blocking holds every send until release is closed.
type blocking struct {
	release chan struct{}
	started chan struct{}
	rec     mailtest.Recorder
}

func (b *blocking) Send(ctx context.Context, m mail.Message) error {
	b.started <- struct{}{}
	<-b.release
	return b.rec.Send(ctx, m)
}

func TestCloseRespectsContext(t *testing.T) {
	t.Parallel()
	b := &blocking{release: make(chan struct{}), started: make(chan struct{}, 1)}
	s, _ := newSender(b)
	s.Send(msg)
	<-b.started

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := s.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Close() with a send in flight and a cancelled context = %v, want context.Canceled", err)
	}
	if err := s.Close(t.Context()); !errors.Is(err, ErrClosed) {
		t.Errorf("second Close() = %v, want ErrClosed", err)
	}

	// Giving up waiting doesn't abandon the send in flight.
	close(b.release)
	s.wg.Wait()
	if got := len(b.rec.Messages()); got != 1 {
		t.Errorf("sent %d messages, want 1", got)
	}
}

func TestSendAfterCloseDrops(t *testing.T) {
	t.Parallel()
	var rec mailtest.Recorder
	s, logs := newSender(&rec)
	if err := s.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	s.Send(msg)
	if got := len(rec.Messages()); got != 0 {
		t.Errorf("sent %d messages after Close, want 0", got)
	}
	if !strings.Contains(logs.String(), "dropped") {
		t.Errorf("dropped message wasn't logged:\n%s", logs)
	}
}
