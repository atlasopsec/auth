// Package sender sends email in the background, so endpoints respond
// without waiting for the email provider.
//
// Responding first keeps response times the same whether or not an email
// was sent, so timing can't reveal whether an account exists. Messages
// aren't stored anywhere: they contain live tokens, and persisting them
// would undo the point of storing only token hashes. The cost is that a
// message still being sent when the process stops is lost; Close keeps
// that window small on a normal shutdown.
package sender

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/atlasopsec/auth/mail"
)

// Default retry behavior: three attempts, waiting 2s and then 10s between
// them, each limited to attemptTimeout.
var defaultBackoff = []time.Duration{2 * time.Second, 10 * time.Second}

const attemptTimeout = 30 * time.Second

// Sender sends messages in the background through a Mailer.
type Sender struct {
	mailer  mail.Mailer
	log     *slog.Logger
	backoff []time.Duration

	mu      sync.Mutex
	closed  bool
	closing chan struct{}
	wg      sync.WaitGroup
}

// New returns a Sender that sends through m and logs failures to log.
func New(m mail.Mailer, log *slog.Logger) *Sender {
	return &Sender{mailer: m, log: log, backoff: defaultBackoff, closing: make(chan struct{})}
}

// Send sends msg in the background, retrying on failure. It returns
// immediately. After Close, messages are dropped and logged.
func (s *Sender) Send(msg mail.Message) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		s.log.Error("auth: email dropped because the sender is closed",
			slog.String("idempotency_key", msg.IdempotencyKey))
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.deliver(msg)
	}()
}

func (s *Sender) deliver(msg mail.Message) {
	var err error
	for attempt := 0; ; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), attemptTimeout)
		err = s.mailer.Send(ctx, msg)
		cancel()
		if err == nil || attempt == len(s.backoff) {
			break
		}
		// On shutdown, retry straight away rather than waiting out the
		// backoff, so Close doesn't wait for timers.
		t := time.NewTimer(s.backoff[attempt])
		select {
		case <-t.C:
		case <-s.closing:
			t.Stop()
		}
	}
	if err != nil {
		// The message itself isn't logged: it contains the recipient's
		// address and a live token.
		s.log.Error("auth: sending email failed",
			slog.String("idempotency_key", msg.IdempotencyKey),
			slog.String("error", err.Error()))
	}
}

// ErrClosed is returned by Close if it was already called.
var ErrClosed = errors.New("sender: already closed")

// Close stops accepting messages and waits for messages already accepted
// to be sent, or to fail their last retry, until ctx is done. Pending
// retries run immediately instead of waiting.
func (s *Sender) Close(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	s.closed = true
	close(s.closing)
	s.mu.Unlock()

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
