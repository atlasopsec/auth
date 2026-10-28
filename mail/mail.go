// Package mail defines how the auth module sends email.
//
// A project passes a Mailer in auth.Config: usually the Resend adapter in
// mail/resend, a Writer during local development, or mailtest.Recorder in
// tests.
package mail

import (
	"context"
	"fmt"
	"io"
	"sync"
)

// Mailer sends one email. The auth module calls Send from a background
// goroutine and retries on error, so an implementation should return an
// error for any failure worth retrying.
type Mailer interface {
	Send(ctx context.Context, m Message) error
}

// Message is one email.
type Message struct {
	To      string
	Subject string
	// Text is the plain-text body. It's always set.
	Text string
	// HTML is an optional HTML body.
	HTML string
	// IdempotencyKey is the same on every retry of one message, so a
	// provider that supports it can drop duplicates.
	IdempotencyKey string
}

// Writer is a Mailer for local development that prints each email to an
// io.Writer instead of sending it.
//
// Emails contain working links with live tokens, so a Writer must never be
// used in production: anyone who can read its output can take over
// accounts. auth.New logs a warning when it's given one.
type Writer struct {
	mu sync.Mutex
	w  io.Writer
}

// NewWriter returns a Writer that prints to w. For local development only.
func NewWriter(w io.Writer) *Writer {
	return &Writer{w: w}
}

// Send prints m.
func (w *Writer) Send(_ context.Context, m Message) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := fmt.Fprintf(w.w, "To: %s\nSubject: %s\n\n%s\n\n", m.To, m.Subject, m.Text); err != nil {
		return fmt.Errorf("mail: writing message: %w", err)
	}
	return nil
}
