// Package mailtest provides a fake Mailer for tests.
package mailtest

import (
	"context"
	"sync"

	"github.com/atlasopsec/auth/mail"
)

// Recorder is a Mailer that records every message instead of sending it.
// It's safe for concurrent use. The zero value is ready to use.
type Recorder struct {
	mu       sync.Mutex
	messages []mail.Message
	err      error
}

// Send records m, or returns the error set with Fail.
func (r *Recorder) Send(_ context.Context, m mail.Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	r.messages = append(r.messages, m)
	return nil
}

// Fail makes every later Send return err, or succeed again if err is nil.
func (r *Recorder) Fail(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.err = err
}

// Messages returns the messages sent so far, oldest first.
func (r *Recorder) Messages() []mail.Message {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]mail.Message(nil), r.messages...)
}
