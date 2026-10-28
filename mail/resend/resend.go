// Package resend sends the auth module's email through Resend
// (https://resend.com), the standard transactional email provider.
//
// It's a separate package so only projects that use Resend compile its SDK.
package resend

import (
	"context"
	"fmt"

	resendapi "github.com/resend/resend-go/v3"

	"github.com/atlasopsec/auth/mail"
)

// Mailer sends email through Resend.
type Mailer struct {
	client *resendapi.Client
	from   string
}

// New returns a Mailer that sends from from, e.g.
// "Example <no-reply@mail.example.com>", using apiKey. Keep the key in an
// environment variable, never in code.
func New(apiKey, from string) *Mailer {
	return &Mailer{client: resendapi.NewClient(apiKey), from: from}
}

// Send sends m. The message's IdempotencyKey is passed to Resend, so a
// retried send isn't delivered twice.
func (m *Mailer) Send(ctx context.Context, msg mail.Message) error {
	req := &resendapi.SendEmailRequest{
		From:    m.from,
		To:      []string{msg.To},
		Subject: msg.Subject,
		Text:    msg.Text,
		Html:    msg.HTML,
	}
	opts := &resendapi.SendEmailOptions{IdempotencyKey: msg.IdempotencyKey}
	if _, err := m.client.Emails.SendWithOptions(ctx, req, opts); err != nil {
		return fmt.Errorf("resend: sending email: %w", err)
	}
	return nil
}
