package auth

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/atlasopsec/auth/internal/emailtoken"
	"github.com/atlasopsec/auth/mail"
)

// Emails overrides the module's default emails. Each field returns an
// email's subject, plain-text body, and optional HTML body. A nil field
// uses the default: short, plain text, and without branding.
type Emails struct {
	// VerifyEmail asks a new user to confirm their address.
	VerifyEmail func(EmailData) (subject, text, html string)
	// SignUpAttempt tells the owner of an existing account that someone
	// tried to sign up with their address. Link is a password reset link.
	SignUpAttempt func(EmailData) (subject, text, html string)
}

// EmailData is what an email template can use.
type EmailData struct {
	// AppName is Config.AppName.
	AppName string
	// AppURL is Config.AppURL, for links that don't need a token, such as
	// the page to request a password reset.
	AppURL string
	// Link is the email's action link, with its token.
	Link string
	// ExpiresIn is how long Link works.
	ExpiresIn time.Duration
}

func defaultVerifyEmail(d EmailData) (string, string, string) {
	return "Verify your email for " + d.AppName,
		fmt.Sprintf(`Confirm your email address for %s by opening this link:

%s

The link works for %s. If you didn't create an account, you can ignore this email.

If you don't remember your password, reset it here: %s/reset-password
`, d.AppName, d.Link, humanDuration(d.ExpiresIn), d.AppURL),
		""
}

func defaultSignUpAttempt(d EmailData) (string, string, string) {
	return "Sign-up attempt for " + d.AppName,
		fmt.Sprintf(`Someone tried to create a %s account with this email address, but you already have one.

If it was you, log in, or reset your password with this link:

%s

The link works for %s. If it wasn't you, you can ignore this email. Your account hasn't changed.
`, d.AppName, d.Link, humanDuration(d.ExpiresIn)),
		""
}

// humanDuration writes the token lifetimes used in emails: "30 minutes",
// "1 hour", "24 hours".
func humanDuration(d time.Duration) string {
	if d >= time.Hour && d%time.Hour == 0 {
		if h := int(d / time.Hour); h != 1 {
			return fmt.Sprintf("%d hours", h)
		}
		return "1 hour"
	}
	if m := int(d / time.Minute); m != 1 {
		return fmt.Sprintf("%d minutes", m)
	}
	return "1 minute"
}

// linkPaths are the Next.js pages that receive each kind of token.
var linkPaths = map[emailtoken.Kind]string{
	emailtoken.VerifyEmail:   "/verify-email",
	emailtoken.ResetPassword: "/reset-password",
}

// link builds an email link. The token goes in the fragment, which
// browsers never send to servers, so it stays out of access logs,
// analytics, and Referer headers.
func (a *Auth) link(kind emailtoken.Kind, tok string) string {
	return a.appURL + linkPaths[kind] + "#token=" + tok
}

// sendEmail renders an email and hands it to the background sender.
// tokenID identifies the message across retries.
func (a *Auth) sendEmail(to string, tmpl func(EmailData) (string, string, string), kind emailtoken.Kind, tok string, tokenID uuid.UUID) {
	subject, text, html := tmpl(EmailData{
		AppName:   a.appName,
		AppURL:    a.appURL,
		Link:      a.link(kind, tok),
		ExpiresIn: kind.Lifetime(),
	})
	a.sender.Send(mail.Message{To: to, Subject: subject, Text: text, HTML: html, IdempotencyKey: tokenID.String()})
}

// parseAppURL checks Config.AppURL: an absolute https URL (or http on
// localhost, for development) with no query or fragment. The result has no
// trailing slash.
func parseAppURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("auth: Config.AppURL: %w", err)
	}
	local := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"
	secure := u.Scheme == "https" || u.Scheme == "http" && local
	switch {
	case u.Host == "":
		return "", fmt.Errorf("auth: Config.AppURL %q must be an absolute URL", raw)
	case !secure:
		return "", fmt.Errorf("auth: Config.AppURL %q must use https (http is allowed only for localhost)", raw)
	case u.RawQuery != "" || u.Fragment != "" || u.User != nil:
		return "", fmt.Errorf("auth: Config.AppURL %q must not have a query, fragment, or user info", raw)
	}
	return strings.TrimRight(u.String(), "/"), nil
}
