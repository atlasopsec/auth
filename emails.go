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
	// PasswordReset sends a password reset link.
	PasswordReset func(EmailData) (subject, text, html string)
	// PasswordChanged tells a user their password was changed or reset.
	// Link is empty.
	PasswordChanged func(EmailData) (subject, text, html string)
	// EmailChange asks a user to confirm a new address. It's sent to the
	// new address.
	EmailChange func(EmailData) (subject, text, html string)
	// EmailChanged tells the old address that the account's email was
	// changed. Link is empty.
	EmailChanged func(EmailData) (subject, text, html string)
	// Invitation invites someone to join an organization. OrgName is set.
	Invitation func(EmailData) (subject, text, html string)
	// TwoFactorEnabled, TwoFactorDisabled, and RecoveryCodesRegenerated
	// tell a user about changes to their 2FA. Link is empty.
	TwoFactorEnabled         func(EmailData) (subject, text, html string)
	TwoFactorDisabled        func(EmailData) (subject, text, html string)
	RecoveryCodesRegenerated func(EmailData) (subject, text, html string)
	// RecoveryCodeUsed tells a user a recovery code was used to log in or
	// to reset their password.
	// RecoveryCodesLeft is set. Link is empty.
	RecoveryCodeUsed func(EmailData) (subject, text, html string)
	// TwoFactorGuessing warns a user that someone got past their password
	// (or into their email, for a password reset) but then entered too
	// many wrong 2FA codes. Link is empty.
	TwoFactorGuessing func(EmailData) (subject, text, html string)
	// OAuthLinked and OAuthUnlinked tell a user a sign-in provider was
	// added to or removed from their account. Provider is set.
	OAuthLinked   func(EmailData) (subject, text, html string)
	OAuthUnlinked func(EmailData) (subject, text, html string)
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
	// OrgName is the organization's name, for invitations.
	OrgName string
	// RecoveryCodesLeft is how many unused recovery codes the user has,
	// for RecoveryCodeUsed.
	RecoveryCodesLeft int
	// Provider is the sign-in provider's name, such as "Google", for
	// OAuthLinked and OAuthUnlinked.
	Provider string
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

func defaultPasswordReset(d EmailData) (string, string, string) {
	return "Reset your password for " + d.AppName,
		fmt.Sprintf(`Someone asked to reset the password for your %s account. To choose a new password, open this link:

%s

The link works for %s. If you didn't ask for this, you can ignore this email. Your password hasn't changed.
`, d.AppName, d.Link, humanDuration(d.ExpiresIn)),
		""
}

func defaultPasswordChanged(d EmailData) (string, string, string) {
	return "Your " + d.AppName + " password was changed",
		fmt.Sprintf(`The password for your %s account was just changed.

If you did this, you can ignore this email. If you didn't, reset your password now at %s/reset-password. Resetting it logs everyone out of your account.
`, d.AppName, d.AppURL),
		""
}

func defaultEmailChange(d EmailData) (string, string, string) {
	return "Confirm your new email for " + d.AppName,
		fmt.Sprintf(`Someone asked to change the email address of a %s account to this one. To confirm, open this link:

%s

The link works for %s. If you didn't ask for this, you can ignore this email.
`, d.AppName, d.Link, humanDuration(d.ExpiresIn)),
		""
}

func defaultEmailChanged(d EmailData) (string, string, string) {
	return "Your " + d.AppName + " email was changed",
		fmt.Sprintf(`The email address of your %s account was just changed, so emails about it will no longer come here. Everyone was logged out of the account.

If you didn't do this, contact %s support right away: someone else may have taken over your account.
`, d.AppName, d.AppName),
		""
}

func defaultInvitation(d EmailData) (string, string, string) {
	return "You're invited to join " + d.OrgName + " on " + d.AppName,
		fmt.Sprintf(`You've been invited to join %s on %s. To accept, open this link and log in, or sign up with this email address:

%s

The invitation works for %s. If you weren't expecting it, you can ignore this email.
`, d.OrgName, d.AppName, d.Link, humanDuration(d.ExpiresIn)),
		""
}

func defaultTwoFactorEnabled(d EmailData) (string, string, string) {
	return "Two-factor authentication is on for your " + d.AppName + " account",
		fmt.Sprintf(`Two-factor authentication was just turned on for your %s account. Logging in now also needs a code from your authenticator app.

Keep your recovery codes somewhere safe. If you didn't do this, reset your password now at %s/reset-password.
`, d.AppName, d.AppURL),
		""
}

func defaultTwoFactorDisabled(d EmailData) (string, string, string) {
	return "Two-factor authentication is off for your " + d.AppName + " account",
		fmt.Sprintf(`Two-factor authentication was just turned off for your %s account. Logging in now needs only your password.

If you didn't do this, reset your password now at %s/reset-password, then turn two-factor authentication back on.
`, d.AppName, d.AppURL),
		""
}

func defaultRecoveryCodesRegenerated(d EmailData) (string, string, string) {
	return "New recovery codes for your " + d.AppName + " account",
		fmt.Sprintf(`New two-factor recovery codes were just created for your %s account. The old ones no longer work.

If you didn't do this, reset your password now at %s/reset-password.
`, d.AppName, d.AppURL),
		""
}

func defaultRecoveryCodeUsed(d EmailData) (string, string, string) {
	codes := fmt.Sprintf("%d recovery codes", d.RecoveryCodesLeft)
	if d.RecoveryCodesLeft == 1 {
		codes = "1 recovery code"
	}
	return "A recovery code was used for your " + d.AppName + " account",
		fmt.Sprintf(`A recovery code was just used for your %s account, to log in or to reset its password. You have %s left. If you're running low, create new ones in your account settings.

If you didn't do this, reset your password now at %s/reset-password, then create new recovery codes.
`, d.AppName, codes, d.AppURL),
		""
}

func defaultTwoFactorGuessing(d EmailData) (string, string, string) {
	return "Someone is trying to get into your " + d.AppName + " account",
		fmt.Sprintf(`Someone tried to log in to your %s account, or to reset its password, and entered too many wrong two-factor codes. Codes won't be accepted for the next 15 minutes.

To get that far, they needed your password or access to this email account. If it wasn't you, change your password now at %s/reset-password, and change your email password too.
`, d.AppName, d.AppURL),
		""
}

func defaultOAuthLinked(d EmailData) (string, string, string) {
	return d.Provider + " sign-in was added to your " + d.AppName + " account",
		fmt.Sprintf(`You can now log in to your %s account with %s.

If you didn't do this, someone else may be able to log in as you: reset your password now at %s/reset-password, and remove %s from your account settings.
`, d.AppName, d.Provider, d.AppURL, d.Provider),
		""
}

func defaultOAuthUnlinked(d EmailData) (string, string, string) {
	return d.Provider + " sign-in was removed from your " + d.AppName + " account",
		fmt.Sprintf(`You can no longer log in to your %s account with %s.

If you didn't do this, reset your password now at %s/reset-password.
`, d.AppName, d.Provider, d.AppURL),
		""
}

// humanDuration writes the token lifetimes used in emails: "30 minutes",
// "1 hour", "24 hours".
func humanDuration(d time.Duration) string {
	if d >= 48*time.Hour && d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%d days", int(d/(24*time.Hour)))
	}
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
	emailtoken.ChangeEmail:   "/confirm-email-change",
}

// link builds an email link. The token goes in the fragment, which
// browsers never send to servers, so it stays out of access logs,
// analytics, and Referer headers.
func (a *Auth) link(kind emailtoken.Kind, tok string) string {
	return a.appURL + linkPaths[kind] + "#token=" + tok
}

// sendEmail renders an email with a token link and hands it to the
// background sender. tokenID identifies the message across retries.
func (a *Auth) sendEmail(to string, tmpl func(EmailData) (string, string, string), kind emailtoken.Kind, tok string, tokenID uuid.UUID) {
	a.send(to, tmpl, EmailData{
		AppName:   a.appName,
		AppURL:    a.appURL,
		Link:      a.link(kind, tok),
		ExpiresIn: kind.Lifetime(),
	}, tokenID)
}

// sendNotice sends an email without a link, such as a security notice.
func (a *Auth) sendNotice(to string, tmpl func(EmailData) (string, string, string)) {
	a.send(to, tmpl, EmailData{AppName: a.appName, AppURL: a.appURL}, uuid.Must(uuid.NewV7()))
}

func (a *Auth) send(to string, tmpl func(EmailData) (string, string, string), d EmailData, key uuid.UUID) {
	subject, text, html := tmpl(d)
	a.sender.Send(mail.Message{To: to, Subject: subject, Text: text, HTML: html, IdempotencyKey: key.String()})
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
