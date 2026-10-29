package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/atlasopsec/auth/internal/db"
	"github.com/atlasopsec/auth/internal/emailtoken"
	"github.com/atlasopsec/auth/internal/oauth"
	"github.com/atlasopsec/auth/internal/pwned"
	"github.com/atlasopsec/auth/internal/secretbox"
	"github.com/atlasopsec/auth/internal/sender"
	"github.com/atlasopsec/auth/internal/session"
	"github.com/atlasopsec/auth/mail"
	"github.com/atlasopsec/auth/rbac"
)

// Config configures the module. DB, Mailer, AppURL, AppName, and
// EncryptionKey are required.
type Config struct {
	// DB is the project's Postgres pool. Run Migrate on it first.
	DB *pgxpool.Pool

	// TrustedProxies are the networks allowed to set X-Forwarded-For and
	// X-Forwarded-User-Agent, normally the Next.js server on Railway's
	// private network. Requests from anywhere else use the connection's
	// own address and User-Agent.
	TrustedProxies []netip.Prefix

	Hooks Hooks

	// Logger receives the module's logs. Default: slog.Default().
	Logger *slog.Logger

	// Now returns the current time. Default: time.Now. Set it in tests to
	// control session expiry.
	Now func() time.Time

	// Mailer sends the module's emails. Required. Use mail/resend in
	// production.
	Mailer mail.Mailer

	// AppURL is the web app's base URL, for links in emails, e.g.
	// "https://app.example.com". Required. It must use https, except on
	// localhost.
	AppURL string

	// AppName appears in email subjects and text, e.g. "Acme", and as the
	// issuer in authenticator apps. Required.
	AppName string

	// EncryptionKey encrypts 2FA secrets: 32 random bytes, base64-encoded,
	// from an environment variable such as AUTH_ENCRYPTION_KEY. Generate one
	// with `openssl rand -base64 32`. Required. Keep a backup: if it's lost,
	// every user has to set up 2FA again.
	EncryptionKey string

	// AllowUnverifiedLogin lets users log in before verifying their email,
	// and makes sign-up log them in immediately. Off by default: new users
	// must verify their email, with their password, before they can log
	// in. See docs/api.md.
	AllowUnverifiedLogin bool

	// Emails overrides the default email templates.
	Emails Emails

	// DisableBreachCheck turns off checking new passwords against Have I
	// Been Pwned. The check is on by default; it sends only the first 5
	// characters of the password's SHA-1 hash, and is skipped if the API
	// doesn't answer within 2 seconds.
	DisableBreachCheck bool

	// OrgRoles are the roles a user can have in an organization, checked
	// by RequireOrg. They must include "owner", which always has every
	// permission. Leave nil if the app has no organizations.
	OrgRoles rbac.Roles

	// DisableOrganizationCreation removes POST /v1/organizations, for apps
	// that create organizations themselves with CreateOrganization.
	DisableOrganizationCreation bool

	// AppRoles are roles that apply across the whole app, such as staff
	// roles, checked by Require. Users have no app role until SetAppRole
	// gives them one. Leave nil if the app doesn't need them.
	AppRoles rbac.Roles

	// TwoFactorRoles are the privileged roles (the auth standard §6): staff
	// roles such as "support" always, and "owner" and "admin" when
	// organizations are shared by teams. Apps where each user gets their
	// own workspace may leave owner and admin out. A user with one of them,
	// in any organization, must have 2FA, and their sessions last at most
	// 12 hours. Until they set 2FA up, they can only set it up, read
	// GET /v1/users/me, and log out. Each name must be defined in OrgRoles
	// or AppRoles.
	TwoFactorRoles []string

	// OAuth turns on signing in with Google and GitHub.
	OAuth OAuth
}

// Hooks let a project react to auth events.
type Hooks struct {
	// OnUserCreated runs inside the sign-up transaction. Returning an error
	// cancels the sign-up, so a project's own rows (e.g. a profile) are
	// created together with the user or not at all.
	//
	// The hook must write through tx, not the project's own pool: writes
	// through the pool aren't part of the transaction and wouldn't be
	// undone. Keep it quick, since the transaction stays open while it
	// runs.
	OnUserCreated func(ctx context.Context, tx pgx.Tx, u User) error
}

// Auth serves the module's endpoints and protects the project's own.
// Create it with New.
type Auth struct {
	pool            *pgxpool.Pool
	q               *db.Queries
	sessions        *session.Manager
	tokens          *emailtoken.Manager
	sender          *sender.Sender
	trusted         []netip.Prefix
	hooks           Hooks
	log             *slog.Logger
	now             func() time.Time
	appURL          string
	appName         string
	allowUnverified bool
	emails          Emails
	box             *secretbox.Box
	// breach is nil when the breach check is disabled.
	breach         breachChecker
	orgRoles       rbac.Roles
	appRoles       rbac.Roles
	twoFactorRoles []string
	// providers are the OAuth providers turned on, by name.
	providers          map[string]oauth.Provider
	disableOrgCreation bool
}

// breachChecker is implemented by *pwned.Checker, and faked in tests.
type breachChecker interface {
	Breached(ctx context.Context, password string) (bool, error)
}

// New validates cfg and returns a ready Auth. It doesn't touch the
// database; call Migrate first.
func New(cfg Config) (*Auth, error) {
	if cfg.DB == nil {
		return nil, errors.New("auth: Config.DB is required")
	}
	if cfg.Mailer == nil {
		return nil, errors.New("auth: Config.Mailer is required")
	}
	if strings.TrimSpace(cfg.AppName) == "" {
		return nil, errors.New("auth: Config.AppName is required")
	}
	appURL, err := parseAppURL(cfg.AppURL)
	if err != nil {
		return nil, err
	}
	box, err := secretbox.New(cfg.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("auth: Config.EncryptionKey: %w", err)
	}
	for _, p := range cfg.TrustedProxies {
		if !p.IsValid() {
			return nil, fmt.Errorf("auth: invalid trusted proxy prefix %v", p)
		}
	}
	if err := cfg.OrgRoles.Validate(); err != nil {
		return nil, fmt.Errorf("auth: Config.OrgRoles: %w", err)
	}
	if cfg.OrgRoles != nil && !cfg.OrgRoles.Defines(OwnerRole) {
		return nil, errors.New(`auth: Config.OrgRoles must define an "owner" role`)
	}
	if err := cfg.AppRoles.Validate(); err != nil {
		return nil, fmt.Errorf("auth: Config.AppRoles: %w", err)
	}
	for _, role := range cfg.TwoFactorRoles {
		if !cfg.OrgRoles.Defines(role) && !cfg.AppRoles.Defines(role) {
			return nil, fmt.Errorf("auth: Config.TwoFactorRoles: %q isn't a role in Config.OrgRoles or Config.AppRoles", role)
		}
	}
	a := &Auth{
		pool:            cfg.DB,
		q:               db.New(cfg.DB),
		trusted:         append([]netip.Prefix(nil), cfg.TrustedProxies...),
		hooks:           cfg.Hooks,
		log:             cfg.Logger,
		now:             cfg.Now,
		appURL:          appURL,
		box:             box,
		appName:         cfg.AppName,
		allowUnverified: cfg.AllowUnverifiedLogin,
		emails:          cfg.Emails,
		orgRoles:        cfg.OrgRoles,
		appRoles:        cfg.AppRoles,
		twoFactorRoles:  append([]string(nil), cfg.TwoFactorRoles...),

		disableOrgCreation: cfg.DisableOrganizationCreation,
	}
	if a.log == nil {
		a.log = slog.Default()
	}
	if a.now == nil {
		a.now = time.Now
	}
	if a.emails.VerifyEmail == nil {
		a.emails.VerifyEmail = defaultVerifyEmail
	}
	if a.emails.SignUpAttempt == nil {
		a.emails.SignUpAttempt = defaultSignUpAttempt
	}
	if a.emails.PasswordReset == nil {
		a.emails.PasswordReset = defaultPasswordReset
	}
	if a.emails.PasswordChanged == nil {
		a.emails.PasswordChanged = defaultPasswordChanged
	}
	if a.emails.EmailChange == nil {
		a.emails.EmailChange = defaultEmailChange
	}
	if a.emails.EmailChanged == nil {
		a.emails.EmailChanged = defaultEmailChanged
	}
	if a.emails.Invitation == nil {
		a.emails.Invitation = defaultInvitation
	}
	if a.emails.TwoFactorEnabled == nil {
		a.emails.TwoFactorEnabled = defaultTwoFactorEnabled
	}
	if a.emails.TwoFactorDisabled == nil {
		a.emails.TwoFactorDisabled = defaultTwoFactorDisabled
	}
	if a.emails.RecoveryCodesRegenerated == nil {
		a.emails.RecoveryCodesRegenerated = defaultRecoveryCodesRegenerated
	}
	if a.emails.RecoveryCodeUsed == nil {
		a.emails.RecoveryCodeUsed = defaultRecoveryCodeUsed
	}
	if a.emails.TwoFactorGuessing == nil {
		a.emails.TwoFactorGuessing = defaultTwoFactorGuessing
	}
	if !cfg.DisableBreachCheck {
		a.breach = pwned.New(pwned.DefaultURL)
	}
	if a.providers, err = newProviders(cfg.OAuth, a.now); err != nil {
		return nil, err
	}
	a.sessions = session.NewManager(cfg.DB, a.now)
	a.tokens = emailtoken.NewManager(cfg.DB, a.now)
	a.sender = sender.New(cfg.Mailer, a.log)
	if _, ok := cfg.Mailer.(*mail.Writer); ok {
		a.log.Warn("auth: emails are printed by mail.Writer, not sent. Their links contain live tokens: never use mail.Writer in production")
	}
	return a, nil
}

// Close waits for emails that are still being sent, until ctx is done.
// Call it when the server shuts down, after it stops accepting requests.
func (a *Auth) Close(ctx context.Context) error {
	if err := a.sender.Close(ctx); err != nil {
		return fmt.Errorf("auth: closing: %w", err)
	}
	return nil
}

// User is a user account. It never contains password hashes or tokens.
type User struct {
	ID            uuid.UUID
	Email         string
	EmailVerified bool
	CreatedAt     time.Time
}

// Session is a login session. It never contains the session token.
type Session struct {
	ID uuid.UUID
	// Client is "web" or "mobile".
	Client    string
	ExpiresAt time.Time
	CreatedAt time.Time
}

func userFromRow(r db.AuthUser) User {
	return User{
		ID:            r.ID,
		Email:         r.Email,
		EmailVerified: r.EmailVerifiedAt != nil,
		CreatedAt:     r.CreatedAt.UTC(),
	}
}

func sessionFromInternal(s session.Session) Session {
	return Session{
		ID:        s.ID,
		Client:    string(s.Client),
		ExpiresAt: s.ExpiresAt,
		CreatedAt: s.CreatedAt,
	}
}
