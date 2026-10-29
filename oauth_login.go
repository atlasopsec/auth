package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/atlasopsec/auth/internal/db"
	"github.com/atlasopsec/auth/internal/httpapi"
	"github.com/atlasopsec/auth/internal/oauth"
	"github.com/atlasopsec/auth/internal/session"
	"github.com/atlasopsec/auth/internal/token"
)

// OAuth configures signing in with other providers. A nil provider is off.
//
// Register these redirect URIs with each provider: {AppURL}/oauth/callback
// for the web app and {AppURL}/oauth/callback/mobile for the mobile app.
// The web app serves both pages; see docs/api.md §9.
type OAuth struct {
	Google *Google
	GitHub *GitHub
	// Apple turns on native Sign in with Apple in the iOS app. Apple isn't
	// offered on the web or Android.
	Apple *Apple
}

// Google is a Google OAuth client, of type "Web application".
type Google struct {
	ClientID string
	// ClientSecret comes from an environment variable, such as
	// GOOGLE_CLIENT_SECRET.
	ClientSecret string
}

// GitHub is a GitHub OAuth app.
type GitHub struct {
	ClientID string
	// ClientSecret comes from an environment variable, such as
	// GITHUB_CLIENT_SECRET.
	ClientSecret string
}

// Apple is native Sign in with Apple, for the iOS app.
type Apple struct {
	// BundleIDs are the iOS apps' bundle IDs, such as "com.example.app".
	// Identity tokens issued to any other app are refused.
	BundleIDs []string
}

// Provider names, as used in the API.
const (
	providerGoogle = "google"
	providerGitHub = "github"
	providerApple  = "apple"
)

// oauthFlowLifetime is how long a user has to finish signing in at the
// provider.
const oauthFlowLifetime = 10 * time.Minute

// newProviders returns the configured providers, by name.
func newProviders(cfg OAuth, now func() time.Time) (map[string]oauth.Provider, error) {
	providers := map[string]oauth.Provider{}
	if g := cfg.Google; g != nil {
		if g.ClientID == "" || g.ClientSecret == "" {
			return nil, errors.New("auth: Config.OAuth.Google needs ClientID and ClientSecret")
		}
		providers[providerGoogle] = oauth.NewGoogle(g.ClientID, g.ClientSecret, oauth.DefaultGoogleEndpoints(), now)
	}
	if g := cfg.GitHub; g != nil {
		if g.ClientID == "" || g.ClientSecret == "" {
			return nil, errors.New("auth: Config.OAuth.GitHub needs ClientID and ClientSecret")
		}
		providers[providerGitHub] = oauth.NewGitHub(g.ClientID, g.ClientSecret, oauth.DefaultGitHubEndpoints())
	}
	return providers, nil
}

func (a *Auth) registerOAuth(mux *http.ServeMux) {
	mux.Handle("POST /v1/oauth-flows", endpoint(a.limitIP(limitOAuthStart, http.HandlerFunc(a.startOAuthFlow))))
	mux.Handle("POST /v1/oauth-flows/complete", endpoint(a.limitIP(limitLogin, http.HandlerFunc(a.completeOAuthFlow))))
	mux.Handle("POST /v1/apple-sign-ins", endpoint(a.limitIP(limitLogin, http.HandlerFunc(a.appleSignIn))))
	mux.Handle("GET /v1/users/me/oauth-accounts", endpoint(a.Authenticated(http.HandlerFunc(a.listOAuthAccounts))))
	mux.Handle("POST /v1/users/me/oauth-accounts", endpoint(a.Authenticated(a.limitIP(limitOAuthStart, http.HandlerFunc(a.startLink)))))
	mux.Handle("DELETE /v1/users/me/oauth-accounts/{id}", endpoint(a.Authenticated(http.HandlerFunc(a.unlink))))
}

// redirectURI is the web app page the provider sends the user back to.
func (a *Auth) redirectURI(client session.Client) string {
	if client == session.ClientMobile {
		return a.appURL + "/oauth/callback/mobile"
	}
	return a.appURL + "/oauth/callback"
}

type startOAuthRequest struct {
	Provider        string `json:"provider"`
	Client          string `json:"client"`
	ClientChallenge string `json:"client_challenge"`
}

type oauthFlowJSON struct {
	AuthorizationURL string    `json:"authorization_url"`
	ExpiresAt        timestamp `json:"expires_at"`
}

// startOAuthFlow starts signing in with a provider, and returns the URL to
// send the user to. client_challenge is the SHA-256 of a secret the client
// keeps, so only it can finish the flow.
func (a *Auth) startOAuthFlow(w http.ResponseWriter, r *http.Request) {
	var req startOAuthRequest
	if err := httpapi.Decode(w, r, &req); err != nil {
		httpapi.WriteDecodeError(w, r, err)
		return
	}
	challenge, details := a.checkFlowStart(req)
	if details != nil {
		writeValidationFailed(w, r, details)
		return
	}
	a.writeNewFlow(w, r, req, challenge, "login", nil)
}

// checkFlowStart validates a request to start a flow, returning the
// decoded client challenge or the invalid fields.
func (a *Auth) checkFlowStart(req startOAuthRequest) ([]byte, []httpapi.FieldError) {
	var details []httpapi.FieldError
	if _, ok := a.providers[req.Provider]; !ok {
		fe := httpapi.FieldError{Field: "provider", Code: "invalid_value", Message: "This sign-in provider isn't available."}
		if req.Provider == "" {
			fe.Code = "required"
		}
		details = append(details, fe)
	}
	if fe, ok := checkClient(req.Client); !ok {
		details = append(details, fe)
	}
	challenge, err := base64.RawURLEncoding.DecodeString(req.ClientChallenge)
	if err != nil || len(challenge) != sha256.Size {
		details = append(details, httpapi.FieldError{Field: "client_challenge", Code: "invalid_format", Message: "Send the base64url SHA-256 of the client verifier."})
	}
	return challenge, details
}

// writeNewFlow creates a flow for purpose ("login", or "link" with the
// user linking), and answers with the provider URL.
func (a *Auth) writeNewFlow(w http.ResponseWriter, r *http.Request, req startOAuthRequest, challenge []byte, purpose string, userID *uuid.UUID) {
	id, err := uuid.NewV7()
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, fmt.Errorf("generating OAuth flow ID: %w", err))
		return
	}
	state, verifier, nonce := token.New(), token.New(), token.New()
	now := a.now().UTC().Truncate(time.Microsecond)
	expires := now.Add(oauthFlowLifetime)
	client := session.Client(req.Client)
	err = a.inTx(r.Context(), func(q *db.Queries) error {
		if _, err := q.DeleteSpentOAuthFlows(r.Context(), now); err != nil {
			return fmt.Errorf("deleting spent OAuth flows: %w", err)
		}
		return q.CreateOAuthFlow(r.Context(), db.CreateOAuthFlowParams{
			ID:                    id,
			StateHash:             token.Hash(state),
			Provider:              req.Provider,
			Purpose:               purpose,
			UserID:                userID,
			Client:                string(client),
			ClientChallenge:       challenge,
			PkceVerifierEncrypted: a.box.Seal([]byte(verifier), id[:]),
			Nonce:                 nonce,
			ExpiresAt:             expires,
			Now:                   now,
		})
	})
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	httpapi.WriteJSON(w, r, http.StatusCreated, oauthFlowJSON{
		AuthorizationURL: a.providers[req.Provider].AuthCodeURL(state, verifier, nonce, a.redirectURI(client)),
		ExpiresAt:        timestamp(expires),
	})
}

type completeOAuthRequest struct {
	State          string `json:"state"`
	Code           string `json:"code"`
	ClientVerifier string `json:"client_verifier"`
}

var (
	// errOAuthFailed covers every way a flow can fail to prove who the
	// user is. The details are logged, never returned.
	errOAuthFailed           = errors.New("OAuth sign-in failed")
	errOAuthEmailNotVerified = errors.New("provider email not verified")
)

// completeOAuthFlow finishes signing in with a provider: with the code and
// state from the provider's redirect, and the client verifier, it logs the
// user in, or returns a 2FA challenge.
func (a *Auth) completeOAuthFlow(w http.ResponseWriter, r *http.Request) {
	var req completeOAuthRequest
	if err := httpapi.Decode(w, r, &req); err != nil {
		httpapi.WriteDecodeError(w, r, err)
		return
	}
	var details []httpapi.FieldError
	for _, f := range []struct{ name, value string }{{"state", req.State}, {"code", req.Code}, {"client_verifier", req.ClientVerifier}} {
		if f.value == "" {
			details = append(details, httpapi.FieldError{Field: f.name, Code: "required", Message: "Send the " + strings.ReplaceAll(f.name, "_", " ") + " from the sign-in."})
		}
	}
	if details != nil {
		writeValidationFailed(w, r, details)
		return
	}

	ctx := r.Context()
	flow, err := a.useOAuthFlow(ctx, req.State, req.ClientVerifier, a.sessionUserID(r))
	if err != nil {
		a.writeOAuthError(w, r, err)
		return
	}
	verifier, err := a.box.Open(flow.PkceVerifierEncrypted, flow.ID[:])
	if err != nil {
		a.writeOAuthError(w, r, fmt.Errorf("%w: decrypting PKCE verifier (was Config.EncryptionKey changed?): %w", errOAuthFailed, err))
		return
	}
	client := session.Client(flow.Client)
	id, err := a.providers[flow.Provider].Exchange(ctx, req.Code, string(verifier), flow.Nonce, a.redirectURI(client))
	if err != nil {
		a.writeOAuthError(w, r, fmt.Errorf("%w: %w", errOAuthFailed, err))
		return
	}

	if flow.Purpose == "link" {
		a.finishLink(w, r, flow, id)
		return
	}
	res, err := a.oauthLogIn(r, flow.Provider, id, client)
	if err != nil {
		a.writeOAuthError(w, r, err)
		return
	}
	a.writeOAuthLogin(w, r, flow.Provider, res)
}

// writeOAuthLogin logs what a provider login did to the account, and
// answers with the session or the 2FA challenge.
func (a *Auth) writeOAuthLogin(w http.ResponseWriter, r *http.Request, provider string, res oauthResult) {
	switch {
	case res.created:
		a.logEvent(r, "auth: user signed up with "+provider, res.user.ID)
	case res.linked:
		a.logEvent(r, "auth: "+provider+" linked by verified email", res.user.ID)
	}
	if res.created || res.linked {
		a.event(r, EventOAuthLinked, &res.user.ID, nil, map[string]string{"provider": provider})
	}
	if res.tookBack {
		a.logEvent(r, "auth: unverified account taken back by its email's owner", res.user.ID)
	}
	if res.challenge != "" {
		a.logEvent(r, "auth: two-factor challenge started", res.user.ID)
		writeChallengeJSON(w, r, res.challenge, res.expires)
		return
	}
	a.logEvent(r, "auth: user logged in with "+provider, res.user.ID)
	a.event(r, EventLoginSucceeded, &res.user.ID, nil, map[string]string{"method": provider})
	httpapi.WriteJSON(w, r, http.StatusCreated, newLoginResponse(toUserJSON(userFromRow(res.user)), res.token, res.session))
}

// useOAuthFlow spends the flow named by state, if it's usable and
// clientVerifier matches its challenge. A link flow also needs the session
// of the user who started it: sessionUser. It's spent before the provider
// is called, so a flow can never be finished twice, even if the call
// fails.
func (a *Auth) useOAuthFlow(ctx context.Context, state, clientVerifier string, sessionUser *uuid.UUID) (db.AuthOauthFlow, error) {
	if !token.Valid(state) {
		return db.AuthOauthFlow{}, fmt.Errorf("%w: malformed state", errOAuthFailed)
	}
	var flow db.AuthOauthFlow
	err := a.inTx(ctx, func(q *db.Queries) error {
		var err error
		flow, err = q.GetOAuthFlowForUpdate(ctx, token.Hash(state))
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: unknown state", errOAuthFailed)
		}
		if err != nil {
			return fmt.Errorf("reading OAuth flow: %w", err)
		}
		now := a.now().UTC().Truncate(time.Microsecond)
		if flow.UsedAt != nil || !now.Before(flow.ExpiresAt) {
			return fmt.Errorf("%w: flow used or expired", errOAuthFailed)
		}
		if flow.Purpose == "link" && (sessionUser == nil || flow.UserID == nil || *sessionUser != *flow.UserID) {
			return fmt.Errorf("%w: link flow finished without the linking user's session", errOAuthFailed)
		}
		sum := sha256.Sum256([]byte(clientVerifier))
		if subtle.ConstantTimeCompare(sum[:], flow.ClientChallenge) != 1 {
			return fmt.Errorf("%w: client verifier doesn't match", errOAuthFailed)
		}
		if _, ok := a.providers[flow.Provider]; !ok {
			return fmt.Errorf("%w: provider %s was turned off", errOAuthFailed, flow.Provider)
		}
		return q.UseOAuthFlow(ctx, db.UseOAuthFlowParams{ID: flow.ID, Now: &now})
	})
	return flow, err
}

// oauthResult is the outcome of oauthLogIn: a session, or a 2FA challenge.
type oauthResult struct {
	user db.AuthUser
	// token is the session token, or challenge the 2FA challenge token.
	token     string
	challenge string
	// expires is when the challenge expires; session is the new session.
	expires time.Time
	session session.Session
	// created, linked, and tookBack say what happened to the account.
	created  bool
	linked   bool
	tookBack bool
}

// oauthLogIn finds or creates the user a provider identified, then starts
// their session, or a 2FA challenge if they have 2FA, all or nothing. See
// docs/api.md §9 for the rules.
func (a *Auth) oauthLogIn(r *http.Request, provider string, id oauth.Identity, client session.Client) (oauthResult, error) {
	ctx := r.Context()
	var res oauthResult
	err := a.withTx(ctx, func(tx pgx.Tx) error {
		q := db.New(tx)
		now := a.now().UTC().Truncate(time.Microsecond)
		var userID uuid.UUID
		acct, err := q.GetOAuthAccount(ctx, db.GetOAuthAccountParams{Provider: provider, ProviderUserID: id.Subject})
		switch {
		case err == nil:
			userID = acct.UserID
		case !errors.Is(err, pgx.ErrNoRows):
			return fmt.Errorf("reading OAuth account: %w", err)
		case !id.EmailVerified:
			return errOAuthEmailNotVerified
		default:
			email := strings.TrimSpace(id.Email)
			if _, ok := checkEmail(email); !ok {
				return fmt.Errorf("%w: the provider's email address isn't usable", errOAuthFailed)
			}
			if userID, err = a.userForOAuthEmail(ctx, tx, email, now, &res); err != nil {
				return err
			}
			aid, err := uuid.NewV7()
			if err != nil {
				return fmt.Errorf("generating OAuth account ID: %w", err)
			}
			if err := q.CreateOAuthAccount(ctx, db.CreateOAuthAccountParams{
				ID: aid, UserID: userID, Provider: provider, ProviderUserID: id.Subject, Email: email, Now: now,
			}); err != nil {
				return fmt.Errorf("linking OAuth account: %w", err)
			}
		}

		var tf twoFactorState
		if res.user, tf, err = a.userWithTwoFactor(ctx, q, userID); err != nil {
			return err
		}
		if tf.enabled {
			if err := a.checkPaused(ctx, q, userID); err != nil {
				return err
			}
			res.challenge, res.expires, err = a.createChallenge(ctx, q, userID, client)
			return err
		}
		ip, ua := httpapi.Client(r, a.trusted)
		res.token, res.session, err = session.NewManager(tx, a.now).Create(ctx, userID, session.Meta{Client: client, IP: ip, UserAgent: ua}, sessionPolicy(tf))
		return err
	})
	if err != nil {
		return oauthResult{}, err
	}
	return res, nil
}

// userForOAuthEmail returns the user to link a provider-verified email to:
// the existing account with that email, or a new one. An existing account
// whose email was never verified may have been created by someone else
// with this address, so it's taken back first: everything that let anyone
// else in is removed, as a password reset does.
func (a *Auth) userForOAuthEmail(ctx context.Context, tx pgx.Tx, email string, now time.Time, res *oauthResult) (uuid.UUID, error) {
	q := db.New(tx)
	row, err := q.GetUserByEmailForUpdate(ctx, email)
	if errors.Is(err, pgx.ErrNoRows) {
		return a.createOAuthUser(ctx, tx, email, now, res)
	}
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("reading user: %w", err)
	}
	res.linked = true
	if row.EmailVerifiedAt != nil {
		return row.ID, nil
	}
	res.tookBack = true
	for _, step := range []struct {
		what string
		do   func() error
	}{
		{"clearing password", func() error { return q.ClearPassword(ctx, db.ClearPasswordParams{ID: row.ID, Now: now}) }},
		{"deleting 2FA secret", func() error { return q.DeleteTOTPSecret(ctx, row.ID) }},
		{"deleting recovery codes", func() error { return q.DeleteRecoveryCodes(ctx, row.ID) }},
		{"deleting 2FA challenges", func() error { return q.DeleteTwoFactorChallenges(ctx, row.ID) }},
		{"deleting email tokens", func() error { return q.DeleteUnusedUserEmailTokens(ctx, row.ID) }},
		{"marking email verified", func() error { return q.MarkEmailVerified(ctx, db.MarkEmailVerifiedParams{ID: row.ID, Now: now}) }},
	} {
		if err := step.do(); err != nil {
			return uuid.UUID{}, fmt.Errorf("taking back account: %s: %w", step.what, err)
		}
	}
	if _, err := session.NewManager(tx, a.now).RevokeAll(ctx, row.ID); err != nil {
		return uuid.UUID{}, err
	}
	return row.ID, nil
}

// createOAuthUser creates a user with a provider-verified email and no
// password, and runs OnUserCreated.
func (a *Auth) createOAuthUser(ctx context.Context, tx pgx.Tx, email string, now time.Time, res *oauthResult) (uuid.UUID, error) {
	q := db.New(tx)
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("generating user ID: %w", err)
	}
	row, err := q.CreateUser(ctx, db.CreateUserParams{ID: id, Email: email, Now: now})
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("creating user: %w", err)
	}
	if err := q.MarkEmailVerified(ctx, db.MarkEmailVerifiedParams{ID: id, Now: now}); err != nil {
		return uuid.UUID{}, fmt.Errorf("marking email verified: %w", err)
	}
	if a.hooks.OnUserCreated != nil {
		u := userFromRow(row)
		u.EmailVerified = true
		if err := a.hooks.OnUserCreated(ctx, tx, u); err != nil {
			return uuid.UUID{}, fmt.Errorf("OnUserCreated hook: %w", err)
		}
	}
	res.created = true
	return id, nil
}

// writeOAuthError writes the response for an error from an OAuth flow.
// Failures are logged with their cause, which the client never sees.
func (a *Auth) writeOAuthError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, errOAuthFailed):
		a.log.WarnContext(r.Context(), "auth: OAuth sign-in failed",
			slog.String("request_id", httpapi.RequestIDFrom(r.Context())),
			slog.String("error", err.Error()))
		httpapi.WriteError(w, r, http.StatusUnauthorized, "oauth_failed", "Signing in didn't work. Try again.", nil)
	case errors.Is(err, errOAuthEmailNotVerified):
		httpapi.WriteError(w, r, http.StatusForbidden, "oauth_email_not_verified",
			"Your email address isn't verified with this provider. Verify it there, then try again.", nil)
	default:
		a.writeLoginCodeError(w, r, err)
	}
}
