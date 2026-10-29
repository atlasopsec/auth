// Package oauth runs the provider side of signing in with Google and
// GitHub: building the authorization URL with PKCE and state, and swapping
// the returned code for the user's identity.
//
// It holds no state of its own. The caller stores state, the PKCE verifier,
// and the nonce between the two steps, and decides what the identity means.
package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Identity is who a provider says the user is.
type Identity struct {
	// Subject is the provider's ID for the user, which never changes.
	Subject string
	// Email is the user's address at the provider. It may be empty.
	Email string
	// EmailVerified reports whether the provider vouches for Email.
	EmailVerified bool
}

// Provider is one sign-in provider.
type Provider interface {
	// AuthCodeURL returns the URL to send the user to. verifier is the PKCE
	// verifier; nonce is checked in the ID token, by providers that issue
	// one.
	AuthCodeURL(state, verifier, nonce, redirectURI string) string
	// Exchange swaps the code from the provider's redirect for the user's
	// identity.
	Exchange(ctx context.Context, code, verifier, nonce, redirectURI string) (Identity, error)
}

// timeout bounds every call to a provider.
const timeout = 10 * time.Second

// maxResponse limits how much of a provider's API response is read.
const maxResponse = 1 << 20

// GoogleEndpoints are where Google's endpoints live. Tests point them at
// a fake.
type GoogleEndpoints struct {
	AuthURL  string
	TokenURL string
	JWKSURL  string
	// Issuers are the accepted values of the ID token's iss claim.
	Issuers []string
}

// DefaultGoogleEndpoints returns Google's real endpoints.
func DefaultGoogleEndpoints() GoogleEndpoints {
	return GoogleEndpoints{ //nolint:gosec // G101: public endpoint URLs, not credentials.
		AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL: "https://oauth2.googleapis.com/token",
		JWKSURL:  "https://www.googleapis.com/oauth2/v3/certs",
		// Google's ID tokens use either form.
		Issuers: []string{"https://accounts.google.com", "accounts.google.com"},
	}
}

type google struct {
	cfg      oauth2.Config
	verifier *oidc.IDTokenVerifier
	issuers  []string
	client   *http.Client
}

// NewGoogle returns Google sign-in, using OpenID Connect: the identity comes
// from the signed ID token. now is the clock for the token's expiry check.
func NewGoogle(clientID, clientSecret string, e GoogleEndpoints, now func() time.Time) Provider {
	client := &http.Client{Timeout: timeout}
	keys := oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), client), e.JWKSURL)
	return &google{
		cfg: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     oauth2.Endpoint{AuthURL: e.AuthURL, TokenURL: e.TokenURL, AuthStyle: oauth2.AuthStyleInParams},
			Scopes:       []string{"openid", "email"},
		},
		// The issuer is checked below, against both forms Google uses.
		verifier: oidc.NewVerifier("", keys, &oidc.Config{ClientID: clientID, SkipIssuerCheck: true, Now: now}),
		issuers:  e.Issuers,
		client:   client,
	}
}

func (g *google) AuthCodeURL(state, verifier, nonce, redirectURI string) string {
	cfg := g.cfg
	cfg.RedirectURL = redirectURI
	return cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce))
}

func (g *google) Exchange(ctx context.Context, code, verifier, nonce, redirectURI string) (Identity, error) {
	cfg := g.cfg
	cfg.RedirectURL = redirectURI
	tok, err := cfg.Exchange(context.WithValue(ctx, oauth2.HTTPClient, g.client), code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Identity{}, fmt.Errorf("oauth: google: exchanging code: %w", err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok {
		return Identity{}, errors.New("oauth: google: no ID token in the response")
	}
	return verifyIDToken(ctx, g.verifier, g.issuers, raw, nonce)
}

// verifyIDToken checks an ID token's signature, audience, expiry, issuer,
// and nonce, and returns the identity in it.
func verifyIDToken(ctx context.Context, v *oidc.IDTokenVerifier, issuers []string, raw, nonce string) (Identity, error) {
	idTok, err := v.Verify(ctx, raw)
	if err != nil {
		return Identity{}, fmt.Errorf("oauth: verifying ID token: %w", err)
	}
	issuerOK := false
	for _, iss := range issuers {
		issuerOK = issuerOK || idTok.Issuer == iss
	}
	if !issuerOK {
		return Identity{}, fmt.Errorf("oauth: ID token issuer %q isn't accepted", idTok.Issuer)
	}
	if idTok.Nonce != nonce {
		return Identity{}, errors.New("oauth: ID token nonce doesn't match")
	}
	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := idTok.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("oauth: reading ID token claims: %w", err)
	}
	if idTok.Subject == "" {
		return Identity{}, errors.New("oauth: ID token has no subject")
	}
	return Identity{Subject: idTok.Subject, Email: claims.Email, EmailVerified: claims.EmailVerified}, nil
}

// GitHubEndpoints are where GitHub's endpoints live. Tests point them at
// a fake.
type GitHubEndpoints struct {
	AuthURL  string
	TokenURL string
	APIURL   string
}

// DefaultGitHubEndpoints returns GitHub's real endpoints.
func DefaultGitHubEndpoints() GitHubEndpoints {
	return GitHubEndpoints{ //nolint:gosec // G101: public endpoint URLs, not credentials.
		AuthURL:  "https://github.com/login/oauth/authorize",
		TokenURL: "https://github.com/login/oauth/access_token",
		APIURL:   "https://api.github.com",
	}
}

type github struct {
	cfg    oauth2.Config
	apiURL string
	client *http.Client
}

// NewGitHub returns GitHub sign-in. GitHub has no ID tokens, so the identity
// comes from its API: the user's ID, and their primary email if verified.
func NewGitHub(clientID, clientSecret string, e GitHubEndpoints) Provider {
	return &github{
		cfg: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     oauth2.Endpoint{AuthURL: e.AuthURL, TokenURL: e.TokenURL, AuthStyle: oauth2.AuthStyleInParams},
			Scopes:       []string{"user:email"},
		},
		apiURL: e.APIURL,
		client: &http.Client{Timeout: timeout},
	}
}

// GitHub ignores the nonce: it has no ID tokens to put it in. PKCE and
// state protect the flow.
func (g *github) AuthCodeURL(state, verifier, _, redirectURI string) string {
	cfg := g.cfg
	cfg.RedirectURL = redirectURI
	return cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
}

func (g *github) Exchange(ctx context.Context, code, verifier, _, redirectURI string) (Identity, error) {
	cfg := g.cfg
	cfg.RedirectURL = redirectURI
	tok, err := cfg.Exchange(context.WithValue(ctx, oauth2.HTTPClient, g.client), code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Identity{}, fmt.Errorf("oauth: github: exchanging code: %w", err)
	}
	var user struct {
		ID int64 `json:"id"`
	}
	if err := g.get(ctx, tok.AccessToken, "/user", &user); err != nil {
		return Identity{}, err
	}
	if user.ID == 0 {
		return Identity{}, errors.New("oauth: github: user has no ID")
	}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := g.get(ctx, tok.AccessToken, "/user/emails", &emails); err != nil {
		return Identity{}, err
	}
	id := Identity{Subject: strconv.FormatInt(user.ID, 10)}
	// Only the primary address: it's the one the user chose to be reached
	// at, so it's the one to match an account by.
	for _, e := range emails {
		if e.Primary {
			id.Email, id.EmailVerified = e.Email, e.Verified
		}
	}
	return id, nil
}

func (g *github) get(ctx context.Context, accessToken, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.apiURL+path, nil)
	if err != nil {
		return fmt.Errorf("oauth: github: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	res, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("oauth: github: GET %s: %w", path, err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("oauth: github: GET %s: status %d", path, res.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, maxResponse)).Decode(v); err != nil {
		return fmt.Errorf("oauth: github: decoding %s: %w", path, err)
	}
	return nil
}

// AppleEndpoints are where Apple's keys live, and the issuer its tokens
// name. Tests point them at a fake.
type AppleEndpoints struct {
	JWKSURL string
	Issuer  string
}

// DefaultAppleEndpoints returns Apple's real endpoints.
func DefaultAppleEndpoints() AppleEndpoints {
	return AppleEndpoints{JWKSURL: "https://appleid.apple.com/auth/keys", Issuer: "https://appleid.apple.com"}
}

// Apple checks the identity tokens of native Sign in with Apple on iOS.
// There's no redirect or code exchange: the app gets the signed token from
// the system sheet and sends it to the API.
type Apple struct {
	verifier  *oidc.IDTokenVerifier
	issuer    string
	bundleIDs []string
}

// NewApple returns a checker for tokens issued to any of bundleIDs. now is
// the clock for the token's expiry check.
func NewApple(bundleIDs []string, e AppleEndpoints, now func() time.Time) *Apple {
	client := &http.Client{Timeout: timeout}
	keys := oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), client), e.JWKSURL)
	return &Apple{
		// The audience is checked below, against every bundle ID.
		verifier:  oidc.NewVerifier(e.Issuer, keys, &oidc.Config{SkipClientIDCheck: true, Now: now}),
		issuer:    e.Issuer,
		bundleIDs: append([]string(nil), bundleIDs...),
	}
}

// Verify checks an identity token from the native sheet and returns the
// identity in it. The app gives Apple the hex SHA-256 of a random nonce,
// and sends the nonce itself here, so a token on its own can't be replayed
// by someone who doesn't have the nonce.
func (a *Apple) Verify(ctx context.Context, rawToken, nonce string) (Identity, error) {
	idTok, err := a.verifier.Verify(ctx, rawToken)
	if err != nil {
		return Identity{}, fmt.Errorf("oauth: apple: verifying identity token: %w", err)
	}
	audOK := false
	for _, aud := range idTok.Audience {
		for _, id := range a.bundleIDs {
			audOK = audOK || aud == id
		}
	}
	if !audOK {
		return Identity{}, fmt.Errorf("oauth: apple: token audience %v isn't a configured bundle ID", idTok.Audience)
	}
	sum := sha256.Sum256([]byte(nonce))
	if nonce == "" || subtle.ConstantTimeCompare([]byte(idTok.Nonce), []byte(hex.EncodeToString(sum[:]))) != 1 {
		return Identity{}, errors.New("oauth: apple: token nonce doesn't match")
	}
	var claims struct {
		Email         string   `json:"email"`
		EmailVerified flexBool `json:"email_verified"`
	}
	if err := idTok.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("oauth: apple: reading claims: %w", err)
	}
	if idTok.Subject == "" {
		return Identity{}, errors.New("oauth: apple: token has no subject")
	}
	return Identity{Subject: idTok.Subject, Email: claims.Email, EmailVerified: bool(claims.EmailVerified)}, nil
}

// flexBool reads a JSON boolean that Apple sends either as true or as the
// string "true".
type flexBool bool

func (b *flexBool) UnmarshalJSON(data []byte) error {
	switch string(data) {
	case `true`, `"true"`:
		*b = true
	case `false`, `"false"`, `null`:
		*b = false
	default:
		return fmt.Errorf("oauth: %s isn't a boolean", data)
	}
	return nil
}
