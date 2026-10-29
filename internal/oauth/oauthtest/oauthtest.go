// Package oauthtest provides fake Google and GitHub servers for tests. They
// check PKCE, the redirect URI, and the client credentials like the real
// ones, and Google's signs real ID tokens with a test key.
package oauthtest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/atlasopsec/auth/internal/oauth"
)

// Client credentials the fakes accept. Obviously fake.
const (
	ClientID     = "test-client-id"
	ClientSecret = "test-client-secret"
)

// grant is an authorization the fake user gave, waiting for its code to be
// exchanged.
type grant struct {
	challenge   string
	redirectURI string
	nonce       string
	claims      map[string]any
	github      *GitHubUser
}

type server struct {
	t      *testing.T
	srv    *httptest.Server
	mu     sync.Mutex
	grants map[string]grant
	tokens map[string]*GitHubUser
}

func newServer(t *testing.T) *server {
	return &server{t: t, grants: map[string]grant{}, tokens: map[string]*GitHubUser{}}
}

// authorize plays the user approving the sign-in at authURL, and returns
// the code and state the provider would redirect back with.
func (s *server) authorize(authURL string, g grant) (code, state string) {
	s.t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		s.t.Fatal(err)
	}
	q := u.Query()
	if !strings.HasPrefix(authURL, s.srv.URL) || q.Get("client_id") != ClientID || q.Get("response_type") != "code" {
		s.t.Fatalf("authorization URL %s isn't for this fake", authURL)
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("state") == "" {
		s.t.Fatalf("authorization URL %s has no PKCE or state", authURL)
	}
	g.challenge, g.redirectURI, g.nonce = q.Get("code_challenge"), q.Get("redirect_uri"), q.Get("nonce")
	code = randomString()
	s.mu.Lock()
	s.grants[code] = g
	s.mu.Unlock()
	return code, q.Get("state")
}

// redeem checks a token request and returns its grant, writing an error
// response if it's wrong.
func (s *server) redeem(w http.ResponseWriter, r *http.Request) (grant, bool) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return grant{}, false
	}
	s.mu.Lock()
	g, ok := s.grants[r.PostForm.Get("code")]
	// A code works once.
	delete(s.grants, r.PostForm.Get("code"))
	s.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	switch {
	case !ok,
		r.PostForm.Get("client_id") != ClientID || r.PostForm.Get("client_secret") != ClientSecret,
		base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge,
		r.PostForm.Get("redirect_uri") != g.redirectURI:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		return grant{}, false
	}
	return g, true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func randomString() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Google is a fake Google.
type Google struct {
	s *server
	// Now is the clock for issued tokens' times.
	Now func() time.Time
	key *rsa.PrivateKey
	// otherKey signs tokens that must fail the signature check.
	otherKey *rsa.PrivateKey
}

// NewGoogle starts a fake Google, stopped when the test ends.
func NewGoogle(t *testing.T, now func() time.Time) *Google {
	t.Helper()
	g := &Google{s: newServer(t), Now: now, key: newKey(t), otherKey: newKey(t)}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", g.token)
	mux.HandleFunc("GET /certs", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"keys": []any{map[string]string{
			"kty": "RSA", "kid": "test", "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(g.key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(g.key.E)).Bytes()),
		}}})
	})
	g.s.srv = httptest.NewServer(mux)
	t.Cleanup(g.s.srv.Close)
	return g
}

func newKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Issuer is the iss claim the fake signs.
const Issuer = "https://accounts.google.com"

// Endpoints points the real Google provider at the fake.
func (g *Google) Endpoints() oauth.GoogleEndpoints {
	return oauth.GoogleEndpoints{
		AuthURL:  g.s.srv.URL + "/auth",
		TokenURL: g.s.srv.URL + "/token",
		JWKSURL:  g.s.srv.URL + "/certs",
		Issuers:  []string{Issuer},
	}
}

// GoogleUser is who signs in at the fake Google.
type GoogleUser struct {
	Subject       string
	Email         string
	EmailVerified bool
	// Claims override the ID token's claims, to test bad tokens. A nil
	// value removes the claim.
	Claims map[string]any
	// WrongKey signs the ID token with a key that isn't published.
	WrongKey bool
}

// Authorize plays u approving the sign-in at authURL, and returns the code
// and state Google would redirect back with.
func (g *Google) Authorize(authURL string, u GoogleUser) (code, state string) {
	g.s.t.Helper()
	claims := map[string]any{"sub": u.Subject, "email": u.Email, "email_verified": u.EmailVerified}
	if u.WrongKey {
		claims["wrong_key"] = true
	}
	for k, v := range u.Claims {
		claims[k] = v
	}
	return g.s.authorize(authURL, grant{claims: claims})
}

func (g *Google) token(w http.ResponseWriter, r *http.Request) {
	gr, ok := g.s.redeem(w, r)
	if !ok {
		return
	}
	now := g.Now()
	claims := map[string]any{
		"iss":   Issuer,
		"aud":   ClientID,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
		"nonce": gr.nonce,
	}
	for k, v := range gr.claims {
		if v == nil {
			delete(claims, k)
		} else {
			claims[k] = v
		}
	}
	key := g.key
	if claims["wrong_key"] == true {
		key = g.otherKey
		delete(claims, "wrong_key")
	}
	writeJSON(w, map[string]any{
		"access_token": randomString(),
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     sign(g.s.t, key, claims),
	})
}

// sign makes an RS256 JWT.
func sign(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "test", "typ": "JWT"})
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// GitHub is a fake GitHub.
type GitHub struct {
	s *server
}

// GitHubUser is who signs in at the fake GitHub.
type GitHubUser struct {
	ID     int64
	Emails []GitHubEmail
}

// GitHubEmail is one of a GitHub user's addresses.
type GitHubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// NewGitHub starts a fake GitHub, stopped when the test ends.
func NewGitHub(t *testing.T) *GitHub {
	t.Helper()
	g := &GitHub{s: newServer(t)}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		gr, ok := g.s.redeem(w, r)
		if !ok {
			return
		}
		tok := randomString()
		g.s.mu.Lock()
		g.s.tokens[tok] = gr.github
		g.s.mu.Unlock()
		writeJSON(w, map[string]any{"access_token": tok, "token_type": "bearer", "scope": "user:email"})
	})
	mux.HandleFunc("GET /user", func(w http.ResponseWriter, r *http.Request) {
		if u := g.user(w, r); u != nil {
			writeJSON(w, map[string]any{"id": u.ID, "login": fmt.Sprintf("user%d", u.ID)})
		}
	})
	mux.HandleFunc("GET /user/emails", func(w http.ResponseWriter, r *http.Request) {
		if u := g.user(w, r); u != nil {
			writeJSON(w, u.Emails)
		}
	})
	g.s.srv = httptest.NewServer(mux)
	t.Cleanup(g.s.srv.Close)
	return g
}

func (g *GitHub) user(w http.ResponseWriter, r *http.Request) *GitHubUser {
	g.s.mu.Lock()
	u := g.s.tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	g.s.mu.Unlock()
	if u == nil {
		http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
	}
	return u
}

// Endpoints points the real GitHub provider at the fake.
func (g *GitHub) Endpoints() oauth.GitHubEndpoints {
	return oauth.GitHubEndpoints{
		AuthURL:  g.s.srv.URL + "/login/oauth/authorize",
		TokenURL: g.s.srv.URL + "/login/oauth/access_token",
		APIURL:   g.s.srv.URL,
	}
}

// Authorize plays u approving the sign-in at authURL, and returns the code
// and state GitHub would redirect back with.
func (g *GitHub) Authorize(authURL string, u GitHubUser) (code, state string) {
	g.s.t.Helper()
	return g.s.authorize(authURL, grant{github: &u})
}
