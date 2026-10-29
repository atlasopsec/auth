package oauth_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/atlasopsec/auth/internal/oauth"
	"github.com/atlasopsec/auth/internal/oauth/oauthtest"
)

const redirect = "https://app.example.com/oauth/callback"

var now = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func clock() time.Time { return now }

func TestGoogle(t *testing.T) {
	t.Parallel()
	fake := oauthtest.NewGoogle(t, clock)
	p := oauth.NewGoogle(oauthtest.ClientID, oauthtest.ClientSecret, fake.Endpoints(), clock)
	ctx := context.Background()

	tests := []struct {
		name    string
		user    oauthtest.GoogleUser
		want    oauth.Identity
		wantErr bool
	}{
		{"verified", oauthtest.GoogleUser{Subject: "g-1", Email: "ada@example.com", EmailVerified: true},
			oauth.Identity{Subject: "g-1", Email: "ada@example.com", EmailVerified: true}, false},
		{"unverified", oauthtest.GoogleUser{Subject: "g-2", Email: "ada@example.com"},
			oauth.Identity{Subject: "g-2", Email: "ada@example.com"}, false},
		{"other issuer", oauthtest.GoogleUser{Subject: "g-3", Claims: map[string]any{"iss": "https://evil.example.com"}}, oauth.Identity{}, true},
		{"other audience", oauthtest.GoogleUser{Subject: "g-3", Claims: map[string]any{"aud": "someone-else"}}, oauth.Identity{}, true},
		{"expired", oauthtest.GoogleUser{Subject: "g-3", Claims: map[string]any{"exp": now.Add(-time.Minute).Unix()}}, oauth.Identity{}, true},
		{"other nonce", oauthtest.GoogleUser{Subject: "g-3", Claims: map[string]any{"nonce": "replayed"}}, oauth.Identity{}, true},
		{"no nonce", oauthtest.GoogleUser{Subject: "g-3", Claims: map[string]any{"nonce": nil}}, oauth.Identity{}, true},
		{"no subject", oauthtest.GoogleUser{Claims: map[string]any{"sub": nil}}, oauth.Identity{}, true},
		{"unpublished key", oauthtest.GoogleUser{Subject: "g-3", WrongKey: true}, oauth.Identity{}, true},
	}
	for _, tt := range tests {
		code, _ := fake.Authorize(p.AuthCodeURL("state", "verifier-0123456789012345678901234567890123", "nonce-1", redirect), tt.user)
		got, err := p.Exchange(ctx, code, "verifier-0123456789012345678901234567890123", "nonce-1", redirect)
		if (err != nil) != tt.wantErr {
			t.Errorf("%s: error = %v, want error %v", tt.name, err, tt.wantErr)
			continue
		}
		if diff := cmp.Diff(tt.want, got); diff != "" {
			t.Errorf("%s: identity (-want +got):\n%s", tt.name, diff)
		}
	}
}

// TestCodeExchangeChecks checks the provider sends what the exchange
// needs: the right PKCE verifier, redirect URI, and credentials.
func TestCodeExchangeChecks(t *testing.T) {
	t.Parallel()
	fake := oauthtest.NewGoogle(t, clock)
	ctx := context.Background()
	const verifier = "verifier-0123456789012345678901234567890123"
	user := oauthtest.GoogleUser{Subject: "g-1", Email: "ada@example.com", EmailVerified: true}

	for name, exchange := range map[string]func(p oauth.Provider, code string) error{
		"wrong verifier": func(p oauth.Provider, code string) error {
			_, err := p.Exchange(ctx, code, "another-verifier-01234567890123456789012345", "n", redirect)
			return err
		},
		"wrong redirect URI": func(p oauth.Provider, code string) error {
			_, err := p.Exchange(ctx, code, verifier, "n", redirect+"/mobile")
			return err
		},
		"wrong secret": func(_ oauth.Provider, code string) error {
			p := oauth.NewGoogle(oauthtest.ClientID, "not-the-secret", fake.Endpoints(), clock)
			_, err := p.Exchange(ctx, code, verifier, "n", redirect)
			return err
		},
	} {
		p := oauth.NewGoogle(oauthtest.ClientID, oauthtest.ClientSecret, fake.Endpoints(), clock)
		code, _ := fake.Authorize(p.AuthCodeURL("state", verifier, "n", redirect), user)
		if err := exchange(p, code); err == nil {
			t.Errorf("%s: error = nil, want an error", name)
		}
	}
}

func TestGitHub(t *testing.T) {
	t.Parallel()
	fake := oauthtest.NewGitHub(t)
	p := oauth.NewGitHub(oauthtest.ClientID, oauthtest.ClientSecret, fake.Endpoints())
	ctx := context.Background()
	const verifier = "verifier-0123456789012345678901234567890123"

	tests := []struct {
		name   string
		emails []oauthtest.GitHubEmail
		want   oauth.Identity
	}{
		{"primary verified", []oauthtest.GitHubEmail{
			{Email: "old@example.com", Verified: true},
			{Email: "ada@example.com", Primary: true, Verified: true},
		}, oauth.Identity{Subject: "42", Email: "ada@example.com", EmailVerified: true}},
		// Another verified address doesn't stand in for the primary.
		{"primary unverified", []oauthtest.GitHubEmail{
			{Email: "ada@example.com", Primary: true},
			{Email: "other@example.com", Verified: true},
		}, oauth.Identity{Subject: "42", Email: "ada@example.com"}},
		{"no emails", nil, oauth.Identity{Subject: "42"}},
	}
	for _, tt := range tests {
		code, _ := fake.Authorize(p.AuthCodeURL("state", verifier, "", redirect), oauthtest.GitHubUser{ID: 42, Emails: tt.emails})
		got, err := p.Exchange(ctx, code, verifier, "", redirect)
		if err != nil {
			t.Errorf("%s: %v", tt.name, err)
			continue
		}
		if diff := cmp.Diff(tt.want, got); diff != "" {
			t.Errorf("%s: identity (-want +got):\n%s", tt.name, diff)
		}
	}

	code, _ := fake.Authorize(p.AuthCodeURL("state", verifier, "", redirect), oauthtest.GitHubUser{ID: 42})
	if _, err := p.Exchange(ctx, code, "another-verifier-01234567890123456789012345", "", redirect); err == nil {
		t.Error("wrong verifier: error = nil, want an error")
	}
	code, _ = fake.Authorize(p.AuthCodeURL("state", verifier, "", redirect), oauthtest.GitHubUser{})
	if _, err := p.Exchange(ctx, code, verifier, "", redirect); err == nil {
		t.Error("user without an ID: error = nil, want an error")
	}
}
