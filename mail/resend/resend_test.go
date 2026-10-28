package resend

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/atlasopsec/auth/mail"
)

// placeholderValue stands in for a Resend API key; it isn't one.
const placeholderValue = "FAKE-KEY-FOR-TESTS"

func newTestMailer(t *testing.T, h http.HandlerFunc) *Mailer {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	m := New(placeholderValue, "Example <no-reply@mail.example.com>")
	u, err := url.Parse(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	m.client.BaseURL = u
	return m
}

func TestSend(t *testing.T) {
	t.Parallel()
	var gotBody map[string]any
	var gotHeader http.Header
	var gotPath string
	m := newTestMailer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotHeader = r.URL.Path, r.Header.Clone()
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decoding request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"49a3999c-0ce1-4ea6-ab68-afcd6dc2e794"}`))
	})

	err := m.Send(t.Context(), mail.Message{
		To:             "ada@example.com",
		Subject:        "Verify your email",
		Text:           "Click the link.",
		HTML:           "<p>Click the link.</p>",
		IdempotencyKey: "verify-123",
	})
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	if gotPath != "/emails" {
		t.Errorf("path = %q, want /emails", gotPath)
	}
	if got := gotHeader.Get("Authorization"); got != "Bearer "+placeholderValue {
		t.Errorf("Authorization = %q", got)
	}
	if got := gotHeader.Get("Idempotency-Key"); got != "verify-123" {
		t.Errorf("Idempotency-Key = %q, want verify-123", got)
	}
	want := map[string]any{
		"from":    "Example <no-reply@mail.example.com>",
		"to":      []any{"ada@example.com"},
		"subject": "Verify your email",
		"text":    "Click the link.",
		"html":    "<p>Click the link.</p>",
	}
	if diff := cmp.Diff(want, gotBody); diff != "" {
		t.Errorf("request body (-want +got):\n%s", diff)
	}
}

func TestSendError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		status int
	}{
		{"rejected", http.StatusUnprocessableEntity},
		{"rate limited", http.StatusTooManyRequests},
		{"server error", http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := newTestMailer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(`{"name":"error","message":"nope"}`))
			})
			if err := m.Send(t.Context(), mail.Message{To: "ada@example.com", Text: "x"}); err == nil {
				t.Error("Send() error = nil, want an error")
			}
		})
	}
}
