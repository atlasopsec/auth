package pwned

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// "password" has SHA-1 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8.
const (
	sample       = "password"
	samplePrefix = "5BAA6"
	sampleSuffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
)

func server(t *testing.T, h http.HandlerFunc) *Checker {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return New(srv.URL + "/")
}

func TestBreached(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"listed", "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n" + sampleSuffix + ":9659365\r\n", true},
		{"listed in lowercase", strings.ToLower(sampleSuffix) + ":3\n", true},
		{"not listed", "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n", false},
		{"only as padding", sampleSuffix + ":0\r\n", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var path, padding, ua string
			c := server(t, func(w http.ResponseWriter, r *http.Request) {
				path, padding, ua = r.URL.Path, r.Header.Get("Add-Padding"), r.Header.Get("User-Agent")
				_, _ = w.Write([]byte(tt.body))
			})
			got, err := c.Breached(t.Context(), sample)
			if err != nil {
				t.Fatalf("Breached() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("Breached() = %v, want %v", got, tt.want)
			}
			// Only the 5-character prefix is sent; never the password or
			// its full hash.
			if path != "/range/"+samplePrefix {
				t.Errorf("request path = %q, want /range/%s", path, samplePrefix)
			}
			if padding != "true" || ua == "" {
				t.Errorf("headers Add-Padding = %q, User-Agent = %q", padding, ua)
			}
		})
	}
}

func TestBreachedErrors(t *testing.T) {
	t.Parallel()
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"server error", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInternalServerError) }},
		{"rate limited", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTooManyRequests) }},
		{"too slow", func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-block:
			case <-r.Context().Done():
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := server(t, tt.handler)
			c.client.Timeout = 50 * time.Millisecond
			if _, err := c.Breached(t.Context(), sample); err == nil {
				t.Error("Breached() error = nil, want an error")
			}
		})
	}
}

func TestUnreachable(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	if _, err := New(url).Breached(t.Context(), sample); err == nil {
		t.Error("Breached() with the API down: error = nil, want an error")
	}
}
