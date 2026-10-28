package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
)

func TestDecode(t *testing.T) {
	t.Parallel()
	type body struct {
		Name string `json:"name"`
	}
	tests := []struct {
		name    string
		body    string
		want    body
		wantErr error
	}{
		{name: "valid", body: `{"name":"ada"}`, want: body{Name: "ada"}},
		{name: "trailing whitespace", body: "{\"name\":\"ada\"}\n", want: body{Name: "ada"}},
		{name: "unknown field", body: `{"name":"ada","nam":"x"}`, wantErr: ErrBadRequest},
		{name: "wrong type", body: `{"name":1}`, wantErr: ErrBadRequest},
		{name: "malformed", body: `{"name":`, wantErr: ErrBadRequest},
		{name: "empty", body: ``, wantErr: ErrBadRequest},
		{name: "two objects", body: `{"name":"a"}{"name":"b"}`, wantErr: ErrBadRequest},
		{name: "trailing garbage", body: `{"name":"a"} x`, wantErr: ErrBadRequest},
		{name: "not an object", body: `["ada"]`, wantErr: ErrBadRequest},
		{name: "too large", body: `{"name":"` + strings.Repeat("a", MaxBodySize) + `"}`, wantErr: ErrTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader(tt.body))
			var got body
			err := Decode(httptest.NewRecorder(), r, &got)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Decode() error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr == nil {
				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Errorf("Decode() (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestWriteDecodeError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		err        error
		wantStatus int
		wantCode   string
	}{
		{ErrBadRequest, http.StatusBadRequest, "bad_request"},
		{ErrTooLarge, http.StatusRequestEntityTooLarge, "payload_too_large"},
	}
	for _, tt := range tests {
		w := httptest.NewRecorder()
		WriteDecodeError(w, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", nil), tt.err)
		if w.Code != tt.wantStatus {
			t.Errorf("WriteDecodeError(%v) status = %d, want %d", tt.err, w.Code, tt.wantStatus)
		}
		var b errorBody
		if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil || b.Error.Code != tt.wantCode {
			t.Errorf("WriteDecodeError(%v) code = %q (err = %v), want %q", tt.err, b.Error.Code, err, tt.wantCode)
		}
	}
}

func TestWriteErrorFormat(t *testing.T) {
	t.Parallel()
	h := WithRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		WriteError(w, r, http.StatusUnprocessableEntity, "validation_failed", "Some fields are invalid.",
			[]FieldError{{Field: "email", Code: "invalid_format", Message: "Enter a valid email address."}})
	}))
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	r.Header.Set(RequestIDHeader, "req-123")
	h.ServeHTTP(w, r)

	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	want := `{"error":{"code":"validation_failed","message":"Some fields are invalid.","request_id":"req-123",` +
		`"details":[{"field":"email","code":"invalid_format","message":"Enter a valid email address."}]}}` + "\n"
	if diff := cmp.Diff(want, w.Body.String()); diff != "" {
		t.Errorf("body (-want +got):\n%s", diff)
	}

	// Without details, the field is still present, as null.
	w = httptest.NewRecorder()
	WriteError(w, r, http.StatusNotFound, "not_found", "Not found.", nil)
	if !strings.Contains(w.Body.String(), `"details":null`) {
		t.Errorf("body = %s, want details present as null", w.Body.String())
	}
}

func TestWithRequestID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		incoming string
		preset   string // set on the response by earlier middleware
		want     string // "" means a new UUIDv7
	}{
		{name: "none", want: ""},
		{name: "reuses incoming", incoming: "abc-123_X.y", want: "abc-123_X.y"},
		{name: "prefers response header", incoming: "from-client", preset: "from-project", want: "from-project"},
		{name: "rejects unsafe characters", incoming: "abc\ninjected", want: ""},
		{name: "rejects spaces", incoming: "a b", want: ""},
		{name: "rejects too long", incoming: strings.Repeat("a", maxRequestID+1), want: ""},
		{name: "accepts max length", incoming: strings.Repeat("a", maxRequestID), want: strings.Repeat("a", maxRequestID)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var inHandler string
			h := WithRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				inHandler = RequestIDFrom(r.Context())
			}))
			w := httptest.NewRecorder()
			if tt.preset != "" {
				w.Header().Set(RequestIDHeader, tt.preset)
			}
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			if tt.incoming != "" {
				r.Header.Set(RequestIDHeader, tt.incoming)
			}
			h.ServeHTTP(w, r)

			got := w.Header().Get(RequestIDHeader)
			if got != inHandler {
				t.Errorf("header %q != context %q", got, inHandler)
			}
			if tt.want != "" {
				if got != tt.want {
					t.Errorf("request ID = %q, want %q", got, tt.want)
				}
				return
			}
			if id, err := uuid.Parse(got); err != nil || id.Version() != 7 {
				t.Errorf("request ID = %q, want a new UUIDv7", got)
			}
		})
	}
}

func TestWithRequestIDNested(t *testing.T) {
	t.Parallel()
	var inner string
	h := WithRequestID(WithRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inner = RequestIDFrom(r.Context())
	})))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	if inner == "" || inner != w.Header().Get(RequestIDHeader) {
		t.Errorf("nested request ID = %q, header = %q; want the same ID", inner, w.Header().Get(RequestIDHeader))
	}
}

func TestClient(t *testing.T) {
	t.Parallel()
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("fd00::/8")}
	tests := []struct {
		name   string
		remote string
		xff    []string
		fwdUA  string
		ua     string
		wantIP string // "" means nil
		wantUA string
	}{
		{
			name: "direct client ignores forwarded headers", remote: "203.0.113.7:4000",
			xff: []string{"198.51.100.1"}, fwdUA: "Spoofed/1.0", ua: "App/1.0",
			wantIP: "203.0.113.7", wantUA: "App/1.0",
		},
		{
			name: "trusted proxy", remote: "10.0.0.5:4000",
			xff: []string{"203.0.113.7"}, fwdUA: "Browser/1.0", ua: "node",
			wantIP: "203.0.113.7", wantUA: "Browser/1.0",
		},
		{
			name: "client-supplied entries on the left are ignored", remote: "10.0.0.5:4000",
			xff:    []string{"1.1.1.1, 203.0.113.7, 10.0.0.9"},
			wantIP: "203.0.113.7",
		},
		{
			name: "multiple header lines", remote: "10.0.0.5:4000",
			xff:    []string{"1.1.1.1", "203.0.113.7, 10.0.0.9"},
			wantIP: "203.0.113.7",
		},
		{
			name: "trusted proxy without forwarded headers", remote: "10.0.0.5:4000", ua: "node",
			wantIP: "10.0.0.5", wantUA: "node",
		},
		{
			name: "malformed entry stops the walk", remote: "10.0.0.5:4000",
			xff:    []string{"203.0.113.7, garbage"},
			wantIP: "10.0.0.5",
		},
		{
			name: "IPv6", remote: "[fd00::1]:4000",
			xff:    []string{"2001:db8::7"},
			wantIP: "2001:db8::7",
		},
		{
			name: "IPv4-mapped peer", remote: "[::ffff:10.0.0.5]:4000",
			xff:    []string{"203.0.113.7"},
			wantIP: "203.0.113.7",
		},
		{
			name: "unparseable remote address", remote: "pipe", ua: "App/1.0",
			wantIP: "", wantUA: "App/1.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			r.RemoteAddr = tt.remote
			for _, v := range tt.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			if tt.fwdUA != "" {
				r.Header.Set(ForwardedUserAgentHeader, tt.fwdUA)
			}
			r.Header.Set("User-Agent", tt.ua)

			ip, ua := Client(r, trusted)
			var gotIP string
			if ip != nil {
				gotIP = ip.String()
			}
			if gotIP != tt.wantIP || ua != tt.wantUA {
				t.Errorf("Client() = (%q, %q), want (%q, %q)", gotIP, ua, tt.wantIP, tt.wantUA)
			}
		})
	}
}
