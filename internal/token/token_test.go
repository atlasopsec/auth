package token

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	t.Parallel()

	tok := New()
	if len(tok) != 43 {
		t.Fatalf("len(New()) = %d, want 43", len(tok))
	}
	b, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		t.Fatalf("New() = %q is not unpadded base64url: %v", tok, err)
	}
	if len(b) != Size {
		t.Fatalf("New() decodes to %d bytes, want %d", len(b), Size)
	}
	if !Valid(tok) {
		t.Fatalf("Valid(New()) = false, want true")
	}
}

func TestNewIsUnique(t *testing.T) {
	t.Parallel()

	const n = 10000
	seen := make(map[string]bool, n)
	for range n {
		tok := New()
		if seen[tok] {
			t.Fatalf("New() returned a duplicate token after %d calls", len(seen))
		}
		seen[tok] = true
	}
}

func TestValid(t *testing.T) {
	t.Parallel()

	good := New()
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"token from New", good, true},
		{"empty", "", false},
		{"one character short", good[:42], false},
		{"one character long", good + "A", false},
		{"padded base64", base64.URLEncoding.EncodeToString(make([]byte, Size)), false},
		{"standard base64 alphabet", strings.Repeat("+", 43), false},
		{"invalid characters", strings.Repeat("!", 43), false},
		{"whitespace", " " + good[1:], false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := Valid(tt.input); got != tt.want {
				t.Errorf("Valid(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestHash(t *testing.T) {
	t.Parallel()

	a, b := New(), New()

	if got := len(Hash(a)); got != 32 {
		t.Fatalf("len(Hash()) = %d, want 32", got)
	}
	if !Equal(Hash(a), Hash(a)) {
		t.Errorf("Hash is not deterministic for the same token")
	}
	if Equal(Hash(a), Hash(b)) {
		t.Errorf("Hash(a) == Hash(b) for different tokens")
	}
	if Equal(Hash(a), []byte(a)) {
		t.Errorf("Hash(a) equals the raw token")
	}
}

func TestHashKnownValue(t *testing.T) {
	t.Parallel()

	// SHA-256("abc"), from FIPS 180-2.
	want := "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"
	if got := base64.RawURLEncoding.EncodeToString(Hash("abc")); got != want {
		t.Errorf("Hash(\"abc\") = %s, want %s", got, want)
	}
}

func TestEqual(t *testing.T) {
	t.Parallel()

	h := Hash(New())
	other := Hash(New())
	tests := []struct {
		name string
		a, b []byte
		want bool
	}{
		{"same hash", h, h, true},
		{"copy of hash", h, append([]byte(nil), h...), true},
		{"different hash", h, other, false},
		{"prefix", h, h[:31], false},
		{"empty vs hash", nil, h, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := Equal(tt.a, tt.b); got != tt.want {
				t.Errorf("Equal() = %v, want %v", got, tt.want)
			}
		})
	}
}
