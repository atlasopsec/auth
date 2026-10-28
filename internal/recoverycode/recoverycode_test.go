package recoverycode

import (
	"regexp"
	"testing"
)

var format = regexp.MustCompile(`^[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}$`)

func TestNew(t *testing.T) {
	t.Parallel()
	codes := New()
	if len(codes) != Count {
		t.Fatalf("got %d codes, want %d", len(codes), Count)
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if !format.MatchString(c) {
			t.Errorf("code %q isn't XXXX-XXXX-XXXX-XXXX base32", c)
		}
		if seen[c] {
			t.Errorf("duplicate code %q", c)
		}
		seen[c] = true
		if _, ok := Normalize(c); !ok {
			t.Errorf("Normalize(%q) failed", c)
		}
	}
}

func TestNormalize(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"ABCD-EFGH-IJKL-MNOP", "ABCDEFGHIJKLMNOP", true},
		{"abcd efgh ijkl mnop", "ABCDEFGHIJKLMNOP", true},
		{"abcdefghijklmnop", "ABCDEFGHIJKLMNOP", true},
		{"ABCD-EFGH-IJKL-MNO", "", false},   // too short
		{"ABCD-EFGH-IJKL-MNOPQ", "", false}, // too long
		{"ABCD-EFGH-IJKL-MN0P", "", false},  // 0 isn't base32
		{"123456", "", false},               // a TOTP code
		{"", "", false},
	}
	for _, tt := range tests {
		got, ok := Normalize(tt.in)
		if got != tt.want || ok != tt.ok {
			t.Errorf("Normalize(%q) = (%q, %v), want (%q, %v)", tt.in, got, ok, tt.want, tt.ok)
		}
	}
	a, _ := Normalize("abcd-efgh-ijkl-mnop")
	b, _ := Normalize("ABCDEFGHIJKLMNOP")
	if string(Hash(a)) != string(Hash(b)) {
		t.Error("the same code typed differently hashes differently")
	}
}
