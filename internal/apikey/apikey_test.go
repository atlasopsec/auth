package apikey

import (
	"bytes"
	"strings"
	"testing"

	"github.com/atlasopsec/auth/internal/token"
)

func TestNew(t *testing.T) {
	t.Parallel()
	key, hash, hint := New("example")
	if !strings.HasPrefix(key, "example_") {
		t.Fatalf("key %q doesn't start with the prefix", key)
	}
	secret := strings.TrimPrefix(key, "example_")
	if !token.Valid(secret) {
		t.Errorf("secret %q isn't a token", secret)
	}
	if hint != secret[:HintLength] {
		t.Errorf("hint = %q, want the first %d characters of %q", hint, HintLength, secret)
	}
	got, ok := Hash("example", key)
	if !ok || !bytes.Equal(got, hash) {
		t.Errorf("Hash(New()) = %x, %v; want %x, true", got, ok, hash)
	}
	if again, _, _ := New("example"); again == key {
		t.Error("two keys are the same")
	}
}

func TestHashRefusesWhatIsntAKey(t *testing.T) {
	t.Parallel()
	key, _, _ := New("example")
	secret := strings.TrimPrefix(key, "example_")
	for name, s := range map[string]string{
		"session token":  token.New(),
		"other prefix":   "other_" + secret,
		"no separator":   "example" + secret,
		"short secret":   "example_" + secret[:42],
		"long secret":    "example_" + secret + "A",
		"bad characters": "example_" + strings.Repeat("!", len(secret)),
		"prefix only":    "example_",
		"empty":          "",
	} {
		if _, ok := Hash("example", s); ok {
			t.Errorf("%s: Hash(%q) ok = true", name, s)
		}
	}
	if _, ok := Hash("", "_"+secret); ok {
		t.Error("Hash with no prefix configured: ok = true")
	}
}

func TestValidPrefix(t *testing.T) {
	t.Parallel()
	for prefix, want := range map[string]bool{
		"example":               true,
		"acme_live":             true,
		"ab1":                   true,
		"ab":                    false,
		"Example":               false,
		"1abc":                  false,
		"_abc":                  false,
		"ab-c":                  false,
		"abcdefghijklmnopqrstu": false,
		"":                      false,
	} {
		if got := ValidPrefix(prefix); got != want {
			t.Errorf("ValidPrefix(%q) = %v, want %v", prefix, got, want)
		}
	}
}
