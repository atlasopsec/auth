// Package apikey makes and reads API keys: a project's prefix, an
// underscore, and a random secret from internal/token, such as
// "example_q3V…". The prefix tells a key apart from a session token, which
// has no prefix and is shorter, and lets secret scanners find a key that
// leaks.
//
// Like a session token, a key is given to its owner once. Only its
// SHA-256 hash is stored.
package apikey

import (
	"regexp"
	"strings"

	"github.com/atlasopsec/auth/internal/token"
)

// HintLength is how many characters of the secret are kept in plain text
// to tell keys apart in a list.
const HintLength = 6

// validPrefix is the form of Config.APIKeyPrefix: lowercase letters,
// digits, and underscores, starting with a letter, 3 to 20 characters.
var validPrefix = regexp.MustCompile(`^[a-z][a-z0-9_]{2,19}$`)

// ValidPrefix reports whether prefix can start keys.
func ValidPrefix(prefix string) bool {
	return validPrefix.MatchString(prefix)
}

// New returns a new key starting with prefix, the hash to store, and its
// hint.
func New(prefix string) (key string, hash []byte, hint string) {
	secret := token.New()
	key = prefix + "_" + secret
	return key, token.Hash(key), secret[:HintLength]
}

// Hash returns the hash to look a key up by, and false if s doesn't have
// the exact shape of a key from New with prefix. A session token never
// has that shape: it's exactly as long as a key's secret alone.
func Hash(prefix, s string) ([]byte, bool) {
	secret, ok := strings.CutPrefix(s, prefix+"_")
	if !ok || prefix == "" || !token.Valid(secret) {
		return nil, false
	}
	return token.Hash(s), true
}
