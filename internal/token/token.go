// Package token generates and hashes the random secrets used for sessions,
// email verification, and password resets.
//
// A token is handed to the client exactly once. Only its SHA-256 hash is
// stored, so a database leak doesn't expose working tokens.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// Size is the number of random bytes in a token.
const Size = 32

// encodedLen is the length of a token as returned by New: 32 bytes in
// unpadded base64url.
var encodedLen = base64.RawURLEncoding.EncodedLen(Size)

// New returns a new random token: Size bytes from crypto/rand, encoded as
// unpadded base64url so it's safe in headers, cookies, and URLs.
func New() string {
	b := make([]byte, Size)
	// crypto/rand.Read never returns an error; it crashes the program if the
	// system's randomness source fails, which is the only safe outcome.
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Valid reports whether s has the exact shape of a token from New. It lets
// callers reject garbage input before doing a database lookup.
func Valid(s string) bool {
	if len(s) != encodedLen {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(b) == Size
}

// Hash returns the SHA-256 hash of a token, for storage and lookup.
func Hash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// Equal reports whether two hashes are equal, in constant time.
func Equal(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
