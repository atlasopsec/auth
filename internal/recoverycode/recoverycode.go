// Package recoverycode makes and checks 2FA recovery codes: single-use
// codes a user keeps for when they lose their authenticator.
//
// Each code is 16 random base32 characters (80 bits), shown in groups of
// four. Codes are stored as SHA-256 hashes. That's enough: slow hashes
// like argon2 exist to resist guessing passwords that people choose, and
// an 80-bit random code can't be guessed either way (docs/api.md §8).
package recoverycode

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"strings"
)

// Count is how many codes a user gets.
const Count = 10

const (
	length    = 16
	groupSize = 4
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// New returns Count new codes, formatted for display (XXXX-XXXX-XXXX-XXXX).
func New() []string {
	codes := make([]string, Count)
	for i := range codes {
		b := make([]byte, length*5/8)
		// crypto/rand.Read never returns an error; it crashes the program
		// if the system's randomness source fails.
		_, _ = rand.Read(b)
		s := b32.EncodeToString(b)
		var parts []string
		for j := 0; j < len(s); j += groupSize {
			parts = append(parts, s[j:j+groupSize])
		}
		codes[i] = strings.Join(parts, "-")
	}
	return codes
}

// Normalize returns code as stored before hashing: uppercase, without
// dashes or spaces, so users can type it loosely. ok is false if it can't
// be a recovery code.
func Normalize(code string) (normalized string, ok bool) {
	s := strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(code))
	if len(s) != length {
		return "", false
	}
	if _, err := b32.DecodeString(s); err != nil {
		return "", false
	}
	return s, true
}

// Hash returns the hash to store for a normalized code.
func Hash(normalized string) []byte {
	sum := sha256.Sum256([]byte(normalized))
	return sum[:]
}
