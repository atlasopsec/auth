// Package totp implements time-based one-time passwords (RFC 6238), the
// six-digit codes from authenticator apps.
//
// It uses the settings every authenticator app supports: HMAC-SHA1, six
// digits, and 30-second steps. It's implemented here rather than imported,
// as design.md decision 5 records: it's short, and it's tested against the
// RFC's own test vectors.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // G505: RFC 6238 TOTP, as authenticator apps implement it, uses HMAC-SHA1, which is still sound as a MAC.
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"time"
)

// Settings shared with authenticator apps.
const (
	Digits     = 6
	Period     = 30 * time.Second
	SecretSize = 20 // 160 bits, RFC 4226's recommendation
)

// Drift is how many steps either side of the current one a code is
// accepted for, to allow for clocks that are slightly off.
const Drift = 1

// NewSecret returns a new random secret.
func NewSecret() []byte {
	b := make([]byte, SecretSize)
	// crypto/rand.Read never returns an error; it crashes the program if
	// the system's randomness source fails.
	_, _ = rand.Read(b)
	return b
}

// Step returns the time step t falls in.
func Step(t time.Time) int64 {
	return t.Unix() / int64(Period/time.Second)
}

// Code returns the code for secret at step.
func Code(secret []byte, step int64) string {
	return hotp(secret, step, Digits)
}

// hotp is RFC 4226's HOTP: HMAC-SHA1 of the counter, dynamically truncated
// to digits decimal digits.
func hotp(secret []byte, counter int64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter)) //nolint:gosec // G115: counters are time steps, never negative; Step counts from 1970.
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, v%mod)
}

// Verify checks code against secret at now, allowing Drift steps either
// way. Steps at or before lastUsed are refused, so a code can't be used
// twice. It returns the step the code matched, to record as the new
// lastUsed.
func Verify(secret []byte, code string, now time.Time, lastUsed int64) (step int64, ok bool) {
	if len(code) != Digits {
		return 0, false
	}
	current := Step(now)
	// Check every candidate, so the time taken doesn't depend on which one
	// matched.
	for s := current - Drift; s <= current+Drift; s++ {
		match := subtle.ConstantTimeCompare([]byte(Code(secret, s)), []byte(code)) == 1
		if match && s > lastUsed && !ok {
			step, ok = s, true
		}
	}
	return step, ok
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// EncodeSecret returns the secret as authenticator apps expect it typed
// in: unpadded base32.
func EncodeSecret(secret []byte) string {
	return b32.EncodeToString(secret)
}

// URI returns the otpauth:// URI that authenticator apps read from a QR
// code. issuer is the app's name; account is usually the user's email.
func URI(issuer, account string, secret []byte) string {
	q := url.Values{}
	q.Set("secret", EncodeSecret(secret))
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(Digits))
	q.Set("period", fmt.Sprint(int(Period/time.Second)))
	u := url.URL{Scheme: "otpauth", Host: "totp", Path: "/" + issuer + ":" + account, RawQuery: q.Encode()}
	return u.String()
}
