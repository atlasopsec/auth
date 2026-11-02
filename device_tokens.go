package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"time"

	"github.com/atlasopsec/auth/internal/ratelimit"
)

// Device tokens keep the account-wide login delay from locking the owner
// out (docs/api.md §10). The delay counts wrong passwords for an email
// from everywhere, so anyone could keep it running. A browser or app that
// has logged in with the password before carries a device token, and is
// held instead to a delay of its own, which only wrong passwords sent with
// that token count toward.
//
// A token is sealed with Config.EncryptionKey, bound to the email it was
// issued for. It holds when it was issued and a random ID, which names
// its own failure count. Nothing is stored: it proves only that this
// device once knew the password, so it lets nobody in by itself.
const (
	// deviceTokenLifetime is how long a device token works. Every login
	// with the password issues a new one.
	deviceTokenLifetime = 365 * 24 * time.Hour
	// deviceThreshold counts failures sent with one device token, from
	// any IP, so a stolen token isn't a way around the delay.
	deviceThreshold = accountIPThreshold
	// maxDeviceTokenLength is far longer than a real token, so anything
	// longer is refused without decoding it.
	maxDeviceTokenLength = 200
	deviceIDSize         = 16
)

// deviceTokenData is what a device token is bound to: the email it was
// issued for, hashed as the login failure keys are.
func deviceTokenData(email string) []byte {
	return []byte("device-token:" + ratelimit.Email(email))
}

// newDeviceToken returns a device token for email.
func (a *Auth) newDeviceToken(email string) string {
	payload := make([]byte, 8+deviceIDSize)
	binary.BigEndian.PutUint64(payload, uint64(a.now().Unix())) //nolint:gosec // G115: a Unix time now is positive.
	_, _ = rand.Read(payload[8:])                               // crypto/rand.Read never fails.
	return base64.RawURLEncoding.EncodeToString(a.box.Seal(payload, deviceTokenData(email)))
}

// deviceKey returns the login failure key for tok, if it's a device token
// for email that hasn't expired, or "".
func (a *Auth) deviceKey(tok, email string) string {
	if tok == "" || len(tok) > maxDeviceTokenLength {
		return ""
	}
	sealed, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		return ""
	}
	payload, err := a.box.Open(sealed, deviceTokenData(email))
	if err != nil || len(payload) != 8+deviceIDSize {
		return ""
	}
	issued := time.Unix(int64(binary.BigEndian.Uint64(payload)), 0) //nolint:gosec // G115: written from a Unix time by newDeviceToken, and sealed.
	// A minute's leeway for clocks that differ between API instances.
	if age := a.now().Sub(issued); age < -time.Minute || age >= deviceTokenLifetime {
		return ""
	}
	return "device:" + hex.EncodeToString(payload[8:])
}
