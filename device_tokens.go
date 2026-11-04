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
// issued for. It holds when it was issued, a random ID, which names its
// own failure counts and stays the same from one login to the next, and
// whether a 2FA code was entered on the device. Nothing is stored: it
// proves only that this device once knew the password, and perhaps a
// code, so it lets nobody in by itself.
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

// device is what a valid device token says about the browser or app that
// sent it.
type device struct {
	// key names the device's own failure counts, or is "" without a valid
	// token.
	key string
	id  []byte
	// twoFactor reports whether a 2FA code was entered on this device, so
	// that it, and not only the password, has been proved here. Only then
	// do wrong 2FA codes from it count toward a limit of its own (see
	// twoFactorScope): a device token comes with the password alone, which
	// someone guessing codes already has, so otherwise each new token would
	// be a new limit.
	twoFactor bool
}

// The payload is when the token was issued (8 bytes), the device ID, and
// a flags byte. Tokens from before 2FA was recorded have no flags byte.
const (
	devicePayloadSize       = 8 + deviceIDSize + 1
	legacyDevicePayloadSize = 8 + deviceIDSize
	deviceFlagTwoFactor     = 1
)

// newDeviceToken returns a device token for email. It keeps d's ID if d is
// a valid device, so a device keeps the same failure counts from one
// login to the next, and is a new device otherwise. twoFactor records that
// a 2FA code was entered on it.
func (a *Auth) newDeviceToken(email string, d device, twoFactor bool) string {
	payload := make([]byte, devicePayloadSize)
	binary.BigEndian.PutUint64(payload, uint64(a.now().Unix())) //nolint:gosec // G115: a Unix time now is positive.
	if d.key != "" {
		copy(payload[8:8+deviceIDSize], d.id)
	} else {
		_, _ = rand.Read(payload[8 : 8+deviceIDSize]) // crypto/rand.Read never fails.
	}
	if twoFactor {
		payload[8+deviceIDSize] = deviceFlagTwoFactor
	}
	return base64.RawURLEncoding.EncodeToString(a.box.Seal(payload, deviceTokenData(email)))
}

// parseDevice reads tok, if it's a device token for email that hasn't
// expired. Otherwise the device has no key.
func (a *Auth) parseDevice(tok, email string) device {
	if tok == "" || len(tok) > maxDeviceTokenLength {
		return device{}
	}
	sealed, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		return device{}
	}
	payload, err := a.box.Open(sealed, deviceTokenData(email))
	if err != nil || len(payload) != devicePayloadSize && len(payload) != legacyDevicePayloadSize {
		return device{}
	}
	issued := time.Unix(int64(binary.BigEndian.Uint64(payload)), 0) //nolint:gosec // G115: written from a Unix time by newDeviceToken, and sealed.
	// A minute's leeway for clocks that differ between API instances.
	if age := a.now().Sub(issued); age < -time.Minute || age >= deviceTokenLifetime {
		return device{}
	}
	id := payload[8 : 8+deviceIDSize]
	return device{
		key:       "device:" + hex.EncodeToString(id),
		id:        id,
		twoFactor: len(payload) == devicePayloadSize && payload[8+deviceIDSize]&deviceFlagTwoFactor != 0,
	}
}

// twoFactorScope returns the key wrong 2FA codes from d count under: its
// own, if a code was entered on it before, so that someone who has the
// password and guesses codes elsewhere can't pause 2FA for it. Otherwise
// "", the account-wide count.
func (d device) twoFactorScope() string {
	if d.twoFactor {
		return d.key
	}
	return ""
}
