package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/atlasopsec/auth/internal/oauth/oauthtest"
)

// deviceTokenOf returns the device_token in a login or challenge response.
func deviceTokenOf(t *testing.T, res response) *string {
	t.Helper()
	var body struct {
		DeviceToken *string `json:"device_token"`
	}
	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(res.body, &raw); err != nil {
		t.Fatalf("decoding %s: %v", res.body, err)
	}
	if _, ok := raw["device_token"]; !ok {
		t.Fatalf("no device_token field in %s", res.body)
	}
	if err := json.Unmarshal(res.body, &body); err != nil {
		t.Fatal(err)
	}
	return body.DeviceToken
}

func (f fixture) logInWithDevice(t *testing.T, email, pw, ip, device string) response {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"email": email, "password": pw, "client": "web", "device_token": device})
	return f.do(t, http.MethodPost, "/v1/sessions", string(b), fromIP(ip))
}

// slowDownAccount sends enough wrong passwords for email, from many IPs,
// that logins without a device token must wait the longest delay.
func (f fixture) slowDownAccount(t *testing.T, email string) {
	t.Helper()
	// Each from a new IP, so only the account-wide count is reached.
	for failures := 0; failures < accountThreshold+3; {
		res := f.tryLogIn(t, email, "not my password", nextTestIP())
		switch res.status {
		case http.StatusUnauthorized:
			failures++
		case http.StatusTooManyRequests:
			secs, _ := strconv.Atoi(res.header.Get("Retry-After"))
			f.clock.advance(time.Duration(secs) * time.Second)
		default:
			t.Fatalf("wrong password: status %d, body %s", res.status, res.body)
		}
	}
	wantError(t, "without a device token", f.tryLogIn(t, email, testPassword, nextTestIP()), 429, "rate_limited")
}

// TestDeviceTokenAvoidsAccountDelay is the lockout case: wrong passwords
// sent for Ada's email from many IPs make every login for it wait, but
// not Ada's own browser, which logged in before.
func TestDeviceTokenAvoidsAccountDelay(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	f.signUp(t, testEmail)
	home := nextTestIP()
	device := deviceTokenOf(t, f.tryLogIn(t, testEmail, testPassword, home))
	if device == nil || *device == "" {
		t.Fatal("no device token after logging in with the password")
	}

	f.slowDownAccount(t, testEmail)

	res := f.logInWithDevice(t, testEmail, testPassword, home, *device)
	if res.status != http.StatusCreated {
		t.Fatalf("with the device token: status %d, body %s; want 201", res.status, res.body)
	}
	if next := deviceTokenOf(t, res); next == nil || *next == *device {
		t.Error("logging in didn't issue a new device token")
	}
	// From a new network too: the token is the device's, not the IP's.
	if res := f.logInWithDevice(t, testEmail, testPassword, nextTestIP(), *device); res.status != http.StatusCreated {
		t.Errorf("with the device token from another IP: status %d, body %s; want 201", res.status, res.body)
	}
}

// TestDeviceTokenHasItsOwnLimit checks a device token can't be used to
// guess passwords: wrong passwords sent with it, from any IP, slow it down
// as wrong passwords from one IP do.
func TestDeviceTokenHasItsOwnLimit(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	f.signUp(t, testEmail)
	device := *deviceTokenOf(t, f.tryLogIn(t, testEmail, testPassword, nextTestIP()))

	for i := range deviceThreshold + 1 {
		wantError(t, fmt.Sprintf("wrong password %d", i+1), f.logInWithDevice(t, testEmail, "not my password", nextTestIP(), device), 401, "invalid_credentials")
	}
	wantRetryAfter(t, "with the device token from yet another IP", f.logInWithDevice(t, testEmail, testPassword, nextTestIP(), device), 1)

	// Other devices aren't slowed by it.
	other := *deviceTokenOf(t, f.tryLogIn(t, testEmail, testPassword, nextTestIP()))
	if res := f.logInWithDevice(t, testEmail, testPassword, nextTestIP(), other); res.status != http.StatusCreated {
		t.Errorf("another device: status %d, body %s", res.status, res.body)
	}
}

// TestDeviceTokenRejects checks that tokens that don't belong to this
// email, or have expired, or were tampered with, are ignored: the login is
// held to the account-wide delay as if it had none.
func TestDeviceTokenRejects(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	f.signUp(t, testEmail)
	f.signUp(t, "grace@example.com")
	ip := nextTestIP()
	graces := *deviceTokenOf(t, f.tryLogIn(t, "grace@example.com", testPassword, ip))
	expired := *deviceTokenOf(t, f.tryLogIn(t, testEmail, testPassword, ip))
	f.clock.advance(deviceTokenLifetime)
	current := *deviceTokenOf(t, f.tryLogIn(t, testEmail, testPassword, ip))
	tampered := []byte(current)
	tampered[len(tampered)/2] ^= 1

	f.slowDownAccount(t, testEmail)
	for name, tok := range map[string]string{
		"another email's": graces,
		"expired":         expired,
		"tampered":        string(tampered),
		"not a token":     "not-a-device-token",
		"far too long":    string(make([]byte, 1000)),
	} {
		wantError(t, name, f.logInWithDevice(t, testEmail, testPassword, nextTestIP(), tok), 429, "rate_limited")
	}
}

// TestDeviceTokenOnlyFromPassword checks which logins return a device
// token: a correct password does, including when 2FA follows, and other
// ways to log in answer null.
func TestDeviceTokenOnlyFromPassword(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{AllowUnverifiedLogin: true})
	l := f.signUp(t, testEmail)
	if tok := deviceTokenOf(t, f.tryLogIn(t, testEmail, testPassword, nextTestIP())); tok == nil {
		t.Error("password login: device_token is null")
	}
	secret, _ := f.enableTwoFactor(t, l.Token)
	res := f.tryLogIn(t, testEmail, testPassword, nextTestIP())
	if res.status != http.StatusOK || deviceTokenOf(t, res) == nil {
		t.Errorf("password login with 2FA: status %d, body %s; want a challenge with a device token", res.status, res.body)
	}
	if tok := deviceTokenOf(t, f.verify(t, challengeIn(t, res), f.code(secret))); tok != nil {
		t.Error("finishing 2FA: device_token isn't null")
	}

	g := f.googleSignIn(t, oauthtest.GoogleUser{Subject: "g-2", Email: "grace@example.com", EmailVerified: true})
	if tok := deviceTokenOf(t, g); tok != nil {
		t.Errorf("Google sign-in: device_token = %q, want null", *tok)
	}
	if res := f.tryLogIn(t, testEmail, "not my password", nextTestIP()); bytes.Contains(res.body, []byte("device_token")) {
		t.Errorf("a wrong password returned a device token: %s", res.body)
	}
}
