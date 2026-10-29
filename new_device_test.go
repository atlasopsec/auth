package auth

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

const newDeviceSubject = "New login to your Example account"

// newDeviceEmails returns how many new-device emails were sent to addr.
func (f fixture) newDeviceEmails(addr string) int {
	n := 0
	for _, m := range f.emailsTo(addr) {
		if m.Subject == newDeviceSubject {
			n++
		}
	}
	return n
}

// logInFrom logs in from ip with user agent ua, and returns how many
// new-device emails that sent.
func (f fixture) logInFrom(t *testing.T, ip, ua string) int {
	t.Helper()
	before := f.newDeviceEmails(testEmail)
	opts := []reqOpt{fromIP(ip)}
	if ua != "" {
		opts = append(opts, withHeader("User-Agent", ua))
	}
	if res := f.do(t, http.MethodPost, "/v1/sessions", credentials(testEmail, testPassword, "web"), opts...); res.status != http.StatusCreated {
		t.Fatalf("log in from %s: status %d, body %s", ip, res.status, res.body)
	}
	return f.newDeviceEmails(testEmail) - before
}

func TestNewDeviceEmail(t *testing.T) {
	t.Parallel()
	f := setup(t, Hooks{})
	f.signUp(t, testEmail)
	const firefox, safari = "Mozilla/5.0 Firefox/140.0", "Mozilla/5.0 Safari/605.1"

	steps := []struct {
		name    string
		advance time.Duration
		ip, ua  string
		want    int
	}{
		{"first login", 0, "192.0.2.10", firefox, 0},
		{"same device and network", 0, "192.0.2.10", firefox, 0},
		{"same /24", 0, "192.0.2.200", firefox, 0},
		{"another network", 0, "198.51.100.10", firefox, 1},
		{"another browser", 0, "192.0.2.10", safari, 1},
		{"no user agent", 0, "192.0.2.10", "", 1},
		{"no user agent again", 0, "192.0.2.10", "", 0},
		{"IPv6", 0, "2001:db8:1:1::1", firefox, 1},
		{"same /48", 0, "2001:db8:1:2::5", firefox, 0},
		{"another /48", 0, "2001:db8:2::1", firefox, 1},
		{"89 days later", 89 * day, "192.0.2.10", safari, 0},
		{"91 days after the last", 91 * day, "198.51.100.10", firefox, 1},
	}
	for _, s := range steps {
		f.clock.advance(s.advance)
		if got := f.logInFrom(t, s.ip, s.ua); got != s.want {
			t.Errorf("%s: %d new-device emails, want %d", s.name, got, s.want)
		}
	}

	var last string
	for _, m := range f.emailsTo(testEmail) {
		if m.Subject == newDeviceSubject {
			last = m.Text
		}
	}
	for _, want := range []string{"Device: " + firefox, "Time: " + f.clock.now().Format("2 January 2006 at 15:04 UTC"), testAppURL + "/reset-password"} {
		if !strings.Contains(last, want) {
			t.Errorf("email doesn't contain %q:\n%s", want, last)
		}
	}
}

func TestNewDeviceEmailTemplate(t *testing.T) {
	t.Parallel()
	var got []EmailData
	f := setupWith(t, Config{AllowUnverifiedLogin: true, Emails: Emails{NewDeviceLogin: func(d EmailData) (string, string, string) {
		got = append(got, d)
		return newDeviceSubject, "", ""
	}}})
	f.signUp(t, testEmail)
	f.logInFrom(t, "192.0.2.10", "")
	f.clock.advance(time.Minute)
	f.logInFrom(t, "198.51.100.10", strings.Repeat("é", 600))
	f.logInFrom(t, "203.0.113.10", "")
	f.sent()
	if len(got) != 2 {
		t.Fatalf("template called %d times, want 2", len(got))
	}
	if got[0].Device != strings.Repeat("é", 512) || !got[0].LoggedInAt.Equal(f.clock.now()) || got[0].AppURL != testAppURL {
		t.Errorf("template data = %+v", got[0])
	}
	if got[1].Device != "" {
		t.Errorf("no user agent: Device = %q", got[1].Device)
	}
	if _, text, _ := defaultNewDeviceLogin(got[1]); !strings.Contains(text, "Device: unknown") {
		t.Errorf("default email with no user agent:\n%s", text)
	}
}

func TestNewDeviceEmailDisabled(t *testing.T) {
	t.Parallel()
	f := setupWith(t, Config{AllowUnverifiedLogin: true, DisableNewDeviceEmails: true})
	f.signUp(t, testEmail)
	f.logInFrom(t, "192.0.2.10", "")
	if got := f.logInFrom(t, "198.51.100.10", "Other/1.0"); got != 0 {
		t.Errorf("%d new-device emails with them turned off", got)
	}
}

func TestNewDeviceEmailForOAuth(t *testing.T) {
	t.Parallel()
	f := setupOAuth(t, Config{AllowUnverifiedLogin: true})
	loginOf(t, f.googleSignIn(t, ada("g-1")))
	// googleSignIn is always from the fixture's default address, so a
	// second sign-in from it is a known device.
	loginOf(t, f.googleSignIn(t, ada("g-1")))
	if got := f.newDeviceEmails(testEmail); got != 0 {
		t.Fatalf("%d new-device emails for a known device", got)
	}
	if got := f.logInFromGoogle(t, "198.51.100.10"); got != 1 {
		t.Errorf("Google sign-in from a new network: %d new-device emails, want 1", got)
	}
}

// logInFromGoogle signs in with Google from ip, and returns how many
// new-device emails that sent.
func (f oauthFixture) logInFromGoogle(t *testing.T, ip string) int {
	t.Helper()
	before := f.newDeviceEmails(testEmail)
	authURL, verifier := f.startFlow(t, providerGoogle, "web")
	code, state := f.google.Authorize(authURL, ada("g-1"))
	loginOf(t, f.do(t, http.MethodPost, "/v1/oauth-flows/complete", completeBody(state, code, verifier), fromIP(ip)))
	return f.newDeviceEmails(testEmail) - before
}
