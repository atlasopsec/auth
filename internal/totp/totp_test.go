package totp

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

// rfcSecret is the SHA-1 secret from RFC 6238 Appendix B.
var rfcSecret = []byte("12345678901234567890")

// TestRFC6238Vectors checks the RFC's own test values (Appendix B, SHA-1).
func TestRFC6238Vectors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		unix int64
		want string // 8 digits, as the RFC lists them
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}
	for _, tt := range tests {
		step := Step(time.Unix(tt.unix, 0))
		if got := hotp(rfcSecret, step, 8); got != tt.want {
			t.Errorf("T=%d: 8-digit code = %s, want %s", tt.unix, got, tt.want)
		}
		// The 6-digit code apps show is the last six digits.
		if got := Code(rfcSecret, step); got != tt.want[2:] {
			t.Errorf("T=%d: Code() = %s, want %s", tt.unix, got, tt.want[2:])
		}
	}
}

func TestVerify(t *testing.T) {
	t.Parallel()
	now := time.Unix(1234567890, 0)
	step := Step(now)
	tests := []struct {
		name     string
		code     string
		lastUsed int64
		wantStep int64
		wantOK   bool
	}{
		{"current step", Code(rfcSecret, step), 0, step, true},
		{"one step behind", Code(rfcSecret, step-1), 0, step - 1, true},
		{"one step ahead", Code(rfcSecret, step+1), 0, step + 1, true},
		{"two steps behind", Code(rfcSecret, step-2), 0, 0, false},
		{"two steps ahead", Code(rfcSecret, step+2), 0, 0, false},
		{"already used", Code(rfcSecret, step), step, 0, false},
		{"older than the last used", Code(rfcSecret, step-1), step, 0, false},
		{"after an older use", Code(rfcSecret, step), step - 1, step, true},
		{"wrong code", "000000", 0, 0, false},
		{"too short", Code(rfcSecret, step)[:5], 0, 0, false},
		{"too long", Code(rfcSecret, step) + "0", 0, 0, false},
		{"empty", "", 0, 0, false},
	}
	for _, tt := range tests {
		gotStep, ok := Verify(rfcSecret, tt.code, now, tt.lastUsed)
		if ok != tt.wantOK || gotStep != tt.wantStep {
			t.Errorf("%s: Verify() = (%d, %v), want (%d, %v)", tt.name, gotStep, ok, tt.wantStep, tt.wantOK)
		}
	}
	// Another secret's code doesn't work.
	if _, ok := Verify(NewSecret(), Code(rfcSecret, step), now, 0); ok {
		t.Error("code accepted for a different secret")
	}
}

func TestNewSecret(t *testing.T) {
	t.Parallel()
	a, b := NewSecret(), NewSecret()
	if len(a) != SecretSize || string(a) == string(b) {
		t.Errorf("NewSecret() = %x, %x; want two different %d-byte secrets", a, b, SecretSize)
	}
}

func TestURI(t *testing.T) {
	t.Parallel()
	raw := URI("Acme App", "ada@example.com", rfcSecret)
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "otpauth" || u.Host != "totp" || u.Path != "/Acme App:ada@example.com" {
		t.Errorf("URI() = %s", raw)
	}
	q := u.Query()
	// The RFC's secret, "12345678901234567890", is GEZDGNBV... in base32.
	if got := q.Get("secret"); got != EncodeSecret(rfcSecret) || !strings.HasPrefix(got, "GEZDGNBV") {
		t.Errorf("secret = %q", got)
	}
	want := map[string]string{"issuer": "Acme App", "algorithm": "SHA1", "digits": "6", "period": "30"}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	if strings.Contains(raw, "=") && strings.Contains(q.Get("secret"), "=") {
		t.Error("secret is padded")
	}
}
