package password

import (
	"errors"
	"regexp"
	"strings"
	"testing"
)

// cheapParams keep most tests fast. DefaultParams are covered separately.
var cheapParams = Params{Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}

// Reference hashes generated with the argon2 C reference implementation
// (via the argon2-cffi Python package), so these tests check compatibility
// with other argon2id implementations, not just round-trips through ours.
var referenceHashes = []struct {
	password string
	encoded  string
}{
	{
		password: "correct horse battery staple",
		encoded:  "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$QKHrg5tayLGcN+Y0HVPNaBqykOVLUxlMkZycXE1uWRM",
	},
	{
		password: "password",
		encoded:  "$argon2id$v=19$m=64,t=1,p=1$c29tZXNhbHRzb21lc2FsdA$55PWTvddWPUD1GMbKxSff4ASfF85k9ibHJt4HlHQtBM",
	},
}

func TestVerifyReferenceHashes(t *testing.T) {
	t.Parallel()

	for _, ref := range referenceHashes {
		ok, err := Verify(ref.password, ref.encoded)
		if err != nil {
			t.Fatalf("Verify(reference %q) error = %v", ref.password, err)
		}
		if !ok {
			t.Errorf("Verify(reference %q) = false, want true", ref.password)
		}

		ok, err = Verify(ref.password+"x", ref.encoded)
		if err != nil {
			t.Fatalf("Verify(wrong password) error = %v", err)
		}
		if ok {
			t.Errorf("Verify(wrong password) against reference hash = true, want false")
		}
	}
}

var encodedPattern = regexp.MustCompile(`^\$argon2id\$v=19\$m=19456,t=2,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$`)

func TestHashWithDefaultParams(t *testing.T) {
	t.Parallel()

	encoded, err := Hash("correct horse battery staple", DefaultParams)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	if !encodedPattern.MatchString(encoded) {
		t.Fatalf("Hash() = %q, want the PHC format with OWASP minimum params", encoded)
	}

	ok, err := Verify("correct horse battery staple", encoded)
	if err != nil || !ok {
		t.Fatalf("Verify(correct password) = %v, %v; want true, nil", ok, err)
	}
}

func TestHashUsesRandomSalt(t *testing.T) {
	t.Parallel()

	a, err := Hash("same password here", cheapParams)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Hash("same password here", cheapParams)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("two hashes of the same password are identical: %q", a)
	}
}

func TestHashDoesNotContainPassword(t *testing.T) {
	t.Parallel()

	const pw = "do-not-store-me-123"
	encoded, err := Hash(pw, cheapParams)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(encoded, pw) {
		t.Fatalf("encoded hash contains the plain-text password")
	}
}

func TestVerify(t *testing.T) {
	t.Parallel()

	const pw = "correct horse battery staple"
	encoded, err := Hash(pw, cheapParams)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		password string
		want     bool
	}{
		{"correct password", pw, true},
		{"wrong password", "correct horse battery stapl", false},
		{"empty password", "", false},
		{"different case", strings.ToUpper(pw), false},
		{"trailing space", pw + " ", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Verify(tt.password, encoded)
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("Verify(%q) = %v, want %v", tt.password, got, tt.want)
			}
		})
	}
}

func TestVerifyTamperedHash(t *testing.T) {
	t.Parallel()

	encoded, err := Hash("correct horse battery staple", cheapParams)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(encoded, "$")

	// Swap in the salt and hash from a different password's hash: valid
	// format, so Verify must say no rather than error.
	other, err := Hash("a different password!", cheapParams)
	if err != nil {
		t.Fatal(err)
	}
	otherParts := strings.Split(other, "$")

	tests := []struct {
		name    string
		encoded string
	}{
		{"different salt", strings.Join([]string{"", parts[1], parts[2], parts[3], otherParts[4], parts[5]}, "$")},
		{"different hash", strings.Join([]string{"", parts[1], parts[2], parts[3], parts[4], otherParts[5]}, "$")},
		{"different cost", strings.Replace(encoded, "t=1", "t=2", 1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ok, err := Verify("correct horse battery staple", tt.encoded)
			if err != nil {
				t.Fatalf("Verify() error = %v, want nil for a well-formed hash", err)
			}
			if ok {
				t.Errorf("Verify() = true for a tampered hash, want false")
			}
		})
	}
}

func TestVerifyMalformedHash(t *testing.T) {
	t.Parallel()

	const good = "$argon2id$v=19$m=64,t=1,p=1$c29tZXNhbHRzb21lc2FsdA$55PWTvddWPUD1GMbKxSff4ASfF85k9ibHJt4HlHQtBM"
	tests := []struct {
		name    string
		encoded string
		wantErr error
	}{
		{"empty", "", ErrInvalidHash},
		{"plain text", "hunter2", ErrInvalidHash},
		{"bcrypt hash", "$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW", ErrInvalidHash},
		{"argon2i, not argon2id", strings.Replace(good, "argon2id", "argon2i", 1), ErrInvalidHash},
		{"older argon2 version", strings.Replace(good, "v=19", "v=16", 1), ErrIncompatibleVersion},
		{"non-numeric version", strings.Replace(good, "v=19", "v=x", 1), ErrInvalidHash},
		{"missing version prefix", strings.Replace(good, "v=19", "19", 1), ErrInvalidHash},
		{"too few sections", strings.TrimSuffix(good, "$55PWTvddWPUD1GMbKxSff4ASfF85k9ibHJt4HlHQtBM"), ErrInvalidHash},
		{"extra section", good + "$extra", ErrInvalidHash},
		{"no leading dollar", strings.TrimPrefix(good, "$"), ErrInvalidHash},
		{"params out of order", strings.Replace(good, "m=64,t=1,p=1", "t=1,m=64,p=1", 1), ErrInvalidHash},
		{"missing param", strings.Replace(good, "m=64,t=1,p=1", "m=64,t=1", 1), ErrInvalidHash},
		{"negative memory", strings.Replace(good, "m=64", "m=-64", 1), ErrInvalidHash},
		{"zero memory", strings.Replace(good, "m=64", "m=0", 1), ErrInvalidHash},
		{"zero iterations", strings.Replace(good, "t=1", "t=0", 1), ErrInvalidHash},
		{"zero parallelism", strings.Replace(good, "p=1", "p=0", 1), ErrInvalidHash},
		{"parallelism over 255", strings.Replace(good, "p=1", "p=256", 1), ErrInvalidHash},
		{"absurd memory (DoS)", strings.Replace(good, "m=64", "m=4294967295", 1), ErrInvalidHash},
		{"absurd iterations (DoS)", strings.Replace(good, "t=1", "t=1000000", 1), ErrInvalidHash},
		{"salt not base64", strings.Replace(good, "c29tZXNhbHRzb21lc2FsdA", "!!!!", 1), ErrInvalidHash},
		{"salt too short", strings.Replace(good, "c29tZXNhbHRzb21lc2FsdA", "c2FsdA", 1), ErrInvalidHash},
		{"salt too long", strings.Replace(good, "c29tZXNhbHRzb21lc2FsdA", strings.Repeat("A", 88), 1), ErrInvalidHash},
		{"padded salt", strings.Replace(good, "c29tZXNhbHRzb21lc2FsdA", "c29tZXNhbHRzb21lc2FsdA==", 1), ErrInvalidHash},
		{"hash too short", strings.Replace(good, "55PWTvddWPUD1GMbKxSff4ASfF85k9ibHJt4HlHQtBM", "55PWTvddWPU", 1), ErrInvalidHash},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ok, err := Verify("password", tt.encoded)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Verify() error = %v, want %v", err, tt.wantErr)
			}
			if ok {
				t.Errorf("Verify() = true for a malformed hash")
			}
		})
	}
}

func TestErrorsDoNotLeakHash(t *testing.T) {
	t.Parallel()

	const storedHash = "$argon2id$v=19$m=64,t=1,p=1$MARKERSALT$MARKERHASH"
	_, err := Verify("password", storedHash)
	if err == nil {
		t.Fatal("Verify() error = nil, want an error for an invalid hash")
	}
	if strings.Contains(err.Error(), "MARKER") {
		t.Errorf("error message %q contains part of the stored hash", err)
	}
}

func TestHashRejectsBadParams(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		p    Params
	}{
		{"zero memory", Params{Memory: 0, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}},
		{"too much memory", Params{Memory: maxMemory + 1, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}},
		{"zero iterations", Params{Memory: 64, Iterations: 0, Parallelism: 1, SaltLength: 16, KeyLength: 32}},
		{"zero parallelism", Params{Memory: 64, Iterations: 1, Parallelism: 0, SaltLength: 16, KeyLength: 32}},
		{"short salt", Params{Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 4, KeyLength: 32}},
		{"long salt", Params{Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 65, KeyLength: 32}},
		{"short key", Params{Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 8}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := Hash("correct horse battery staple", tt.p); err == nil {
				t.Errorf("Hash() with %+v: error = nil, want an error", tt.p)
			}
		})
	}
}

func TestNeedsRehash(t *testing.T) {
	t.Parallel()

	encoded, err := Hash("correct horse battery staple", cheapParams)
	if err != nil {
		t.Fatal(err)
	}

	stronger := cheapParams
	stronger.Memory = 128
	moreIterations := cheapParams
	moreIterations.Iterations = 2
	longerKey := cheapParams
	longerKey.KeyLength = 64
	longerSalt := cheapParams
	longerSalt.SaltLength = 32

	tests := []struct {
		name string
		p    Params
		want bool
	}{
		{"same params", cheapParams, false},
		{"more memory", stronger, true},
		{"more iterations", moreIterations, true},
		{"longer key", longerKey, true},
		{"longer salt", longerSalt, true},
		{"default params", DefaultParams, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := NeedsRehash(encoded, tt.p)
			if err != nil {
				t.Fatalf("NeedsRehash() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("NeedsRehash() = %v, want %v", got, tt.want)
			}
		})
	}

	if _, err := NeedsRehash("not a hash", DefaultParams); !errors.Is(err, ErrInvalidHash) {
		t.Errorf("NeedsRehash(malformed) error = %v, want ErrInvalidHash", err)
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		password string
		wantErr  error
	}{
		{"empty", "", ErrTooShort},
		{"11 characters", "abcdefghijk", ErrTooShort},
		{"12 characters", "abcdefghijkl", nil},
		{"spaces allowed", "correct horse battery", nil},
		{"only spaces, 12 long", strings.Repeat(" ", 12), nil},
		{"no composition rules", strings.Repeat("a", 12), nil},
		{"12 emoji count as 12 characters", strings.Repeat("🔒", 12), nil},
		{"11 emoji are too short even at 44 bytes", strings.Repeat("🔒", 11), ErrTooShort},
		{"max length", strings.Repeat("a", MaxLength), nil},
		{"over max length", strings.Repeat("a", MaxLength+1), ErrTooLong},
		{"invalid UTF-8", "abcdefghijk\xff", ErrInvalidUTF8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := Validate(tt.password); !errors.Is(err, tt.wantErr) {
				t.Errorf("Validate() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestSimulateVerifyCompletes(t *testing.T) {
	t.Parallel()

	// SimulateVerify's purpose (matching Verify's timing) can't be asserted
	// without a timing-based, flaky test. This checks it runs with the real
	// default cost and doesn't panic on any input.
	SimulateVerify("any password")
	SimulateVerify("")
	SimulateVerify(strings.Repeat("🔒", MaxLength))
}
