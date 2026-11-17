package password

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func bcryptOf(t *testing.T, pw string, cost int) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), cost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

func TestVerifyBcrypt(t *testing.T) {
	t.Parallel()
	const pw = "correct horse battery staple"
	h2a := bcryptOf(t, pw, bcrypt.MinCost)
	// The same algorithm under the prefixes other libraries write: 2b
	// (current OpenBSD) and 2y (PHP).
	tests := []struct {
		name, hash, pw string
		want           bool
	}{
		{"2a", h2a, pw, true},
		{"2b", "$2b$" + h2a[4:], pw, true},
		{"2y", "$2y$" + h2a[4:], pw, true},
		{"wrong password", h2a, pw + "!", false},
		{"empty password", h2a, "", false},
	}
	for _, tt := range tests {
		if !IsBcrypt(tt.hash) {
			t.Errorf("%s: IsBcrypt = false", tt.name)
		}
		got, err := VerifyBcrypt(tt.pw, tt.hash)
		if err != nil || got != tt.want {
			t.Errorf("%s: VerifyBcrypt = %v, %v; want %v", tt.name, got, err, tt.want)
		}
	}
}

func TestVerifyBcryptMalformed(t *testing.T) {
	t.Parallel()
	good := bcryptOf(t, "correct horse battery staple", bcrypt.MinCost)
	bad := map[string]string{
		"empty":          "",
		"argon2id":       "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g",
		"2x prefix":      "$2x$" + good[4:],
		"2 prefix":       "$2$" + good[4:],
		"truncated":      good[:len(good)-1],
		"extra":          good + "a",
		"bad character":  good[:len(good)-1] + "!",
		"cost 03":        good[:4] + "03" + good[6:],
		"cost 16":        good[:4] + "16" + good[6:],
		"cost 31":        good[:4] + "31" + good[6:],
		"cost one digit": good[:4] + "4$" + good[7:],
	}
	for name, h := range bad {
		if err := CheckBcrypt(h); !errors.Is(err, ErrInvalidHash) {
			t.Errorf("%s: CheckBcrypt = %v, want ErrInvalidHash", name, err)
		}
		ok, err := VerifyBcrypt("correct horse battery staple", h)
		if ok || !errors.Is(err, ErrInvalidHash) {
			t.Errorf("%s: VerifyBcrypt = %v, %v; want ErrInvalidHash", name, ok, err)
		}
		if err != nil && h != "" && strings.Contains(err.Error(), h) {
			t.Errorf("%s: error contains the hash", name)
		}
	}
	if err := CheckBcrypt(good); err != nil {
		t.Errorf("CheckBcrypt(good) = %v", err)
	}
	for _, s := range []string{"", "$2", "$argon2id$", "$2c$10$"} {
		if IsBcrypt(s) {
			t.Errorf("IsBcrypt(%q) = true", s)
		}
	}
}

func TestBcryptDummy(t *testing.T) {
	t.Parallel()
	d, err := NewBcryptDummy(bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if d.Cost() != bcrypt.MinCost {
		t.Errorf("Cost() = %d, want %d", d.Cost(), bcrypt.MinCost)
	}
	d.SimulateBcrypt("anything")
	for _, cost := range []int{0, 3, MaxBcryptCost + 1} {
		if _, err := NewBcryptDummy(cost); err == nil {
			t.Errorf("NewBcryptDummy(%d): no error", cost)
		}
	}
}
