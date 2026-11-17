package totp

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestDecodeSecret(t *testing.T) {
	t.Parallel()
	secret := bytes.Repeat([]byte{0xA5}, 20)
	enc := EncodeSecret(secret)
	ok := []string{
		enc,
		strings.ToLower(enc),
		enc + "====",
		// Spaced in groups, as some apps show it.
		enc[:4] + " " + enc[4:8] + " " + enc[8:],
	}
	for _, s := range ok {
		got, err := DecodeSecret(s)
		if err != nil || !bytes.Equal(got, secret) {
			t.Errorf("DecodeSecret(%q) = %x, %v; want %x", s, got, err, secret)
		}
	}
	bad := map[string]string{
		"empty":           "",
		"80 bits":         EncodeSecret(bytes.Repeat([]byte{1}, 10)),
		"120 bits":        EncodeSecret(bytes.Repeat([]byte{1}, 15)),
		"over 512 bits":   EncodeSecret(bytes.Repeat([]byte{1}, 65)),
		"not base32":      strings.Repeat("1", 32),
		"padding mid-way": enc[:8] + "=" + enc[8:],
	}
	for name, s := range bad {
		_, err := DecodeSecret(s)
		if !errors.Is(err, ErrInvalidSecret) {
			t.Errorf("%s: error = %v, want ErrInvalidSecret", name, err)
		}
		if err != nil && s != "" && strings.Contains(err.Error(), s) {
			t.Errorf("%s: error contains the secret", name)
		}
	}
	for _, n := range []int{MinImportedSecretSize, MaxImportedSecretSize} {
		if _, err := DecodeSecret(EncodeSecret(bytes.Repeat([]byte{1}, n))); err != nil {
			t.Errorf("%d bytes: %v", n, err)
		}
	}
}
