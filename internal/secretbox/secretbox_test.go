package secretbox

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
)

// Obviously fake keys for tests.
var (
	keyA = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xA1}, 32))
	keyB = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xB2}, 32))
)

func mustNew(t *testing.T, key string) *Box {
	t.Helper()
	b, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSealOpen(t *testing.T) {
	t.Parallel()
	b := mustNew(t, keyA)
	secret := []byte("a totp secret")
	sealed := b.Seal(secret, []byte("user-1"))
	if bytes.Contains(sealed, secret) {
		t.Error("sealed value contains the plaintext")
	}
	got, err := b.Open(sealed, []byte("user-1"))
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("Open() = %q, %v", got, err)
	}
	// Each seal uses a fresh nonce.
	if bytes.Equal(sealed, b.Seal(secret, []byte("user-1"))) {
		t.Error("sealing twice gave the same output")
	}
}

func TestOpenRejects(t *testing.T) {
	t.Parallel()
	a, other := mustNew(t, keyA), mustNew(t, keyB)
	sealed := a.Seal([]byte("secret"), []byte("user-1"))
	flipped := bytes.Clone(sealed)
	flipped[len(flipped)-1] ^= 1
	badVersion := bytes.Clone(sealed)
	badVersion[0] = 2

	tests := map[string]struct {
		box    *Box
		sealed []byte
		ad     string
	}{
		"another user's row": {a, sealed, "user-2"},
		"another key":        {other, sealed, "user-1"},
		"tampered":           {a, flipped, "user-1"},
		"unknown version":    {a, badVersion, "user-1"},
		"truncated":          {a, sealed[:10], "user-1"},
		"empty":              {a, nil, "user-1"},
	}
	for name, tt := range tests {
		if _, err := tt.box.Open(tt.sealed, []byte(tt.ad)); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s: Open() error = %v, want ErrDecrypt", name, err)
		}
	}
}

func TestNewRejectsBadKeys(t *testing.T) {
	t.Parallel()
	for name, key := range map[string]string{
		"empty":        "",
		"not base64":   "not a key!",
		"too short":    base64.StdEncoding.EncodeToString(make([]byte, 16)),
		"too long":     base64.StdEncoding.EncodeToString(make([]byte, 33)),
		"raw 32 chars": "0123456789abcdef0123456789abcdef",
	} {
		if _, err := New(key); err == nil {
			t.Errorf("%s: New() error = nil", name)
		}
	}
}
