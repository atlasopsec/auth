// Package secretbox encrypts small secrets for storage, such as TOTP
// secrets, with AES-256-GCM.
//
// A sealed value is: a format version byte, a 4-byte key ID, a 12-byte
// random nonce, then the ciphertext and tag. The key ID lets a future
// version decrypt with older keys after a rotation, without migrating
// stored values.
package secretbox

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

const (
	version   = 1
	keySize   = 32
	keyIDSize = 4
	nonceSize = 12
	header    = 1 + keyIDSize + nonceSize
)

// ErrDecrypt means a sealed value couldn't be opened: it's corrupt, was
// sealed with another key, or was sealed with different associated data
// (for example, copied from another user's row).
var ErrDecrypt = errors.New("secretbox: can't decrypt")

// Box seals and opens values with one key.
type Box struct {
	aead  cipher.AEAD
	keyID [keyIDSize]byte
}

// New returns a Box using key: 32 bytes, standard base64-encoded (as
// produced by `openssl rand -base64 32`).
func New(key string) (*Box, error) {
	k, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, errors.New("secretbox: key must be base64")
	}
	if len(k) != keySize {
		return nil, fmt.Errorf("secretbox: key must be %d bytes, got %d", keySize, len(k))
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, fmt.Errorf("secretbox: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secretbox: %w", err)
	}
	// The ID identifies the key without revealing it.
	sum := sha256.Sum256(append([]byte("atlasopsec/auth key id:"), k...))
	b := &Box{aead: aead}
	copy(b.keyID[:], sum[:keyIDSize])
	return b, nil
}

// Seal encrypts plaintext, bound to associatedData: Open must be given the
// same associated data, such as the owning user's ID.
func (b *Box) Seal(plaintext, associatedData []byte) []byte {
	out := make([]byte, header, header+len(plaintext)+b.aead.Overhead())
	out[0] = version
	copy(out[1:], b.keyID[:])
	// crypto/rand.Read never returns an error; it crashes the program if
	// the system's randomness source fails.
	_, _ = rand.Read(out[1+keyIDSize : header])
	return b.aead.Seal(out, out[1+keyIDSize:header], plaintext, associatedData)
}

// Open decrypts a value from Seal, checking associatedData.
func (b *Box) Open(sealed, associatedData []byte) ([]byte, error) {
	if len(sealed) < header+b.aead.Overhead() || sealed[0] != version || !bytes.Equal(sealed[1:1+keyIDSize], b.keyID[:]) {
		return nil, ErrDecrypt
	}
	plain, err := b.aead.Open(nil, sealed[1+keyIDSize:header], sealed[header:], associatedData)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plain, nil
}
