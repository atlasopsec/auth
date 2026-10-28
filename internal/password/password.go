// Package password hashes and verifies passwords with argon2id, and checks
// new passwords against the length policy in the auth standard.
//
// Hashes are stored in the standard PHC string format, which keeps the
// algorithm, parameters, salt, and hash together:
//
//	$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
//
// Storing the parameters with each hash lets them be raised later: after a
// successful login, NeedsRehash reports whether the hash should be replaced.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Length limits for new passwords, counted in characters (runes), not bytes.
const (
	MinLength = 12
	MaxLength = 256
)

var (
	// ErrTooShort means a new password has fewer than MinLength characters.
	ErrTooShort = errors.New("password is too short")
	// ErrTooLong means a new password has more than MaxLength characters.
	ErrTooLong = errors.New("password is too long")
	// ErrInvalidUTF8 means a new password isn't valid UTF-8 text.
	ErrInvalidUTF8 = errors.New("password is not valid UTF-8")
	// ErrInvalidHash means a stored hash couldn't be parsed.
	ErrInvalidHash = errors.New("invalid password hash")
	// ErrIncompatibleVersion means a stored hash uses an argon2 version this
	// package doesn't support.
	ErrIncompatibleVersion = errors.New("incompatible argon2 version")
)

// Params are the argon2id cost settings.
type Params struct {
	Memory      uint32 // in KiB
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32 // in bytes
	KeyLength   uint32 // in bytes
}

// DefaultParams are OWASP's minimum recommended settings for argon2id:
// 19 MiB of memory, 2 iterations, parallelism 1.
var DefaultParams = Params{
	Memory:      19 * 1024,
	Iterations:  2,
	Parallelism: 1,
	SaltLength:  16,
	KeyLength:   32,
}

// Limits on parameters read from a stored hash. A hash with absurd costs
// (from corruption or tampering) could otherwise make a single login use
// gigabytes of memory.
const (
	maxMemory     = 1024 * 1024 // 1 GiB, in KiB
	maxIterations = 100
	minSaltLength = 8
	maxSaltLength = 64
	minKeyLength  = 16
	maxKeyLength  = 128
)

// Validate checks a new password against the length policy. It's for
// sign-up and password changes; existing hashes are never re-checked.
func Validate(password string) error {
	if !utf8.ValidString(password) {
		return ErrInvalidUTF8
	}
	n := utf8.RuneCountInString(password)
	switch {
	case n < MinLength:
		return ErrTooShort
	case n > MaxLength:
		return ErrTooLong
	}
	return nil
}

// Hash returns the encoded argon2id hash of password, using a new random
// salt.
func Hash(password string, p Params) (string, error) {
	if err := p.check(); err != nil {
		return "", err
	}
	salt := make([]byte, p.SaltLength)
	// crypto/rand.Read never returns an error; it crashes the program if the
	// system's randomness source fails.
	_, _ = rand.Read(salt)

	key := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	return encode(p, salt, key), nil
}

// Verify reports whether password matches the encoded hash. It returns an
// error only when the hash itself is malformed, never for a wrong password.
// The comparison runs in constant time.
func Verify(password, encoded string) (bool, error) {
	p, salt, key, err := decode(encoded)
	if err != nil {
		return false, err
	}
	other := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	return subtle.ConstantTimeCompare(key, other) == 1, nil
}

// NeedsRehash reports whether an encoded hash was made with different
// parameters than p, so it should be replaced after the next successful
// login.
func NeedsRehash(encoded string, p Params) (bool, error) {
	got, salt, _, err := decode(encoded)
	if err != nil {
		return false, err
	}
	return got.Memory != p.Memory ||
		got.Iterations != p.Iterations ||
		got.Parallelism != p.Parallelism ||
		len(salt) != int(p.SaltLength) ||
		got.KeyLength != p.KeyLength, nil
}

// dummySalt is a fixed salt for SimulateVerify. It never protects a real
// password, so it doesn't need to be random.
var dummySalt = make([]byte, 16)

// SimulateVerify does the same amount of work as Verify with DefaultParams,
// for logins with an email that has no account. Without it, a login for a
// nonexistent account would return noticeably faster, revealing which
// emails are registered.
func SimulateVerify(password string) {
	p := DefaultParams
	_ = argon2.IDKey([]byte(password), dummySalt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
}

func (p Params) check() error {
	switch {
	case p.Memory == 0 || p.Memory > maxMemory:
		return fmt.Errorf("argon2 memory %d KiB out of range", p.Memory)
	case p.Iterations == 0 || p.Iterations > maxIterations:
		return fmt.Errorf("argon2 iterations %d out of range", p.Iterations)
	case p.Parallelism == 0:
		return errors.New("argon2 parallelism must be at least 1")
	case p.SaltLength < minSaltLength || p.SaltLength > maxSaltLength:
		return fmt.Errorf("argon2 salt length %d out of range", p.SaltLength)
	case p.KeyLength < minKeyLength || p.KeyLength > maxKeyLength:
		return fmt.Errorf("argon2 key length %d out of range", p.KeyLength)
	}
	return nil
}

func encode(p Params, salt, key []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Iterations, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}

// decode parses an encoded hash. Every failure is reported as
// ErrInvalidHash (or ErrIncompatibleVersion), without echoing the input,
// so hashes never end up in error messages or logs.
func decode(encoded string) (Params, []byte, []byte, error) {
	var p Params

	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return p, nil, nil, ErrInvalidHash
	}

	version, ok := strings.CutPrefix(parts[2], "v=")
	if !ok {
		return p, nil, nil, ErrInvalidHash
	}
	v, err := strconv.Atoi(version)
	if err != nil {
		return p, nil, nil, ErrInvalidHash
	}
	if v != argon2.Version {
		return p, nil, nil, ErrIncompatibleVersion
	}

	if err := parseCosts(parts[3], &p); err != nil {
		return p, nil, nil, ErrInvalidHash
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil {
		return p, nil, nil, ErrInvalidHash
	}
	key, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil {
		return p, nil, nil, ErrInvalidHash
	}
	// Bounds-check before converting, so the lengths provably fit in uint32.
	saltLen, keyLen := len(salt), len(key)
	if saltLen < minSaltLength || saltLen > maxSaltLength {
		return p, nil, nil, ErrInvalidHash
	}
	if keyLen < minKeyLength || keyLen > maxKeyLength {
		return p, nil, nil, ErrInvalidHash
	}
	p.SaltLength = uint32(saltLen)
	p.KeyLength = uint32(keyLen)

	if p.check() != nil {
		return p, nil, nil, ErrInvalidHash
	}
	return p, salt, key, nil
}

// parseCosts parses "m=19456,t=2,p=1" in exactly that order.
func parseCosts(s string, p *Params) error {
	fields := strings.Split(s, ",")
	if len(fields) != 3 {
		return ErrInvalidHash
	}
	m, err := parseCost(fields[0], "m=", math.MaxUint32)
	if err != nil {
		return err
	}
	t, err := parseCost(fields[1], "t=", math.MaxUint32)
	if err != nil {
		return err
	}
	par, err := parseCost(fields[2], "p=", math.MaxUint8)
	if err != nil {
		return err
	}
	// Each value was checked against its type's maximum in parseCost.
	if m > math.MaxUint32 || t > math.MaxUint32 || par > math.MaxUint8 {
		return ErrInvalidHash
	}
	p.Memory = uint32(m)
	p.Iterations = uint32(t)
	p.Parallelism = uint8(par)
	return nil
}

// parseCost parses one "x=123" field, rejecting values above limit.
func parseCost(field, prefix string, limit uint64) (uint64, error) {
	raw, ok := strings.CutPrefix(field, prefix)
	if !ok {
		return 0, ErrInvalidHash
	}
	n, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || n > limit {
		return 0, ErrInvalidHash
	}
	return n, nil
}
