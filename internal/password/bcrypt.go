package password

import (
	"errors"
	"regexp"
	"strconv"

	"golang.org/x/crypto/bcrypt"
)

// Bcrypt hashes are only ever verified, for accounts moved in from systems
// that used bcrypt, and are replaced with argon2id after the first correct
// password. This package never creates them for real passwords.

// MaxBcryptCost is the highest bcrypt cost accepted. Each step doubles the
// work: at 15 one check takes a few seconds, and a hash with a higher cost
// (from corruption or tampering) could tie up the server for minutes.
const MaxBcryptCost = 15

// bcryptPattern is a whole bcrypt hash: the $2a$, $2b$, or $2y$ prefix, a
// two-digit cost, and 53 characters of bcrypt's base64 (22 of salt, 31 of
// hash).
var bcryptPattern = regexp.MustCompile(`^\$2[aby]\$(\d\d)\$[./A-Za-z0-9]{53}$`)

// IsBcrypt reports whether encoded looks like a bcrypt hash, well formed
// or not. It's how a stored hash is told apart from an argon2id one.
func IsBcrypt(encoded string) bool {
	return len(encoded) > 4 && encoded[0] == '$' && encoded[1] == '2' &&
		(encoded[2] == 'a' || encoded[2] == 'b' || encoded[2] == 'y') && encoded[3] == '$'
}

// CheckBcrypt reports whether encoded is a well-formed bcrypt hash with a
// cost from bcrypt.MinCost to MaxBcryptCost. Its errors never echo the
// hash.
func CheckBcrypt(encoded string) error {
	_, err := bcryptCost(encoded)
	return err
}

func bcryptCost(encoded string) (int, error) {
	m := bcryptPattern.FindStringSubmatch(encoded)
	if m == nil {
		return 0, ErrInvalidHash
	}
	cost, err := strconv.Atoi(m[1])
	if err != nil || cost < bcrypt.MinCost || cost > MaxBcryptCost {
		return 0, ErrInvalidHash
	}
	return cost, nil
}

// VerifyBcrypt reports whether password matches the bcrypt hash encoded.
// Like Verify, it returns an error only for a malformed hash, never for a
// wrong password, and compares in constant time. As in every bcrypt
// implementation, only the first 72 bytes of the password count.
func VerifyBcrypt(password, encoded string) (bool, error) {
	if _, err := bcryptCost(encoded); err != nil {
		return false, err
	}
	err := bcrypt.CompareHashAndPassword([]byte(encoded), []byte(password))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
		return false, nil
	default:
		return false, ErrInvalidHash
	}
}

// BcryptDummy is a bcrypt hash at a given cost that no password matches
// in practice, for SimulateBcrypt.
type BcryptDummy struct {
	hash []byte
}

// NewBcryptDummy makes a BcryptDummy at cost. It does one bcrypt hash, so
// make it once, at startup.
func NewBcryptDummy(cost int) (BcryptDummy, error) {
	if cost < bcrypt.MinCost || cost > MaxBcryptCost {
		return BcryptDummy{}, errors.New("bcrypt cost out of range")
	}
	// A fixed input is fine: nothing is ever meant to match it, and a
	// match would still only make SimulateBcrypt's result true, which is
	// discarded.
	h, err := bcrypt.GenerateFromPassword([]byte("dummy password, never a real one"), cost)
	if err != nil {
		return BcryptDummy{}, err
	}
	return BcryptDummy{hash: h}, nil
}

// Cost is the dummy's cost.
func (d BcryptDummy) Cost() int {
	c, _ := bcrypt.Cost(d.hash)
	return c
}

// SimulateBcrypt does the same work as VerifyBcrypt with a hash at the
// dummy's cost, so a password check that has no bcrypt hash to verify takes
// as long as one that has.
func (d BcryptDummy) SimulateBcrypt(password string) {
	_ = bcrypt.CompareHashAndPassword(d.hash, []byte(password))
}
