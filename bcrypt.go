package gosecure

import (
	"errors"
	"fmt"

	"bitbucket.org/idomdavis/gofigure"
	"golang.org/x/crypto/bcrypt"
)

// Bcrypt hashing algorithm.
type Bcrypt struct {
	Cost int
}

// Hash a passphrase using the cost set on this Bcrypt instance. The actual cost
// used is as per the golang.org/x/crypto/bcrypt documentation.
func (b *Bcrypt) Hash(passphrase string) ([]byte, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(passphrase), b.Cost)

	if err != nil {
		return hash, fmt.Errorf("bcrypt: %w", err)
	}

	return hash, nil
}

// Compare a passphrase to a previously hashed passphrase. If the passphrase
// matches the hash then this function will return nil. A mismatched passphrase
// will result in ErrMismatchedPassphrase. All other errors indicate something
// went wrong comparing the hash and passphrase.
func (*Bcrypt) Compare(passphrase string, hash []byte) error {
	if err := bcrypt.CompareHashAndPassword(hash, []byte(passphrase)); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return ErrMismatchedPassphrase
		}

		return fmt.Errorf("bcrypt: %w", err)
	}

	return nil
}

// Register Bcrypt with gofigure.
func (b *Bcrypt) Register(opts *gofigure.Configuration) {
	group := opts.Group("Bcrypt settings")

	group.Add(gofigure.Optional("Bcrypt Cost", "bcrypt-cost",
		&b.Cost, bcrypt.DefaultCost, gofigure.NamedSources, gofigure.ReportValue,
		"Bcrypt hashing cost"))
}
