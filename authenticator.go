package gosecure

import (
	"errors"
	"fmt"
	"time"
)

// Authenticator used to hash passphrases and compare passphrases against
// hashes. The Authenticator can use multiple comparison algorithms to allow
// algorithm migration.
type Authenticator struct {
	// MinimumTime is the shortest amount of time the Authenticator will take
	// to compare a passphrase and hash. This helps to mitigate timing attacks.
	MinimumTime time.Duration

	// MinimumLength is the shortest passphrase the Authenticator will allow
	// when hashing passphrases.
	MinimumLength int

	hash    Algorithm
	compare []Algorithm
}

// ErrMismatchedPassphrase is returned if a passphrase and hash do not match.
var ErrMismatchedPassphrase = errors.New("mismatched passphrase")

// ErrPassphraseTooShort is returned if a passphrase to be hashed is shorter
// that Authenticator.MinimumLength.
var ErrPassphraseTooShort = errors.New("passphrase too short")

// Default minimums for password length and comparison time.
const (
	MinimumLength = 8
	MinimumTime   = time.Millisecond * 100
)

// NewAuthenticator returns a new Authenticator type with the hash and compare
// algorithms set to the given algorithm. If an invalid or nil algorithm is
// provided then the algorithm will default to Bcrypt.
func NewAuthenticator(algorithm Algorithm) *Authenticator {
	if !usable(algorithm) {
		algorithm = &Bcrypt{}
	}

	return &Authenticator{hash: algorithm, compare: []Algorithm{algorithm}}
}

// Add an Algorithm to the set of comparison algorithms.
func (a *Authenticator) Add(algorithm Algorithm) {
	if !usable(algorithm) {
		return
	}

	a.compare = append(a.compare, algorithm)
}

// Hash a passphrase using the registered hashing algorithm. The passphrase must
// meet any minimum length requirements.
func (a *Authenticator) Hash(passphrase string) (b []byte, err error) {
	a.lazyInit()

	if len(passphrase) < a.MinimumLength {
		err = fmt.Errorf("%w: %d characters", ErrPassphraseTooShort, len(passphrase))
	} else {
		b, err = a.hash.Hash(passphrase)
	}

	if err != nil {
		err = fmt.Errorf("hash failure: %w", err)
	}

	return b, err
}

// Compare the given passphrase and hash using the registered comparison
// algorithms.
func (a *Authenticator) Compare(passphrase string, hash []byte) error {
	var err error

	a.lazyInit()

	timer := time.NewTimer(a.MinimumTime)

	for _, algorithm := range a.compare {
		if err = algorithm.Compare(passphrase, hash); err != nil {
			err = fmt.Errorf("comparison failure: %w", err)
		}
	}

	<-timer.C

	return err
}

func (a *Authenticator) lazyInit() {
	if a.MinimumLength <= 0 {
		a.MinimumLength = MinimumLength
	}

	if a.MinimumTime <= 0 {
		a.MinimumTime = MinimumTime
	}
}

func usable(algorithm Algorithm) bool {
	if algorithm == nil {
		return false
	}

	_, ok := algorithm.(*Authenticator)

	return !ok
}
