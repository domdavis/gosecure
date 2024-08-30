package gosecure

import (
	"errors"
	"fmt"
	"runtime"

	"bitbucket.org/idomdavis/gofigure"
	"github.com/alexedwards/argon2id"
)

// Argon2id hashing algorithm. If no parameters are defined then the default are
// used.
type Argon2id struct {
	*argon2id.Params
}

// ErrFailedToHashArgon2Id is returned if the Argon2id hashing algorithm panics.
var ErrFailedToHashArgon2Id = errors.New("hash failure")

// Hash a passphrase. The argon2id.DefaultParams are used if no Params are set.
func (a *Argon2id) Hash(passphrase string) (b []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%w: %v", ErrFailedToHashArgon2Id, r)
		}
	}()

	a.lazyInit()

	//nolint: errcheck // this can only go bang if crypto/rand does.
	hash, _ := argon2id.CreateHash(passphrase, a.Params)

	return []byte(hash), nil
}

// Compare a passphrase to a hash. If the passphrase matches the hash then this
// function will return nil. A mismatched passphrase will result in
// ErrMismatchedPassphrase. All other errors indicate something went wrong
// comparing the hash and passphrase.
func (*Argon2id) Compare(passphrase string, hash []byte) error {
	ok, err := argon2id.ComparePasswordAndHash(passphrase, string(hash))

	switch {
	case err != nil:
		return fmt.Errorf("argon2: %w", err)
	case !ok:
		return ErrMismatchedPassphrase
	default:
		return nil
	}
}

// Register Argon2id with gofigure.
func (a *Argon2id) Register(opts *gofigure.Configuration) {
	a.lazyInit()

	group := opts.Group("Argon2id settings")

	group.Add(gofigure.Optional("Argon2Id Memory", "argon2id-cost",
		&a.Memory, argon2id.DefaultParams.Memory,
		gofigure.NamedSources, gofigure.ReportValue,
		"The amount of memory used by the algorithm (in kibibytes): "+
			"deprecated, use argon2id-memory"))
	group.Add(gofigure.Optional("Argon2Id Memory", "argon2id-memory",
		&a.Memory, argon2id.DefaultParams.Memory,
		gofigure.NamedSources, gofigure.ReportValue,
		"The amount of memory used by the algorithm (in kibibytes)"))
	group.Add(gofigure.Optional("Argon2Id Iterations", "argon2id-iterations",
		&a.Iterations, argon2id.DefaultParams.Iterations,
		gofigure.NamedSources, gofigure.ReportValue,
		"The number of iterations over the memory"))
	group.Add(gofigure.Optional("Argon2Id Parallelism", "argon2id-parallelism",
		&a.Parallelism, uint8(runtime.NumCPU()),
		gofigure.NamedSources, gofigure.ReportValue,
		"The number of threads (or lanes) used by the algorithm"))
	group.Add(gofigure.Optional("Argon2Id Salt Length", "argon2id-salt-length",
		&a.SaltLength, argon2id.DefaultParams.SaltLength,
		gofigure.NamedSources, gofigure.ReportValue,
		"Length of the random salt"))
	group.Add(gofigure.Optional("Argon2Id Key Length", "argon2id-key-length",
		&a.KeyLength, argon2id.DefaultParams.KeyLength,
		gofigure.NamedSources, gofigure.ReportValue,
		"Length of the generated key"))
}

func (a *Argon2id) lazyInit() {
	if a.Params == nil {
		a.Params = argon2id.DefaultParams
	}
}
