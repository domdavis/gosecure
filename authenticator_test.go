package gosecure_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/domdavis/gosecure"
	"github.com/stretchr/testify/assert"
)

const passphrase = "passphrase"

func ExampleNewAuthenticator() {
	p := gosecure.NewAuthenticator(&gosecure.Bcrypt{})

	h, err := p.Hash("password")

	if err != nil {
		fmt.Println(err)
	}

	start := time.Now()

	err = p.Compare("password", h)

	d := time.Since(start)

	switch {
	case err != nil:
		fmt.Println(err)
	case d < gosecure.MinimumTime:
		fmt.Println("Finished too early")
	default:
		fmt.Println("Passwords match")
	}

	// Output:
	// Passwords match
}

func TestAuthenticator_Add(t *testing.T) {
	t.Run("Authenticators can be added", func(t *testing.T) {
		t.Parallel()

		h, err := gosecure.NewAuthenticator(&gosecure.Bcrypt{}).Hash(passphrase)

		assert.NoError(t, err)

		p := gosecure.NewAuthenticator(&gosecure.Argon2id{})
		p.MinimumTime = time.Nanosecond
		p.Add(&gosecure.Bcrypt{})

		err = p.Compare(passphrase, h)

		assert.NoError(t, err)
	})

	t.Run("Invalid authenticators will not panic", func(t *testing.T) {
		t.Parallel()

		p := gosecure.NewAuthenticator(nil)
		p.Add(nil)
		p.Add(p)
	})
}

func TestAuthenticator_Hash(t *testing.T) {
	t.Parallel()

	for _, algorithm := range []gosecure.Algorithm{
		nil,
		&gosecure.Bcrypt{},
		&gosecure.Argon2id{},
	} {
		func(algorithm gosecure.Algorithm, name string) {
			t.Run(name+": A valid passphrase will hash", func(t *testing.T) {
				t.Parallel()

				p := gosecure.NewAuthenticator(algorithm)
				p.MinimumTime = time.Nanosecond

				h, err := p.Hash(passphrase)

				assert.NoError(t, err)

				err = p.Compare(passphrase, h)

				assert.NoError(t, err)
			})

			t.Run(name+": An empty passphrase will error", func(t *testing.T) {
				t.Parallel()

				p := gosecure.NewAuthenticator(algorithm)
				p.MinimumTime = time.Nanosecond

				_, err := p.Hash("")

				assert.ErrorIs(t, err, gosecure.ErrPassphraseTooShort)
			})

			t.Run(name+": A short passphrase short will error", func(t *testing.T) {
				t.Parallel()

				p := gosecure.NewAuthenticator(algorithm)
				p.MinimumTime = time.Nanosecond
				p.MinimumLength = len(passphrase) + 1

				_, err := p.Hash(passphrase)

				assert.ErrorIs(t, err, gosecure.ErrPassphraseTooShort)
			})
		}(algorithm, fmt.Sprintf("%T", algorithm))
	}
}

func TestAuthenticator_Compare(t *testing.T) {
	t.Parallel()

	for _, algorithm := range []gosecure.Algorithm{
		&gosecure.Bcrypt{},
		&gosecure.Argon2id{},
	} {
		func(algorithm gosecure.Algorithm, name string) {
			t.Run(name+"Mismatched passphrases will error", func(t *testing.T) {
				t.Parallel()

				p := gosecure.NewAuthenticator(algorithm)
				p.MinimumTime = time.Nanosecond

				h, err := p.Hash(passphrase)

				assert.NoError(t, err)

				err = p.Compare("password", h)

				assert.ErrorIs(t, err, gosecure.ErrMismatchedPassphrase)
			})

			t.Run(name+"An empty passphrase will error", func(t *testing.T) {
				t.Parallel()

				p := gosecure.NewAuthenticator(algorithm)
				p.MinimumTime = time.Nanosecond

				h, err := p.Hash(passphrase)

				assert.NoError(t, err)

				err = p.Compare("", h)

				assert.Error(t, err)
			})

			t.Run(name+"An empty hash will error", func(t *testing.T) {
				t.Parallel()

				p := gosecure.NewAuthenticator(algorithm)
				p.MinimumTime = time.Nanosecond

				err := p.Compare("password", []byte{})

				assert.Error(t, err)
			})
		}(algorithm, fmt.Sprintf("%T", algorithm))
	}
}
