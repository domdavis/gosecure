package gosecure_test

import (
	"fmt"
	"strings"
	"testing"

	"bitbucket.org/idomdavis/gofigure"
	"github.com/domdavis/gosecure"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

func ExampleBcrypt_Register() {
	var settings struct{ Bcrypt gosecure.Bcrypt }

	config := gofigure.NewConfiguration("EXAMPLE")

	settings.Bcrypt.Register(config)

	// Ordinarily this would be config.Parse().
	err := config.ParseUsing([]string{"--bcrypt-cost", "100"})

	if err != nil {
		fmt.Println(config.Format(err))
		fmt.Println(config.Usage())
	}

	fmt.Println(settings.Bcrypt)

	// Output:
	// {100}
}

func TestBcrypt_Hash(t *testing.T) {
	t.Run("An long passphrase will fail", func(t *testing.T) {
		t.Parallel()

		const maxLength = 72

		b := gosecure.Bcrypt{}

		_, err := b.Hash(strings.Repeat("a", maxLength+1))

		assert.ErrorIs(t, err, bcrypt.ErrPasswordTooLong)
	})
}
