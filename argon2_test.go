package gosecure_test

import (
	"fmt"
	"testing"

	"bitbucket.org/idomdavis/gofigure"
	"github.com/alexedwards/argon2id"
	"github.com/domdavis/gosecure"
	"github.com/stretchr/testify/assert"
)

func ExampleArgon2id_Register() {
	var settings struct{ Argon2id gosecure.Argon2id }

	config := gofigure.NewConfiguration("EXAMPLE")

	settings.Argon2id.Register(config)

	// Ordinarily this would be config.Parse().
	err := config.ParseUsing([]string{"--argon2id-parallelism", "2"})

	if err != nil {
		fmt.Println(config.Format(err))
		fmt.Println(config.Usage())
	}

	fmt.Println(settings.Argon2id.Parallelism)

	// Output:
	// 2
}

func TestArgon2id_Hash(t *testing.T) {
	t.Run("A memory options will error", func(t *testing.T) {
		t.Parallel()

		a := gosecure.Argon2id{Params: &argon2id.Params{Memory: 0}}

		_, err := a.Hash("passphrase")

		assert.Error(t, err)
	})

	t.Run("An invalid salt length will error", func(t *testing.T) {
		t.Parallel()

		a := gosecure.Argon2id{Params: &argon2id.Params{SaltLength: 0}}

		_, err := a.Hash("passphrase")

		assert.Error(t, err)
	})
}

func TestToUINT8(t *testing.T) {
	t.Run("Handles values in range", func(t *testing.T) {
		t.Parallel()

		result := gosecure.ToUINT8(100)

		assert.Equal(t, uint8(100), result)
	})

	t.Run("Handles above Max UINT8", func(t *testing.T) {
		t.Parallel()

		result := gosecure.ToUINT8(300)

		assert.Equal(t, uint8(255), result)
	})

	t.Run("Handles zero", func(t *testing.T) {
		t.Parallel()

		result := gosecure.ToUINT8(0)

		assert.Equal(t, uint8(0), result)
	})

	t.Run("Handles negative numbers", func(t *testing.T) {
		t.Parallel()

		result := gosecure.ToUINT8(-1)

		assert.Equal(t, uint8(255), result) // Wraps due to uint8 conversion
	})
}
