package gosecure_test

import (
	"fmt"
	"testing"

	"github.com/domdavis/gosecure"
	"github.com/stretchr/testify/assert"
)

type MockReader struct{}

func (MockReader) Read([]byte) (n int, err error) {
	return 0, assert.AnError
}

func ExampleInt() {
	i := gosecure.Int(5)

	fmt.Println(i < 5)

	// Output:
	// true
}

func TestIntFrom(t *testing.T) {
	t.Run("Errors generating a random number will panic", func(t *testing.T) {
		t.Parallel()

		assert.Panics(t, func() { gosecure.IntFrom(MockReader{}, 5) })
	})
}
