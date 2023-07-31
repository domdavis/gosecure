package gosecure_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/domdavis/gosecure"
	"github.com/stretchr/testify/assert"
)

type ErrorReader struct{}

func (ErrorReader) Read([]byte) (int, error) {
	return 0, assert.AnError
}

func ExampleGUID() {
	guid := gosecure.GUID()

	// Replace non `-` characters with an *
	guid = regexp.MustCompile(`[^-]`).ReplaceAllString(guid, "*")

	fmt.Println(guid)

	// Output:
	// ********-****-****-****-************
}

func TestGUID(t *testing.T) {
	t.Run("GUID should not be blank", func(t *testing.T) {
		t.Parallel()

		if gosecure.GUID() == "" {
			t.Error("GUID should not be blank")
		}
	})

	t.Run("GUIDs should be unique", func(t *testing.T) {
		t.Parallel()

		//nolint:staticcheck // Need to compare the outputs of subsequent calls.
		if gosecure.GUID() == gosecure.GUID() {
			t.Errorf("Generate two identical UUIDs")
		}
	})
}

func TestGUIDFrom(t *testing.T) {
	t.Run("GUIDFrom panics on error", func(t *testing.T) {
		t.Parallel()

		assert.Panics(t, func() {
			gosecure.GUIDFrom(ErrorReader{})
		})
	})
}
