package gosecure

import (
	"crypto/rand"
	"io"
	"math/big"
)

type Integers interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64
}

// Int will take an integer and generate a cryptographically secure random
// number x such that 0 >= x < n. Int will panic on any errors.
func Int[T Integers](n T) T {
	return IntFrom(rand.Reader, n)
}

// IntFrom will take an integer and generate a random number x from the reader
// such that 0 >= x < n. It will panic on any errors.
//
// Note: that IntFrom is only secure if rand.Reader, or other cryptographically
// secure source of randomness is used.
func IntFrom[T Integers](reader io.Reader, n T) T {
	r, err := rand.Int(reader, big.NewInt(int64(n)))

	if err != nil {
		panic(err)
	}

	return T(r.Int64())
}
