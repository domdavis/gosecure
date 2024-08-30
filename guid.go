package gosecure

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

// GUID generator based on V4 UUIDs. GUID will panic if there is an error
// reading from rand.Reader since this means the IDs being generated cannot be
// unique.
func GUID() string {
	return GUIDFrom(rand.Reader)
}

// GUIDFrom uses the given reader to generate the GUID. Used primarily for
// testing. Will panic if there is an error reading from the reader.
//
//nolint:mnd // These are fairly well known positions and values.
func GUIDFrom(reader io.Reader) string {
	const dash byte = '-'

	u := make([]byte, 16)
	buf := make([]byte, 36)

	if _, err := io.ReadFull(reader, u); err != nil {
		panic(fmt.Errorf("failed to build GUID: %w", err))
	}

	u[6] = (u[6] | 0x40) & 0x4F
	u[8] = (u[8] | 0x80) & 0xBF

	hex.Encode(buf[0:8], u[0:4])
	buf[8] = dash
	hex.Encode(buf[9:13], u[4:6])
	buf[13] = dash
	hex.Encode(buf[14:18], u[6:8])
	buf[18] = dash
	hex.Encode(buf[19:23], u[8:10])
	buf[23] = dash
	hex.Encode(buf[24:], u[10:])

	return string(buf)
}
