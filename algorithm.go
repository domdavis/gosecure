package gosecure

// Algorithm that allows for hashing of passphrases, and comparison of
// passphrases against hashes.
type Algorithm interface {

	// Hash a passphrase. An error is returned if there is a problem creating
	// the hash.
	Hash(passphrase string) ([]byte, error)

	// Compare a passphrase to a previously hashed passphrase. An error is
	// returned if the passphrase and hash don't match, or there is an issue
	// comparing the two.
	Compare(passphrase string, hash []byte) error
}
