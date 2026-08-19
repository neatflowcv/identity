package hasher

// Hasher hashes passwords and verifies them against encoded hashes.
type Hasher interface {
	Hash(password string) (encodedHash string, err error)
	Verify(password string, encodedHash string) (bool, error)
}
