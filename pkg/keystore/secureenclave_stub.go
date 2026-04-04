//go:build !darwin

package keystore

// supportsSecureEnclave always returns false on non-Darwin platforms.
func supportsSecureEnclave() bool { return false }

func generateSecureEnclave(_ Config) (KeyStore, error) {
	return nil, ErrKeyNotFound
}

func openSecureEnclave(_ Config) (KeyStore, error) {
	return nil, ErrKeyNotFound
}
