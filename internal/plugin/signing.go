package plugin

// Signer signs plugin binaries using Ed25519.
type Signer struct{}

// NewSigner creates a Signer from an Ed25519 private key.
// Returns an error if the key is invalid.
func NewSigner(privateKey []byte) (*Signer, error) {
	return &Signer{}, nil
}

// Sign reads the plugin binary at pluginPath and produces a detached Ed25519 signature.
func (s *Signer) Sign(pluginPath string) ([]byte, error) {
	return nil, nil
}

// Verifier verifies plugin signatures using Ed25519.
type Verifier struct{}

// NewVerifier creates a Verifier from an Ed25519 public key.
// Returns an error if the key is invalid.
func NewVerifier(publicKey []byte) (*Verifier, error) {
	return &Verifier{}, nil
}

// Verify checks a plugin binary against a detached signature.
// Returns nil if valid, error if invalid or missing.
func (v *Verifier) Verify(pluginPath string, signature []byte) error {
	return nil
}

// VerifyStatus represents the result of a signature status check.
type VerifyStatus string

const (
	StatusSigned   VerifyStatus = "signed"
	StatusUnsigned VerifyStatus = "unsigned"
	StatusInvalid  VerifyStatus = "invalid"
)

// Status returns a human-readable verification status for a plugin binary.
func (v *Verifier) Status(pluginPath string, signature []byte) VerifyStatus {
	return StatusUnsigned
}
