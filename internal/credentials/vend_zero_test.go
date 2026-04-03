package credentials

import "testing"

func TestVendedCredential_Zero(t *testing.T) {
	cred := &VendedCredential{
		APIKey: []byte("secret123"),
	}
	cred.Zero()

	for i, b := range cred.APIKey {
		if b != 0 {
			t.Errorf("Expected byte at %d to be 0, got %v", i, b)
		}
	}
}
