package keystore

// pkcs11.go — PKCS#11 backend for YubiKey and other hardware tokens.
//
// PKCS#11 is the standard cryptographic API for hardware security modules.
// This backend supports any PKCS#11 provider:
//   - YubiKey (libykcs11.so / ykcs11.dll)
//   - OpenSC (opensc-pkcs11.so) for smart cards and other tokens
//   - SoftHSM2 (libsofthsm2.so) for testing
//
// NOTE: This backend requires a build tag and a CGo PKCS#11 library.
// To enable: go build -tags pkcs11 ./...
// The PKCS#11 library dependency (miekg/pkcs11 or ThalesIgnite/crypto11)
// is documented in go.mod and requires explicit opt-in per the dependency
// policy in AGENTS.md.
//
// For the current release, the PKCS#11 backend is scaffolded but disabled
// by default.  To activate it:
//   1. Run: go get github.com/miekg/pkcs11
//   2. Rebuild with -tags pkcs11
//   3. Set PKCS11Lib in Config to your library path (e.g. /usr/lib/libykcs11.so)

import (
	"crypto"
	"errors"
	"fmt"
)

// pkcs11NotAvailableError is returned when the PKCS#11 backend is requested
// but the pkcs11 build tag is not set.
var errPKCS11NotBuilt = errors.New(
	"keystore: PKCS#11 backend not compiled in; rebuild with -tags pkcs11\n" +
		"  For YubiKey on Linux:  go build -tags pkcs11 -ldflags '-extldflags=-lykcs11' ./...\n" +
		"  For SoftHSM2 testing:  go build -tags pkcs11 -ldflags '-extldflags=-lsofthsm2' ./...",
)

// pkcs11Placeholder satisfies the KeyStore interface but always returns an error.
// It is replaced by the real implementation when built with -tags pkcs11.
type pkcs11Placeholder struct{}

func (pkcs11Placeholder) Backend() Backend                  { return BackendPKCS11 }
func (pkcs11Placeholder) Signer() (crypto.Signer, error)    { return nil, errPKCS11NotBuilt }
func (pkcs11Placeholder) PublicKey() (crypto.PublicKey, error) { return nil, errPKCS11NotBuilt }
func (pkcs11Placeholder) Close() error                      { return nil }

func openPKCS11(cfg Config) (KeyStore, error) {
	return nil, fmt.Errorf("keystore: PKCS#11: %w", errPKCS11NotBuilt)
}

func generatePKCS11(cfg Config) (KeyStore, error) {
	return nil, fmt.Errorf("keystore: PKCS#11: %w", errPKCS11NotBuilt)
}

// YubiKeySetupInstructions prints instructions for setting up a YubiKey
// as an AgentKMS hardware token.
func YubiKeySetupInstructions() string {
	return `
AgentKMS YubiKey Setup
======================
1. Install ykman:  brew install ykman  (macOS)  or  apt install yubikey-manager
2. Reset PIV applet (CAUTION: this wipes existing PIV keys):
      ykman piv reset
3. Set PIV PIN and PUK (replace with your own values):
      ykman piv access change-pin --pin 123456 --new-pin <YOUR_PIN>
      ykman piv access change-puk --puk 12345678 --new-puk <YOUR_PUK>
4. Enroll with AgentKMS:
      PKCS11_LIB=/usr/lib/libykcs11.so \
      go run ./cmd/enroll --backend pkcs11 --pkcs11-lib $PKCS11_LIB
5. The YubiKey generates the key on-device.  The private key never leaves
   the hardware token.  Every signing operation requires the PIV PIN.
`
}
