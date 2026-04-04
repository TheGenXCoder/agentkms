package keystore

// pkcs11.go — PKCS#11 backend stub for YubiKey and other hardware tokens.
//
// This backend requires -tags pkcs11 and the miekg/pkcs11 library.
// See YubiKeySetupInstructions() for setup details.

import (
	"errors"
	"fmt"
)

// errPKCS11NotBuilt is returned when the PKCS#11 backend is requested
// but the pkcs11 build tag is not set.
var errPKCS11NotBuilt = errors.New(
	"keystore: PKCS#11 backend not compiled in; rebuild with -tags pkcs11",
)

func openPKCS11(_ Config) (KeyStore, error) {
	return nil, fmt.Errorf("keystore: PKCS#11: %w", errPKCS11NotBuilt)
}

func generatePKCS11(_ Config) (KeyStore, error) {
	return nil, fmt.Errorf("keystore: PKCS#11: %w", errPKCS11NotBuilt)
}

// YubiKeySetupInstructions returns instructions for setting up a YubiKey.
func YubiKeySetupInstructions() string {
	return `
AgentKMS YubiKey Setup
======================
1. Install ykman:  brew install ykman  (macOS)  or  apt install yubikey-manager
2. Reset PIV applet (CAUTION: this wipes existing PIV keys):
      ykman piv reset
3. Set PIV PIN and PUK:
      ykman piv access change-pin --pin 123456 --new-pin <YOUR_PIN>
      ykman piv access change-puk --puk 12345678 --new-puk <YOUR_PUK>
4. Enroll with AgentKMS:
      PKCS11_LIB=/usr/lib/libykcs11.so \
      go run ./cmd/enroll --backend pkcs11 --pkcs11-lib $PKCS11_LIB
`
}
