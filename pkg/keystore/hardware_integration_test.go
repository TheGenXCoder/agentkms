//go:build integration

// hardware_integration_test.go runs the Secure Enclave and PKCS#11 tests
// against real hardware.  These tests are excluded from normal `go test ./...`
// runs because they require:
//   - macOS with Apple Secure Enclave (M1/M2/M3 or T2) for BackendSecureEnclave
//   - A connected YubiKey with PIV applet for BackendPKCS11
//
// Run with:
//   go test -tags integration -run TestHardware ./pkg/keystore/
//
// These are intentionally in a separate file with the integration build tag
// so the regular quality gate does not fail on machines without hardware tokens.

package keystore_test
