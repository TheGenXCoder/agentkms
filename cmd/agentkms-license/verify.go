package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

const verifyUsage = `Usage: agentkms-license verify [flags]

Validate a license file: parse format, verify Ed25519 signature, check expiry.

Flags:
  --license    string   Path to the license file to verify (required)
  --public-key string   Path to the PEM public key to verify against (required)
  --at         string   Override "now" for expiry check in RFC 3339 UTC (optional)

Exit codes:
  0   License is valid and not expired
  1   Invalid (bad format or bad signature)
  2   Signature valid but license is expired
`

// runVerify executes the verify subcommand and returns an exit code.
func runVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, verifyUsage) }

	licensePath := fs.String("license", "", "Path to the license file to verify (required)")
	publicKeyPath := fs.String("public-key", "", "Path to the PEM public key (required)")
	atOverride := fs.String("at", "", `Override "now" for expiry check in RFC 3339 UTC (optional)`)

	if err := fs.Parse(args); err != nil {
		return 1
	}

	if *licensePath == "" {
		fmt.Fprintln(os.Stderr, "error: --license is required")
		return 1
	}
	if *publicKeyPath == "" {
		fmt.Fprintln(os.Stderr, "error: --public-key is required")
		return 1
	}

	// Read and parse the public key.
	pubKeyPEM, err := os.ReadFile(*publicKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: read public key %q: %v\n", *publicKeyPath, err)
		return 1
	}
	pubKey, err := parsePublicKey(pubKeyPEM)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	// Read the license file.
	licenseData, err := os.ReadFile(*licensePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: read license file %q: %v\n", *licensePath, err)
		return 1
	}

	// Decode and parse.
	manifest, sigBytes, manifestBytes, err := DecodeFile(licenseData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid license format: %v\n", err)
		return 1
	}

	// Verify schema_version.
	if manifest.SchemaVersion != 1 {
		fmt.Fprintf(os.Stderr, "error: unsupported schema_version: %d (expected 1)\n", manifest.SchemaVersion)
		return 1
	}

	// Verify Ed25519 signature.
	if !ed25519.Verify(pubKey, manifestBytes, sigBytes) {
		fmt.Fprintln(os.Stderr, "error: signature verification failed")
		return 1
	}

	// Determine "now" for expiry check.
	var now time.Time
	if *atOverride != "" {
		now, err = time.Parse(time.RFC3339, *atOverride)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: parse --at %q: %v\n", *atOverride, err)
			return 1
		}
		now = now.UTC()
	} else {
		now = time.Now().UTC()
	}

	// Check expiry — exit code 2 is distinct from 1 (spec §2.4).
	if !manifest.ExpiresAt.After(now) {
		fmt.Fprintf(os.Stderr, "error: license expired at %s (now: %s)\n",
			manifest.ExpiresAt.Format(time.RFC3339), now.Format(time.RFC3339))
		return 2
	}

	// All checks passed.
	fmt.Printf("OK  license_id=%s  customer=%s  expires=%s  features=[%s]\n",
		manifest.LicenseID,
		manifest.Customer,
		manifest.ExpiresAt.Format(time.RFC3339),
		strings.Join(manifest.Features, ", "))

	return 0
}

// parsePublicKey decodes a PEM block and returns an ed25519.PublicKey.
func parsePublicKey(pemBytes []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in public key input")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("unsupported PEM block type %q: expected \"PUBLIC KEY\" (SPKI)", block.Type)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse SPKI public key: %w", err)
	}
	ed, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not Ed25519 (got %T)", key)
	}
	return ed, nil
}
