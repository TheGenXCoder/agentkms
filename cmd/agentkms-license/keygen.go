package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
)

const keygenUsage = `Usage: agentkms-license keygen [flags]

Generate an Ed25519 signing keypair for license issuance.

Flags:
  --private-key string   Output path for PEM-encoded private key (required)
  --public-key  string   Output path for PEM-encoded public key (required)
  --key-version int      Integer label for this key epoch; printed in output (default 1)
  --force                Overwrite existing output files (default: refuse)
`

// runKeygen executes the keygen subcommand and returns an exit code.
func runKeygen(args []string) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, keygenUsage) }

	privateKeyPath := fs.String("private-key", "", "Output path for PEM-encoded private key (required)")
	publicKeyPath := fs.String("public-key", "", "Output path for PEM-encoded public key (required)")
	keyVersion := fs.Int("key-version", 1, "Integer label for this key epoch")
	force := fs.Bool("force", false, "Overwrite existing output files")

	if err := fs.Parse(args); err != nil {
		return 1
	}

	if *privateKeyPath == "" {
		fmt.Fprintln(os.Stderr, "error: --private-key is required")
		return 1
	}
	if *publicKeyPath == "" {
		fmt.Fprintln(os.Stderr, "error: --public-key is required")
		return 1
	}

	// Refuse to overwrite unless --force is set.
	if !*force {
		for _, path := range []string{*privateKeyPath, *publicKeyPath} {
			if _, err := os.Stat(path); err == nil {
				fmt.Fprintf(os.Stderr,
					"error: output file already exists: %s\nUse --force to overwrite. Overwriting a key in use will invalidate all licenses signed with it.\n",
					path)
				return 1
			}
		}
	}

	// Generate Ed25519 keypair.
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to generate keypair: %v\n", err)
		return 1
	}

	// Marshal private key as PKCS#8 PEM.
	privDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: marshal private key: %v\n", err)
		return 1
	}
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privDER,
	})

	// Marshal public key as SPKI PEM.
	pubDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: marshal public key: %v\n", err)
		return 1
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})

	// Write private key (mode 0600).
	if err := os.WriteFile(*privateKeyPath, privPEM, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "error: write private key: %v\n", err)
		return 1
	}

	// Write public key (mode 0644).
	if err := os.WriteFile(*publicKeyPath, pubPEM, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error: write public key: %v\n", err)
		return 1
	}

	// Compute SHA-256 fingerprint of the raw public key bytes (the Ed25519
	// 32-byte public key, not the SPKI DER).
	fingerprint := publicKeyFingerprint(pubKey)

	fmt.Printf("Key version:    %d\n", *keyVersion)
	fmt.Printf("Private key:    %s  (mode 0600)\n", *privateKeyPath)
	fmt.Printf("Public key:     %s  (mode 0644)\n", *publicKeyPath)
	fmt.Printf("Fingerprint:    SHA256:%s\n", fingerprint)
	fmt.Println()
	fmt.Println("NEXT STEPS:")
	fmt.Printf("1. Store the private key in KPM:\n")
	fmt.Printf("   kpm set catalyst9/license-signing-key/v%d < %s\n", *keyVersion, *privateKeyPath)
	fmt.Printf("2. Delete the local private key file:\n")
	fmt.Printf("   rm %s\n", *privateKeyPath)
	fmt.Printf("3. Embed the public key bytes in internal/license/verify.go before the Pro plugin release.\n")

	return 0
}

// publicKeyFingerprint computes a colon-separated lowercase hex SHA-256
// fingerprint of the raw Ed25519 public key bytes (16 bytes = 32 hex chars,
// split into 16 colon-separated pairs).
func publicKeyFingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	// Use the first 16 bytes (128-bit prefix) colon-separated, lowercase hex.
	half := sum[:16]
	out := make([]byte, 0, 16*3-1)
	for i, b := range half {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hexNibble(b>>4), hexNibble(b&0x0f))
	}
	return string(out)
}

func hexNibble(n byte) byte {
	if n < 10 {
		return '0' + n
	}
	return 'a' + (n - 10)
}
