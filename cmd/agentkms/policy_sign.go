package main

// policy_sign.go — `agentkms policy sign` (Task 2 of signed-policy-bundles).
//
// Offline/CI tool: reads a private key from disk, signs a policy YAML file,
// and writes a v1 Bundle JSON envelope. This file, and internal/policy's
// SignPolicyYAML, are the only places in the agentkms binary that touch
// ed25519 private key material for policy bundles — the server load path
// (Task 3) never imports a private key type, only TrustStore public keys.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/agentkms/agentkms/internal/policy"
)

const policyUsage = `Usage: agentkms policy sign --key <path> --key-id <id> --in <policy.yaml> --out <bundle.json>

Sign a policy YAML file into a v1 signed Bundle JSON envelope.

Flags:
  --key      Path to a hex-encoded Ed25519 key file (required). Accepts
             either a 32-byte seed or a 64-byte private key, hex encoded on
             a single line (surrounding whitespace/newline ignored).
  --key-id   key_id to embed in the envelope; the verifying TrustStore must
             have a public key registered under this id (required).
  --in       Path to the policy YAML document to sign (required).
  --out      Path to write the JSON bundle envelope to (required).

Never commit the private key file. Store it in a secrets manager (kpm,
OpenBao, etc.) and delete the local copy after signing.
`

func runPolicy(args []string) int {
	if len(args) < 1 {
		fmt.Fprint(os.Stderr, policyUsage)
		return 1
	}
	switch args[0] {
	case "sign":
		return runPolicySign(args[1:])
	case "help", "-h", "--help":
		fmt.Print(policyUsage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown policy subcommand %q\n", args[0])
		fmt.Fprint(os.Stderr, policyUsage)
		return 1
	}
}

func runPolicySign(args []string) int {
	fs := flag.NewFlagSet("policy sign", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, policyUsage) }

	keyPath := fs.String("key", "", "path to hex-encoded ed25519 key file (seed or private key)")
	keyID := fs.String("key-id", "", "key_id to embed in the bundle envelope")
	inPath := fs.String("in", "", "path to policy YAML to sign")
	outPath := fs.String("out", "", "path to write the signed bundle JSON")

	if err := fs.Parse(args); err != nil {
		return 1
	}

	if *keyPath == "" || *keyID == "" || *inPath == "" || *outPath == "" {
		fmt.Fprintln(os.Stderr, "error: --key, --key-id, --in, and --out are all required")
		fs.Usage()
		return 1
	}

	priv, err := loadEd25519PrivateKey(*keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading key: %v\n", err)
		return 1
	}

	yamlBody, err := os.ReadFile(*inPath) // #nosec G304 — operator-supplied CLI path
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading %s: %v\n", *inPath, err)
		return 1
	}

	bundle, err := policy.SignPolicyYAML(yamlBody, priv, *keyID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: signing: %v\n", err)
		return 1
	}

	out, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: marshalling bundle: %v\n", err)
		return 1
	}
	out = append(out, '\n')

	if err := os.WriteFile(*outPath, out, 0o644); err != nil { // #nosec G306 — bundle is a public signed artifact, not a secret
		fmt.Fprintf(os.Stderr, "error: writing %s: %v\n", *outPath, err)
		return 1
	}

	fmt.Printf("Signed bundle written to %s (key_id=%s)\n", *outPath, *keyID)
	return 0
}

// loadEd25519PrivateKey reads a hex-encoded Ed25519 key from path. It accepts
// either a 32-byte seed (expanded via ed25519.NewKeyFromSeed) or a raw
// 64-byte private key. Any other decoded length is rejected — fail closed
// rather than guess at operator intent.
func loadEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path) // #nosec G304 — operator-supplied CLI path
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}
	trimmed := strings.TrimSpace(string(raw))
	decoded, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("key file is not valid hex: %w", err)
	}
	switch len(decoded) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(decoded), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(decoded), nil
	default:
		return nil, fmt.Errorf("key file has %d bytes, want %d (seed) or %d (private key)", len(decoded), ed25519.SeedSize, ed25519.PrivateKeySize)
	}
}
