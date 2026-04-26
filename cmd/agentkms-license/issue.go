package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const issueUsage = `Usage: agentkms-license issue [flags]

Sign and produce a license file.

Flags:
  --private-key string   Path to PEM private key, or "-" to read from stdin (required)
  --customer    string   Customer display name (required)
  --email       string   Customer email address (required)
  --expires     string   Expiration in RFC 3339 UTC, e.g. "2027-05-01T00:00:00Z" (required)
  --feature     string   Feature string (repeatable; at least one required)
  --out         string   Output license file path (required)
  --license-id  string   Override UUID v4 for the license_id field (default: auto-generated)
  --issued-at   string   Override issued_at in RFC 3339 UTC (default: current UTC time)
  --force                Overwrite existing output file

KPM pipe pattern (recommended):
  kpm get catalyst9/license-signing-key/v1 | \
    agentkms-license issue --private-key - --customer "Acme" --email "admin@acme.example" \
      --expires "2027-05-01T00:00:00Z" --feature rotation_orchestrator --out acme.lic
`

// featureList implements flag.Value for repeatable --feature flags.
type featureList []string

func (f *featureList) String() string { return strings.Join(*f, ",") }
func (f *featureList) Set(v string) error {
	*f = append(*f, v)
	return nil
}

// runIssue executes the issue subcommand and returns an exit code.
func runIssue(args []string) int {
	fs := flag.NewFlagSet("issue", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, issueUsage) }

	privateKeyPath := fs.String("private-key", "", `Path to PEM private key, or "-" to read from stdin (required)`)
	customer := fs.String("customer", "", "Customer display name (required)")
	email := fs.String("email", "", "Customer email address (required)")
	expires := fs.String("expires", "", `Expiration in RFC 3339 UTC, e.g. "2027-05-01T00:00:00Z" (required)`)
	out := fs.String("out", "", "Output license file path (required)")
	licenseID := fs.String("license-id", "", "Override UUID v4 for the license_id field (default: auto-generated)")
	issuedAtOverride := fs.String("issued-at", "", "Override issued_at in RFC 3339 UTC (default: current UTC time)")
	force := fs.Bool("force", false, "Overwrite existing output file")

	var features featureList
	fs.Var(&features, "feature", "Feature string (repeatable; at least one required)")

	if err := fs.Parse(args); err != nil {
		return 1
	}

	// Validate required flags.
	if *privateKeyPath == "" {
		fmt.Fprintln(os.Stderr, "error: --private-key is required")
		return 1
	}
	if *customer == "" {
		fmt.Fprintln(os.Stderr, "error: --customer is required")
		return 1
	}
	if *email == "" {
		fmt.Fprintln(os.Stderr, "error: --email is required")
		return 1
	}
	if *expires == "" {
		fmt.Fprintln(os.Stderr, "error: --expires is required")
		return 1
	}
	if *out == "" {
		fmt.Fprintln(os.Stderr, "error: --out is required")
		return 1
	}
	if len(features) == 0 {
		fmt.Fprintln(os.Stderr, "error: at least one --feature is required")
		return 1
	}

	// Refuse to overwrite unless --force is set.
	if !*force {
		if _, err := os.Stat(*out); err == nil {
			fmt.Fprintf(os.Stderr, "error: output file already exists: %s (use --force to overwrite)\n", *out)
			return 1
		}
	}

	// Read private key PEM.
	var privPEMBytes []byte
	if *privateKeyPath == "-" {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: read private key from stdin: %v\n", err)
			return 1
		}
		privPEMBytes = b
	} else {
		b, err := os.ReadFile(*privateKeyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: read private key file %q: %v\n", *privateKeyPath, err)
			return 1
		}
		privPEMBytes = b
	}

	privKey, err := parsePrivateKey(privPEMBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	// Parse --expires.
	expiresAt, err := time.Parse(time.RFC3339, *expires)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: parse --expires %q: must be RFC 3339 UTC (e.g. \"2027-05-01T00:00:00Z\"): %v\n", *expires, err)
		return 1
	}
	expiresAt = expiresAt.UTC()

	// Determine issued_at.
	var issuedAt time.Time
	if *issuedAtOverride != "" {
		issuedAt, err = time.Parse(time.RFC3339, *issuedAtOverride)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: parse --issued-at %q: must be RFC 3339 UTC: %v\n", *issuedAtOverride, err)
			return 1
		}
		issuedAt = issuedAt.UTC()
	} else {
		issuedAt = time.Now().UTC().Truncate(time.Second)
	}

	if !expiresAt.After(issuedAt) {
		fmt.Fprintf(os.Stderr,
			"error: --expires must be after --issued-at (got expires=%s, issued_at=%s)\n",
			expiresAt.Format(time.RFC3339), issuedAt.Format(time.RFC3339))
		return 1
	}

	// Determine license_id.
	id := *licenseID
	if id == "" {
		id, err = newUUID()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: generate UUID: %v\n", err)
			return 1
		}
	}

	// Build manifest.
	manifest := LicenseManifest{
		LicenseID:     id,
		Customer:      *customer,
		Email:         *email,
		IssuedAt:      issuedAt,
		ExpiresAt:     expiresAt,
		Features:      []string(features),
		SchemaVersion: 1,
	}

	// Marshal manifest JSON.
	manifestBytes, err := MarshalManifest(manifest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: marshal manifest: %v\n", err)
		return 1
	}

	// Sign with Ed25519.
	signature := ed25519.Sign(privKey, manifestBytes)

	// Encode license file.
	licenseData := EncodeFile(manifestBytes, signature)

	// Write to output file (mode 0644 — the .lic file is a public artifact).
	if err := os.WriteFile(*out, licenseData, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error: write license file: %v\n", err)
		return 1
	}

	// Print confirmation manifest JSON to stderr.
	fmt.Fprintf(os.Stderr, "%s\n", manifestBytes)

	// Print summary to stdout.
	fmt.Println("License issued successfully.")
	fmt.Printf("File:        %s\n", *out)
	fmt.Printf("License ID:  %s\n", manifest.LicenseID)
	fmt.Printf("Customer:    %s <%s>\n", manifest.Customer, manifest.Email)
	fmt.Printf("Issued:      %s\n", manifest.IssuedAt.Format(time.RFC3339))
	fmt.Printf("Expires:     %s\n", manifest.ExpiresAt.Format(time.RFC3339))
	fmt.Printf("Features:    %s\n", strings.Join(manifest.Features, ", "))

	return 0
}

// parsePrivateKey decodes a PEM block and returns an ed25519.PrivateKey.
// Accepts PKCS#8 PEM ("PRIVATE KEY") or raw "ED25519 PRIVATE KEY" PEM.
func parsePrivateKey(pemBytes []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in private key input")
	}

	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
		}
		ed, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not Ed25519 (got %T)", key)
		}
		return ed, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q: expected \"PRIVATE KEY\" (PKCS#8)", block.Type)
	}
}

// newUUID generates a UUID v4 using crypto/rand.
// Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
// No external dependency — implemented inline per spec guidance.
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	// Set version 4 bits.
	b[6] = (b[6] & 0x0f) | 0x40
	// Set variant bits (RFC 4122 §4.1.1: top two bits = 10).
	b[8] = (b[8] & 0x3f) | 0x80

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4],
		b[4:6],
		b[6:8],
		b[8:10],
		b[10:16],
	), nil
}
