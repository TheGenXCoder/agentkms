package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

const inspectUsage = `Usage: agentkms-license inspect [flags]

Print manifest JSON from a license file without signature verification.

Flags:
  --license string   Path to the license file (required)
  --raw              Print raw base64url-encoded lines instead of decoded JSON

WARNING: No signature verification is performed. Use 'agentkms-license verify'
to confirm authenticity.
`

// runInspect executes the inspect subcommand and returns an exit code.
func runInspect(args []string) int {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, inspectUsage) }

	licensePath := fs.String("license", "", "Path to the license file (required)")
	raw := fs.Bool("raw", false, "Print raw base64url-encoded lines instead of decoded JSON")

	if err := fs.Parse(args); err != nil {
		return 1
	}

	if *licensePath == "" {
		fmt.Fprintln(os.Stderr, "error: --license is required")
		return 1
	}

	// Always print verification warning to stderr.
	fmt.Fprintln(os.Stderr, "WARNING: signature was NOT verified — use 'agentkms-license verify' to check authenticity")

	licenseData, err := os.ReadFile(*licensePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: read license file %q: %v\n", *licensePath, err)
		return 1
	}

	if *raw {
		return inspectRaw(licenseData)
	}
	return inspectJSON(licenseData)
}

// inspectJSON decodes the license file and pretty-prints the manifest JSON.
func inspectJSON(data []byte) int {
	_, _, manifestBytes, err := DecodeFile(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: parse license: %v\n", err)
		return 1
	}

	// Pretty-print the manifest JSON.
	var v interface{}
	if err := json.Unmarshal(manifestBytes, &v); err != nil {
		fmt.Fprintf(os.Stderr, "error: re-parse manifest JSON: %v\n", err)
		return 1
	}
	pretty, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: pretty-print manifest: %v\n", err)
		return 1
	}
	fmt.Printf("%s\n", pretty)
	return 0
}

// inspectRaw prints the two raw base64url lines with labels.
func inspectRaw(data []byte) int {
	// We need the raw lines — re-parse the file without full decoding so we
	// can show exactly what is in the file even if JSON is malformed.
	// Use the same splitting logic as DecodeFile.
	if len(data) > maxLicenseFileBytes {
		fmt.Fprintf(os.Stderr, "error: license file exceeds 4 KB limit\n")
		return 1
	}

	content := string(data)
	// Strip trailing newline(s) and split on internal newline.
	for len(content) > 0 && content[len(content)-1] == '\n' {
		content = content[:len(content)-1]
	}
	parts := splitLines(content)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		fmt.Fprintf(os.Stderr, "error: invalid license format: expected exactly 2 non-empty lines\n")
		return 1
	}

	fmt.Printf("manifest:  %s\n", parts[0])
	fmt.Printf("signature: %s\n", parts[1])
	return 0
}

// splitLines splits content on the first newline only, returning exactly the
// two halves. If there is no newline, returns a single-element slice.
func splitLines(content string) []string {
	for i := 0; i < len(content); i++ {
		if content[i] == '\n' {
			return []string{content[:i], content[i+1:]}
		}
	}
	return []string{content}
}
