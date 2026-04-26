// Package main is the agentkms-license internal issuance CLI.
//
// This tool is Catalyst9-internal only. It is NOT distributed in public
// release artifacts. Customers receive only the signed license file (.lic);
// the signing private key and this CLI are held exclusively by Catalyst9.
//
// Usage:
//
//	agentkms-license <subcommand> [flags]
//
// Subcommands:
//
//	keygen    Generate an Ed25519 signing keypair
//	issue     Sign and produce a license file
//	verify    Validate a license file against a public key
//	inspect   Print manifest JSON from a license file (no verification)
package main

import (
	"fmt"
	"os"
)

const globalUsage = `agentkms-license — Catalyst9 internal license issuance tooling (NOT for distribution)

Usage:
  agentkms-license <subcommand> [flags]

Subcommands:
  keygen    Generate an Ed25519 signing keypair for license issuance
  issue     Sign and produce a license file for a customer
  verify    Validate a license file against a public key (exit 0=ok, 1=invalid, 2=expired)
  inspect   Print manifest JSON from a license file without verification

Run 'agentkms-license <subcommand> --help' for subcommand-specific flags.

INTERNAL TOOL: The signing private key must never exist in plaintext on disk
outside of keygen. Use the KPM pipe pattern for issuance:
  kpm get catalyst9/license-signing-key/v1 | agentkms-license issue --private-key - ...
`

func main() {
	os.Exit(run(os.Args[1:]))
}

// run dispatches subcommands and returns an exit code.
// Extracted for testability.
func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, globalUsage)
		return 1
	}

	switch args[0] {
	case "keygen":
		return runKeygen(args[1:])
	case "issue":
		return runIssue(args[1:])
	case "verify":
		return runVerify(args[1:])
	case "inspect":
		return runInspect(args[1:])
	case "--help", "-h", "help":
		fmt.Fprint(os.Stdout, globalUsage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n%s", args[0], globalUsage)
		return 1
	}
}
