// Package main is the standalone agentkms enroll CLI.
//
// This CLI handles production developer enrollment via OIDC/SAML SSO,
// issuing a developer certificate signed by the team's Intermediate CA.
//
// Backlog: A-09 (dev enroll), A-11 (OIDC/SAML SSO flow).
//
// For LOCAL DEV enrollment (no SSO, no network required), use:
//
//	agentkms-dev enroll
//
// This production enrollment CLI is not yet implemented (A-11, T1+).
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, `agentkms enroll: production OIDC/SSO enrollment (backlog A-11, T1+)

For local development enrollment, use:

  agentkms-dev enroll

Production enrollment requires a running AgentKMS service with OIDC/SAML
configured.  See docs/architecture.md §4.4 for the full enrollment flow.`)
	os.Exit(1)
}
