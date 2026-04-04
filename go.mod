module github.com/agentkms/agentkms

// AgentKMS — Enterprise Cryptographic Services for Agentic Platforms
//
// Dependency policy: zero external dependencies for the foundation layer
// (F-01 to F-08).  All cryptographic operations use the Go standard library.
// Every new dependency added to this file requires a documented reason in
// AGENTS.md before the PR is merged.

go 1.25.0

require gopkg.in/yaml.v3 v3.0.1

require (
	golang.org/x/crypto v0.49.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/term v0.41.0 // indirect
)
