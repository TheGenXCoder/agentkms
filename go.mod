module github.com/agentkms/agentkms

// AgentKMS — Enterprise Cryptographic Services for Agentic Platforms
//
// Dependency policy: zero external dependencies for the foundation layer
// (F-01 to F-08).  All cryptographic operations use the Go standard library.
// Every new dependency added to this file requires a documented reason in
// AGENTS.md before the PR is merged.

go 1.25
