module github.com/agentkms/agentkms

// AgentKMS — Enterprise Cryptographic Services for Agentic Platforms
//
// Dependency policy: zero external dependencies for the foundation layer
// (F-01 to F-08).  All cryptographic operations use the Go standard library.
// Every new dependency added to this file requires a documented reason in
// AGENTS.md before the PR is merged.

go 1.25.0

require (
	github.com/go-webauthn/webauthn v0.16.2
	golang.org/x/crypto v0.49.0
	golang.org/x/term v0.41.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/fxamacker/cbor/v2 v2.9.1 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/x v0.2.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/tinylib/msgp v1.6.3 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/sys v0.42.0 // indirect
)
