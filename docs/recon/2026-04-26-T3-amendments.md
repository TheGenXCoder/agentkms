# T3 Amendments — 2026-04-26

**OQ-T5-6 pre-commit patch:** Added `LastCredentialUUID string` (`json:"last_credential_uuid,omitempty"`) to `BindingMetadata` in `internal/credentials/binding/binding.go`. Field is written by the Pro rotation orchestrator after each successful rotation to record the UUID of the vended credential for grace-period revocation. OSS code does not write to it.

**Tests verified:** Two new test functions added to `binding_test.go` — `TestJSONRoundTrip_LastCredentialUUID` (marshal/unmarshal round-trip asserts field survives) and `TestJSONRoundTrip_LastCredentialUUID_OmitEmpty` (asserts `omitempty` suppresses the key when blank). All 14 tests in `./internal/credentials/binding/...` pass. `go build ./...` and `go vet ./...` clean.

**Spec doc updated:** `docs/specs/2026-04-25-T3-credential-binding-design.md` — added a `BindingMetadata` field reference table (5 rows) immediately before the validation rules, with `last_credential_uuid` as the final row. Added one sentence clarifying the Pro-only write path.
