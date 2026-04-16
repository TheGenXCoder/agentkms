# Contributing to AgentKMS

Thanks for considering a contribution. AgentKMS is the server half of a secrets platform — it holds keys, enforces policy, and produces the audit trail that downstream consumers rely on. The bar for changes here is higher than for most open-source projects. Read this first.

## Quick start

```bash
git clone https://github.com/TheGenXCoder/agentkms.git
cd agentkms
go build ./cmd/agentkms/
go build ./cmd/agentkms-dev/
go test ./... -count=1 -race
```

## What makes a good contribution

- **Bug fixes with tests.** Write a failing test first, then fix the bug.
- **Test coverage for the underfilled areas.** `internal/backend` (50.6%) and `pkg/keystore` (57.7%) both have room.
- **Backend adapters.** Adding support for another vault? The backend interface is stable. Build tests in `internal/backend/yourname_test.go` that exercise real infrastructure (we run `openbao` in CI).
- **Documentation improvements.** README, blog posts, examples. If you got confused, others will too.
- **Performance improvements** with benchmarks proving the improvement.

## What needs discussion before a PR

Open an issue before doing any of the following. We want to talk through the design.

- **New API endpoints.** The surface area is small on purpose. Adding endpoints widens the authorization model and adds to what client implementers have to reason about.
- **Changes to the audit event schema.** The format is load-bearing for compliance and downstream indexers. Breaking it breaks deployments.
- **Changes to the policy engine.** Policy evaluates at every request; subtle changes have outsized blast radius.
- **New cryptographic primitives.** We use Go stdlib (`crypto/aes`, `crypto/cipher`, `crypto/tls`) where possible. Adding a crypto dependency needs justification.
- **Changes to the separated-storage invariant.** `kv/secrets/*` and `kv/metadata/*` are physically different paths so that list/describe/history endpoints cannot leak values. Changing that requires a strong argument.
- **Breaking changes to the client protocol.** Pre-1.0 we can break things, but we want to batch breaking changes rather than dribble them out.

## Code style

- **Follow existing patterns.** Read the code before adding to it.
- **`[]byte` for secrets, `string` only as a last resort.** See `internal/credentials/`.
- **Zero secrets after use.** Use `defer ZeroBytes(value)` or equivalent.
- **Every operation produces an audit event.** Successes, denials, errors — all three.
- **Audit events never contain secret values.** Use SHA-256 hashes when correlation is needed.
- **No secret values in error messages.** Ever. The client gets a generic error; the audit log has the details.
- **Prefer explicit flags over magic.** If a behavior needs to be opt-in, make it a flag.
- **`context.WithoutCancel(ctx)` for audit writes.** Audit events must survive client disconnection.

## Testing requirements

Every PR must:

1. **Pass `go test -race ./...`** with no new failures.
2. **Pass `go vet ./...`** with no warnings.
3. **Maintain the coverage gate.** Overall minimum 80%; security-sensitive packages (`internal/auth`, `internal/policy`, `internal/audit`) minimum 85%. Enforced by `scripts/quality_check.sh` and CI.
4. **Include tests for new code paths.** Not just happy paths — error cases too.
5. **Include adversarial tests for security-relevant changes.** If you touched the policy engine, add tests where the caller should be denied. If you touched the encrypt path, add bit-flip / truncation / wrong-key tests.

Integration tests against a real OpenBao run in CI on pushes to main and release tags:

```bash
# Start a local OpenBao
docker run -d --name=bao -e BAO_DEV_ROOT_TOKEN_ID=root \
  -p 8200:8200 openbao/openbao:latest

# Run integration tests
OPENBAO_ADDR=http://127.0.0.1:8200 OPENBAO_TOKEN=root \
  go test -race -tags=integration ./internal/backend/...
```

## Commit messages

Use [conventional commits](https://www.conventionalcommits.org/):

- `feat:` new feature
- `fix:` bug fix
- `test:` tests only
- `docs:` documentation only
- `refactor:` code restructuring with no behavior change
- `chore:` tooling, dependencies, build

Scope optional but helpful: `feat(api): ...`, `fix(policy): ...`, `test(credentials): ...`.

Commit messages should explain **why**, not just what. The diff shows what.

## Pull requests

- **Keep PRs focused.** One logical change per PR. Don't bundle refactoring with feature work.
- **Write a clear description.** What problem does this solve? What alternatives did you consider?
- **Reference the issue** if one exists. Link to the design discussion.
- **Sign your commits** (recommended). `git commit -s` or configure `user.signingkey`.

## Code review

Security-sensitive changes require review from a maintainer. Non-security changes may be merged faster. Expect 1-5 business days for initial response.

Review focuses on:

1. Does it solve the stated problem?
2. Does it introduce new risks?
3. Does it maintain the invariants in `SECURITY.md`?
4. Is it tested — including adversarial tests where the change is security-sensitive?
5. Is the code understandable by someone who isn't you?

## Security-sensitive areas

Extra care required when changing:

- `internal/api/` — HTTP handlers, request validation, response shaping
- `internal/auth/` — mTLS cert parsing, client identity extraction, session token signing
- `internal/policy/` — policy rule evaluation, deny-by-default, first-match-wins semantics
- `internal/audit/` — audit event format, validation, write path
- `internal/credentials/encrypted_kv.go` — AES-256-GCM at-rest encryption, HKDF key derivation, atomic writes
- `internal/backend/` — backend adapter interfaces (Vault, OpenBao)
- `pkg/keystore/` — EC key loading, HSM / Secure Enclave / PKCS#11 paths
- `pkg/tlsutil/` — TLS config construction, cert rotation

Changes in these areas need:

- Adversarial tests added or updated
- Security implications documented in the PR description
- A second reviewer if the change is non-trivial
- Coverage on the touched package must not decrease

## Reporting a vulnerability

**Do not open a public GitHub issue for security bugs.** See [`SECURITY.md`](SECURITY.md) for the disclosure process.

## Not sure?

Open an issue. Ask. "Is this a good idea?" is a valid question, and getting a "yes" before you spend a weekend on a PR is better than getting a "no" after.
