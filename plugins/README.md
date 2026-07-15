# AgentKMS plugins (extension surface)

Dynamic secrets and other extensions **register with the server** as plugins.
They are **not** hardwired into `cmd/server`.

## Reference dynamic-secrets providers

| Provider | Kind | Library | Binary |
|----------|------|---------|--------|
| AWS STS | `aws-sts` | [`dynsecrets-aws`](./dynsecrets-aws/) | `go build -o agentkms-plugin-aws ./cmd/agentkms-plugin-aws` |
| GitHub App tokens | `github-pat` | [`dynsecrets-github`](./dynsecrets-github/) | `go build -o agentkms-plugin-github ./cmd/agentkms-plugin-github` |

These are the **canonical examples** of the Terraform-style model:

1. Implement `credentials.ScopeValidator` + `credentials.CredentialVender` in a library package under `plugins/`.
2. Ship a `cmd/agentkms-plugin-*` binary that serves go-plugin gRPC (`credential_vender`).
3. Install/start the binary via the AgentKMS plugin host → kind is registered at runtime.
4. Bind paths + policy; clients vend via AgentKMS (not by importing provider code in core).

## Customer / internal tools

Copy `dynsecrets-aws` (simpler) or `dynsecrets-github` (host broker for secrets).  
Do **not** add new kinds under `internal/`.

## Design

See [docs/design/2026-07-15-dynsecrets-provider-extraction.md](../docs/design/2026-07-15-dynsecrets-provider-extraction.md).
