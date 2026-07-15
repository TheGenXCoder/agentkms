# dynsecrets-github — reference Dynamic Secrets provider

**Kind:** `github-pat` (GitHub App installation tokens)  
**Location:** `plugins/dynsecrets-github` (not `internal/`)  
**Binary:** `cmd/agentkms-plugin-github`

Reference provider for multi-App GitHub token vending via the HostService broker (`GetGithubApp`). Same extension model as `dynsecrets-aws`.

## Build & register

```bash
go build -o agentkms-plugin-github ./cmd/agentkms-plugin-github
```

Apps are registered server-side (`kpm gh-app register`); the plugin fetches PEMs via HostService and never writes them to disk.

## Contract

| Interface | Methods |
|-----------|---------|
| `credentials.ScopeValidator` | `Kind`, `Validate`, `Narrow` |
| `credentials.CredentialVender` | `Kind`, `Vend` |

## Scope params

| Param | Required |
|-------|----------|
| `app_name` | yes (selects registered GitHub App) |

## See also

- `plugins/dynsecrets-aws/README.md` — simpler STS-shaped provider template  
- `docs/design/2026-07-15-dynsecrets-provider-extraction.md` — product decision  
