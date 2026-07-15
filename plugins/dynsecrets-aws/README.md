# dynsecrets-aws — reference Dynamic Secrets provider

**Kind:** `aws-sts`  
**Location:** `plugins/dynsecrets-aws` (not `internal/`)  
**Binary:** `cmd/agentkms-plugin-aws`

This is the **template** for customer and OSS providers: library package + go-plugin subprocess, registered with the AgentKMS host at runtime.

## Build & register

```bash
go build -o agentkms-plugin-aws ./cmd/agentkms-plugin-aws
# install into the host plugin directory (see agentkms plugin / deploy docs)
# host StartProvider loads the binary; Kind() reports "aws-sts"
```

## Contract

| Interface | Methods |
|-----------|---------|
| `credentials.ScopeValidator` | `Kind`, `Validate`, `Narrow` |
| `credentials.CredentialVender` | `Kind`, `Vend` |

`Vend` requires an `STSClient` (`Plugin.WithSTS(...)`). Wire a real AWS STS AssumeRole adapter in the provider process; core AgentKMS never imports the AWS SDK.

## Scope params

| Param | Required |
|-------|----------|
| `role_arn` | yes |
| `session_name` | yes |
| `external_id` | no |
| `policy` | no (session policy JSON) |
| `region` | no (defaults to plugin config) |

## Customer providers

Copy this layout:

```text
plugins/dynsecrets-<yours>/
  plugin.go          # library implementing the interfaces
  plugin_test.go
cmd/agentkms-plugin-<yours>/
  main.go            # go-plugin Serve + gRPC adapter
```

Do **not** add new kinds under `internal/` or hardwire them in `cmd/server`.
