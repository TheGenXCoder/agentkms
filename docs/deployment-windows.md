# AgentKMS Windows Deployment Runbook

This runbook covers the initial Windows dev/server deployment path used for sandbox validation.

## Scope

- Validate on a non-client Windows VM first (for example Parallels Windows 11).
- Deploy to client sandbox only after smoke tests pass and human approval is captured.
- Bind AgentKMS to `127.0.0.1:8443` by default.
- Use demo or approved sandbox secrets only.

## Binaries

Build from the AgentKMS repo:

```powershell
# Built by CI/release for windows/amd64
go build -o agentkms-dev.exe ./cmd/dev/
go build -o agentkms-server.exe ./cmd/server/
go build -o agentkms-mcp.exe ./cmd/mcp/
```

## Dev server smoke path

```powershell
$ToolDir = 'C:\Tools\AgentKMS'
$env:AGENTKMS_DIR = Join-Path $ToolDir 'dev'

.\agentkms-dev.exe enroll --client-cn default
.\agentkms-dev.exe secrets set generic/windows-smoke value=demo-secret
.\agentkms-dev.exe serve --rate-limit 0
```

In a second shell, configure KPM with the generated certs and run:

```powershell
kpm list
kpm run --plaintext --from .\.env.template -- cmd /c echo %SMOKE_SECRET%
```

## Service posture for sandbox

For the first sandbox deployment, run as a managed Windows service/process with:

- Service account: least-privilege local account where possible.
- Listener: `127.0.0.1:8443` unless a human-approved firewall exception is required.
- Data directory: `%ProgramData%\AgentKMS` or an approved sandbox path.
- Audit log: `%ProgramData%\AgentKMS\audit.ndjson`.
- Secrets: encrypted dev store for pilot; production backend requires separate approval.

## Approval gates

- Approve Windows validation results before sandbox deployment.
- Approve any non-localhost bind or firewall change.
- Approve secret import procedure.
- Preserve smoke output and audit evidence with secret values redacted.
