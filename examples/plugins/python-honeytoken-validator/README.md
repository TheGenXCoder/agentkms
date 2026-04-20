# Python Reference Plugin — Honeytoken Scope Validator

A minimal but complete AgentKMS plugin written in Python. Demonstrates
how to implement the `ScopeValidatorService` gRPC interface in a
non-Go language.

## What this does

Validates "honeytoken" credential scopes. Honeytokens are fake
credentials planted as tripwires — this validator ensures they carry a
`name` (identifying the token) and a `purpose` (documenting why it was
planted) before issuance.

## Why this exists

Proves the AgentKMS plugin ecosystem is language-agnostic. If you can
speak gRPC, you can write a plugin. This is the reference implementation
for Python plugin authors.

## Quick start

```bash
cd examples/plugins/python-honeytoken-validator
pip install -r requirements.txt
bash generate.sh          # generate Python gRPC stubs from plugin.proto
PLUGIN_MAGIC_COOKIE=agentkms_plugin_v1 python plugin.py
```

The plugin will print its connection line to stdout and block:

```
1|1|tcp|127.0.0.1:54321|grpc
```

AgentKMS reads that line and connects. Under normal operation you do
not run the plugin directly — AgentKMS launches it as a subprocess.

## Testing

No gRPC stubs required. The validation logic is pure Python and can be
tested immediately after cloning:

```bash
pip install pytest
pytest test_plugin.py -v
```

Expected output:

```
test_plugin.py::test_kind_returns_honeytoken PASSED
test_plugin.py::test_validate_valid_scope PASSED
test_plugin.py::test_validate_missing_name PASSED
test_plugin.py::test_validate_missing_purpose PASSED
...
```

## Structure

| File | Purpose |
|---|---|
| `plugin.py` | Plugin implementation + gRPC server entrypoint |
| `test_plugin.py` | Unit tests — validation logic, no gRPC needed |
| `generate.sh` | Generates `plugin_pb2.py` / `plugin_pb2_grpc.py` from the proto |
| `requirements.txt` | Python dependencies |

## Plugin contract

This plugin implements `ScopeValidatorService` with `Kind = "honeytoken"`:

| RPC | Behaviour |
|---|---|
| `Kind` | Returns `"honeytoken"` |
| `Validate` | Requires `params.name` and `params.purpose` — both non-empty strings |
| `Narrow` | Passes requested scope through unchanged (no narrowing semantics) |

## go-plugin handshake protocol

AgentKMS uses [hashicorp/go-plugin](https://github.com/hashicorp/go-plugin) to
manage plugin subprocess lifecycle. The protocol from the plugin side is:

1. **Magic cookie check**: AgentKMS sets `PLUGIN_MAGIC_COOKIE=agentkms_plugin_v1`
   before launching the plugin binary. If the variable is absent or wrong, the
   plugin exits with a clear error rather than silently misbehaving.

2. **Advertise the address**: Print exactly one line to stdout:
   ```
   1|1|tcp|127.0.0.1:{port}|grpc
   ```
   Fields: `core_protocol|app_protocol|network|address|transport`

3. **Serve gRPC**: Listen on the advertised port and serve registered services
   until the process is killed by the host.

See `plugin.py` for the full implementation with inline comments.

## Writing your own plugin

1. Copy this directory as a starting point.
2. Replace the `KIND` constant and validation logic in `plugin.py`.
3. Implement one or more of:
   - `ScopeValidatorService` — structural validation + policy narrowing (required per-Kind)
   - `ScopeAnalyzerService` — risk/anomaly detection (optional)
   - `ScopeSerializerService` — convert scope to provider-native format (required for upstream vending)
   - `CredentialVenderService` — issue real upstream credentials
4. Run `bash generate.sh` to generate stubs for your language target.
5. Register the plugin binary in your AgentKMS config.

See [`api/plugin/v1/plugin.proto`](../../../api/plugin/v1/plugin.proto) for full
service and message definitions.
