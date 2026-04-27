# T5 Follow-up: Provider-Params Drop Bug — Fix Report

**Date:** 2026-04-26
**Triggered by:** T6 demo failure — `kpm cred rotate blog-audit-rotator` returned `unknown app "default"; registered apps: [blog-audit]`
**Status:** FIXED. Params-drop bug resolved. Workaround alias removed.

---

## Root Cause: Three-Layer Drop

The `provider_params` from the binding (`{"app_name":"blog-audit"}`) were silently dropped at **three compounding points** in the rotation chain. The github plugin read `app_name` from `scope.Params` — but the value never arrived there.

### Drop Point 1 — `state_machine.go:112` (Pro)

```go
// BEFORE (bug)
vc, err := sm.host.VendCredential(ctx, b.GetProviderKind(), b.GetScope(), nil)

// AFTER (fix)
vc, err := sm.host.VendCredential(ctx, b.GetProviderKind(), b.GetScope(), b.GetProviderParams())
```

The orchestrator fetched the binding (which contains `provider_params`), then passed literal `nil` instead of `b.GetProviderParams()` to the host client.

**File:** `/Users/BertSmith/personal/catalyst9/projects/agentkms-pro/internal/orchestrator/state_machine.go` line 112

### Drop Point 2 — `host/client.go:103` (Pro)

```go
// BEFORE (bug): accepted params map[string]any but never put it in the proto request
func (c *Client) VendCredential(ctx context.Context, providerKind string, scope *pluginv1.Scope, params map[string]any) (*pluginv1.VendedCredential, error) {
    req := &pluginv1.VendCredentialRequest{
        ProviderKind: providerKind,
        Scope:        scope,
        // ProviderParams: <MISSING>
    }

// AFTER (fix): takes *structpb.Struct, populates ProviderParams in proto
func (c *Client) VendCredential(ctx context.Context, providerKind string, scope *pluginv1.Scope, providerParams *structpb.Struct) (*pluginv1.VendedCredential, error) {
    req := &pluginv1.VendCredentialRequest{
        ProviderKind:   providerKind,
        Scope:          scope,
        ProviderParams: providerParams,
    }
```

Even if the state machine had passed non-nil params, the client would have discarded them. The old signature accepted `map[string]any` which was an unused placeholder parameter; it was never serialized into the gRPC request.

**File:** `/Users/BertSmith/personal/catalyst9/projects/agentkms-pro/internal/host/client.go` lines 103–116

### Drop Point 3 — `host_service.go:313` (OSS)

```go
// BEFORE (bug): scope built from req.GetScope() only; provider_params discarded
scope := protoToScope(req.GetScope())
vc, err := vender.Vend(ctx, scope)

// AFTER (fix): provider_params merged into scope.Params before dispatch
scope := protoToScope(req.GetScope())
if pp := req.GetProviderParams(); pp != nil {
    if scope.Params == nil {
        scope.Params = make(map[string]any)
    }
    for k, v := range pp.AsMap() {
        if _, exists := scope.Params[k]; !exists {
            scope.Params[k] = v
        }
    }
}
vc, err := vender.Vend(ctx, scope)
```

The OSS host service received the `VendCredentialRequest` (with `provider_params` populated), but only converted `req.GetScope()` to Go — ignoring `req.GetProviderParams()` entirely before calling `vender.Vend`. This is the join point where binding-level configuration must reach the plugin.

**File:** `/Users/BertSmith/personal/catalyst9/projects/agentkms/internal/plugin/host_service.go` lines 313–345

---

## Chain Diagram (Before Fix)

```
Binding.ProviderParams = {"app_name": "blog-audit"}
    │
    ▼
state_machine.go:112
    VendCredential(ctx, kind, scope, nil)   ← DROP 1: nil passed
    │
    ▼
host/client.go:103
    VendCredentialRequest{Scope: scope}      ← DROP 2: ProviderParams not set
    │   [gRPC →]
    ▼
host_service.go:323
    scope = protoToScope(req.GetScope())    ← DROP 3: provider_params ignored
    vender.Vend(ctx, scope)
    │   [gRPC →]
    ▼
github plugin Vend()
    appName = scope.Params["app_name"]      ← empty → fallback "default"
    lookupApp("default")                    ← ERROR: unknown app "default"
```

## Chain Diagram (After Fix)

```
Binding.ProviderParams = {"app_name": "blog-audit"}
    │
    ▼
state_machine.go:112
    VendCredential(ctx, kind, scope, b.GetProviderParams())   ← fixed
    │
    ▼
host/client.go:103
    VendCredentialRequest{
        Scope:          scope,
        ProviderParams: providerParams,   ← fixed
    }
    │   [gRPC →]
    ▼
host_service.go:313
    scope = protoToScope(req.GetScope())
    // merge provider_params into scope.Params (scope wins on collision)
    scope.Params["app_name"] = "blog-audit"   ← fixed
    vender.Vend(ctx, scope)
    │   [gRPC →]
    ▼
github plugin Vend()
    appName = scope.Params["app_name"]  = "blog-audit"   ← correct
    lookupApp("blog-audit")             ← SUCCESS
```

---

## Merge Semantics

`provider_params` keys are merged into `scope.Params` with scope-wins-on-collision semantics: if `scope.Params` already contains a key (runtime caller override), `provider_params` does not overwrite it. This preserves the intuition that the caller can override binding-level defaults.

---

## Files Modified

### agentkms-pro (Pro)

| File | Change |
|------|--------|
| `internal/orchestrator/state_machine.go` | Line 112: `nil` → `b.GetProviderParams()` |
| `internal/host/client.go` | `VendCredential` param type `map[string]any` → `*structpb.Struct`; added `ProviderParams` to request; added `structpb` import |
| `internal/orchestrator/state_machine_test.go` | Added `vendReqs` field to stub, added `TestRotateBinding_ProviderParamsForwarded` regression test |

### agentkms (OSS)

| File | Change |
|------|--------|
| `internal/plugin/host_service.go` | `VendCredential`: merge `req.GetProviderParams()` into `scope.Params` before dispatch |
| `internal/plugin/host_service_test.go` | Added `scopeCapturingVender`, `TestHostService_VendCredential_ProviderParams_MergedIntoScope`, `TestHostService_VendCredential_ScopeParamsWinOnCollision`; added `structpb` import |

### No proto changes required

`VendCredentialRequest.provider_params` (field 3, `google.protobuf.Struct`) already existed in both `agentkms-pro/api/plugin/v1/host.proto` and `agentkms/api/plugin/v1/host.proto`. The field was correctly defined but never populated or consumed.

`plugin.proto`'s `VendRequest` only carries `Scope` — `app_name` travels through `Scope.Params`, which is the correct vehicle. No proto regeneration needed.

---

## Workaround Removed

`~/.agentkms/plugins/github-apps.yaml` updated. The `"default"` alias entry has been removed:

```yaml
# BEFORE (workaround present)
apps:
  - app_name: blog-audit
    private_key_path: /tmp/blog-audit-app.pem
    app_id: 3512662
    installation_id: 127321567
  - app_name: default        ← WORKAROUND: no longer needed
    private_key_path: /tmp/blog-audit-app.pem
    app_id: 3512662
    installation_id: 127321567

# AFTER (workaround removed)
apps:
  - app_name: blog-audit
    private_key_path: /tmp/blog-audit-app.pem
    app_id: 3512662
    installation_id: 127321567
```

---

## Verification Results

### Tests

All existing tests pass in both repos. New regression tests added:

**agentkms-pro:**
```
ok  github.com/catalyst9ai/agentkms-pro/internal/orchestrator   0.441s
```
`TestRotateBinding_ProviderParamsForwarded` — verifies that `VendCredentialRequest.ProviderParams` contains `{"app_name":"blog-audit"}` when a binding with `provider_params` is rotated.

**agentkms:**
```
ok  github.com/agentkms/agentkms/internal/plugin   16.9s
```
- `TestHostService_VendCredential_ProviderParams_MergedIntoScope` — verifies that `provider_params` keys arrive in the `Scope.Params` seen by the vender.
- `TestHostService_VendCredential_ScopeParamsWinOnCollision` — verifies that `scope.Params` values take precedence over `provider_params` on key collision.

### Runtime Verification

1. `~/.agentkms/plugins/github-apps.yaml` updated to remove the `"default"` alias (only `blog-audit` entry).
2. Dev server rebuilt and restarted. Server log: `[plugin] provider "github" started (kind="github-pat")` — github plugin starts with 1 app registered.
3. `kpm cred rotate blog-audit-rotator` run.

**Before fix (T6 demo):**
```
host error [HOST_PERMANENT]: vend from provider "github-pat":
  github plugin: [permanent] unknown app "default"; registered apps: [blog-audit]
```

**After fix:**
```
error: rotation of "blog-audit-rotator" failed: all destinations failed
```

The "unknown app default" error is **gone**. The audit log confirms:
- `binding_rotate_start` — orchestrator reached the state machine
- `destination_deliver` outcome=error, `error_detail: "ghsecret: [permanent] FetchPublicKey: HTTP 401: Bad credentials"` — GitHub vend succeeded and returned a token; the gh-secret destination plugin then attempted to use a *separate* GH token (the GH Actions API token used to write the repo secret) which has expired since T6

The destination 401 is a separate issue: the gh-secret destination plugin needs a refreshed GH API token to write the secret to `TheGenXCoder/blog`. This is outside the scope of the params-drop fix.

### GH Actions Secret Timestamp

Not updated — the destination delivery failed due to the expired GH API token (401 on FetchPublicKey). The params-drop fix is confirmed correct by the audit chain showing the github vend completed successfully; the failure is downstream at gh-secret delivery.

---

## New Blockers

**BLOCKER-GH-SECRET-401:** The gh-secret destination plugin gets HTTP 401 when fetching the repo's public key for secret encryption. The GH API token used by `agentkms-plugin-gh-secret` to authenticate to the `repos/TheGenXCoder/blog` API has expired. This token was presumably set during T6 setup.

**Resolution path:** Re-provision the GH API token used by the gh-secret plugin (separate from the GH App token the github vender mints). The gh-secret plugin uses a PAT or GH App token of its own to write secrets via the GitHub Actions API — that credential needs to be refreshed.

This is distinct from the params-drop bug (which is fully fixed) and does not affect the fix's correctness.

---

## Notes

### CGO Build Issue (macOS-specific, non-blocking)

The OSS deploy script (`deploy-oss-plugins.sh`) uses `CGO_ENABLED=1` by default. On this macOS development machine, CGO-enabled binaries newly built in this session are killed with SIGKILL (exit 137) by the OS when launched as subprocess. The workaround is `CGO_ENABLED=0` at build time:

```bash
CGO_ENABLED=0 go build -o ~/.agentkms/plugins/agentkms-plugin-github ./cmd/agentkms-plugin-github/
CGO_ENABLED=0 go build -o ~/.agentkms/plugins/agentkms-plugin-gh-secret ./cmd/agentkms-plugin-gh-secret/
```

This is a local dev environment artifact (Gatekeeper or similar). The deploy script should be updated to default to `CGO_ENABLED=0` for local plugin builds.
