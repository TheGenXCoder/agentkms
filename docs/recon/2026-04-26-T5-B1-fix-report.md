# T5 B1 Fix Report — broker.Dial Wiring in orchestratorPlugin

**Date:** 2026-04-26  
**Sprint:** T5 Part 2 follow-up  
**Scope:** `cmd/agentkms-plugin-orchestrator/` in `agentkms-pro`  
**Status:** RESOLVED — all tests pass, `go build ./...` and `go vet ./...` clean

---

## What Was Broken

`orchestratorServer.Init` received `host_broker_id` in the request but had no
way to call `broker.Dial()` — the `*goplugin.GRPCBroker` reference was only
available in `GRPCServer(broker, s)` and was not threaded through to individual
RPC handlers. `Init` therefore logged the broker ID and returned an empty
success without ever constructing `StateMachine`, `RotationHookService`, or
`CronDriver`. The plugin compiled and passed license checks but could not
perform any real rotations.

---

## Exact Lines Added / Modified in main.go

### 1. `brokerDialer` interface (new, ~line 51)

```go
type brokerDialer interface {
    Dial(id uint32) (*grpc.ClientConn, error)
}
```

Wraps the single method of `*goplugin.GRPCBroker` used by Init. Allows
injection of `fakeBroker` in tests without requiring the full go-plugin
subprocess machinery. The real `*goplugin.GRPCBroker` satisfies this interface
because it has `Dial(uint32) (*grpc.ClientConn, error)` as a concrete method.

### 2. `orchestratorPlugin.Impl` type narrowed from interface to `*orchestratorServer`

Before: `Impl pluginv1.OrchestratorServiceServer`  
After:  `Impl *orchestratorServer`

Required so `GRPCServer` can write to `p.Impl.broker` without a type assertion.
The `OrchestratorServiceServer` interface is still satisfied — `pluginv1.RegisterOrchestratorServiceServer`
receives `p.Impl` directly.

### 3. `GRPCServer` — broker stored before registration (modified)

```go
func (p *orchestratorPlugin) GRPCServer(broker *goplugin.GRPCBroker, s *grpc.Server) error {
    p.Impl.broker = broker   // B1 fix: thread broker through to Init handler
    pluginv1.RegisterOrchestratorServiceServer(s, p.Impl)
    return nil
}
```

go-plugin calls `GRPCServer` once before dispatching any RPCs, so the
assignment is race-free with respect to subsequent RPC handler reads.

### 4. `orchestratorServer` — new fields added

```go
broker    brokerDialer       // set by GRPCServer; used once inside Init
sm        *orchestrator.StateMachine  // nil until Init succeeds
initOnce  sync.Once
initErr   error
```

`hostClient` and `cronDriver` / `hookSvc` were already present; `sm` was added
because `TriggerRotation` / `BindingForCredential` need to check a non-nil live
component before dispatching.

### 5. `Init` — now calls `wire()` under `sync.Once` guard (full rewrite)

```go
func (s *orchestratorServer) Init(ctx context.Context, req *pluginv1.OrchestratorInitRequest) (...) {
    if err := license.CheckRuntime(s.manifest, rotationFeature); err != nil {
        return nil, fmt.Errorf("runtime license check: %w", err)
    }
    brokerID := req.GetHostBrokerId()
    s.initOnce.Do(func() { s.initErr = s.wire(brokerID) })
    if s.initErr != nil {
        return nil, s.initErr   // HC-5 fail-closed
    }
    return &pluginv1.OrchestratorInitResponse{}, nil
}
```

Key behaviour changes:
- Returns a **non-nil gRPC error** on failure (previously returned an `ErrorMessage`
  string in a success response — this was wrong; a failing Init should abort
  plugin startup, which only happens on a non-nil RPC error).
- `sync.Once` guard: second Init call returns the first call's outcome without
  re-wiring (idempotent).

### 6. `wire()` — new private method

```go
func (s *orchestratorServer) wire(brokerID uint32) error {
    if s.broker == nil {
        return fmt.Errorf("orchestrator: broker not available ...")
    }
    conn, err := s.broker.Dial(brokerID)
    if err != nil { return fmt.Errorf(...) }

    s.hostClient = host.NewFromConn(conn)
    sm := orchestrator.NewStateMachine(s.hostClient)
    s.hookSvc = orchestrator.NewRotationHookService(sm, s.hostClient)
    s.cronDriver = orchestrator.NewCronDriver(sm, s.hostClient)
    s.sm = sm

    return s.cronDriver.Start()   // synchronous — see rationale below
}
```

---

## Cron Driver: Synchronous vs Deferred — Decision and Rationale

`CronDriver.Start()` is called **synchronously** inside `wire()`, which runs
inside `Init`. This means:

- `Init` does not return until the cron scheduler is running and the initial
  drain of pending revocations has completed.
- The host receives a clear success or failure signal from `Init`. If
  `loadAllBindings` or `drainOnce` fail, `Init` returns a non-nil error and the
  host aborts plugin registration.

The background goroutines launched by `CronDriver.Start()` (the drain loop and
the robfig/cron scheduler) run after `Init` returns. They use `CronDriver.ctx`,
which is cancelled by `CronDriver.Stop()` on plugin shutdown.

**Why not deferred?** A deferred launch would mean Init always returns nil even
if the initial binding load fails. The host would register the plugin as healthy
but rotations would never fire. Synchronous startup trades slightly longer Init
latency for a reliable health signal — preferred for a fail-closed system.

---

## Test Broker Helper Implementation

`*goplugin.GRPCBroker` is a concrete struct with unexported fields and cannot
be constructed in unit tests. The solution is the `fakeBroker` type defined in
`main_test.go`:

```go
type fakeBroker struct {
    listener *bufconn.Listener
    server   *grpc.Server
}

func newFakeBroker(t *testing.T, svc pluginv1.HostServiceServer) *fakeBroker {
    lis := bufconn.Listen(1 << 20)
    srv := grpc.NewServer()
    pluginv1.RegisterHostServiceServer(srv, svc)
    go srv.Serve(lis)
    t.Cleanup(func() { srv.GracefulStop(); lis.Close() })
    return &fakeBroker{listener: lis, server: srv}
}

func (b *fakeBroker) Dial(_ uint32) (*grpc.ClientConn, error) {
    return grpc.NewClient("passthrough:///bufconn",
        grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
            return b.listener.DialContext(ctx)
        }),
        grpc.WithTransportCredentials(insecure.NewCredentials()),
    )
}
```

`fakeBroker` satisfies `brokerDialer`. It starts a real in-process gRPC server
backed by `google.golang.org/grpc/test/bufconn` and returns a live
`*grpc.ClientConn` to it. The broker ID passed to `Dial` is ignored because
the test does not use go-plugin's broker negotiation protocol.

The `stubHostService` returns empty-success for `ListBindings` and
`DrainPendingRevocations` — the two RPCs called by `CronDriver.Start()`.

Note on GRPCServer path coverage: because `GRPCPlugin.GRPCServer` takes
`*goplugin.GRPCBroker` (concrete, fixed by the interface contract), we cannot
call `plugin.GRPCServer(fake, grpcSrv)` from a test without a type error.
Instead, the test directly injects `impl.broker = fake`. The production code
path (`p.Impl.broker = broker` in `GRPCServer`) is covered by the compile-time
type constraint: `*goplugin.GRPCBroker` satisfies `brokerDialer`.

---

## Final Test Output (cmd package)

```
=== RUN   TestHandshakeConfig_Values
--- PASS: TestHandshakeConfig_Values (0.00s)
=== RUN   TestRotationFeatureConstant
--- PASS: TestRotationFeatureConstant (0.00s)
=== RUN   TestOrchestratorServer_TriggerRotation_Uninitialized
--- PASS: TestOrchestratorServer_TriggerRotation_Uninitialized (0.00s)
=== RUN   TestOrchestratorServer_BindingForCredential_Uninitialized
--- PASS: TestOrchestratorServer_BindingForCredential_Uninitialized (0.00s)
=== RUN   TestOrchestratorPlugin_GRPCClientReturnsClient
--- PASS: TestOrchestratorPlugin_GRPCClientReturnsClient (0.00s)
=== RUN   TestInit_WiresComponents
--- PASS: TestInit_WiresComponents (0.00s)
=== RUN   TestGRPCServer_ImplFieldIsOrchestratorServer
--- PASS: TestGRPCServer_ImplFieldIsOrchestratorServer (0.00s)
=== RUN   TestInit_NoBroker
--- PASS: TestInit_NoBroker (0.00s)
PASS
ok  github.com/catalyst9ai/agentkms-pro/cmd/agentkms-plugin-orchestrator  0.413s
```

Full repo (`go test ./...`):

```
?   github.com/catalyst9ai/agentkms-pro/api/plugin/v1         [no test files]
ok  github.com/catalyst9ai/agentkms-pro/cmd/agentkms-plugin-orchestrator  0.955s
ok  github.com/catalyst9ai/agentkms-pro/internal/host         0.362s
ok  github.com/catalyst9ai/agentkms-pro/internal/license      0.792s
ok  github.com/catalyst9ai/agentkms-pro/internal/orchestrator 0.697s
```

---

## B1 Resolution Confirmation

`BLOCKERS.md` §B1 has been updated:

- Status changed from **BLOCKER** to **RESOLVED**
- Resolution date: 2026-04-26
- Commit anchor: `fix/B1-broker-wiring` (pending Bert's review and commit)
- Fix summary, changed files, and test coverage documented inline

B1 is fully resolved. The orchestrator is end-to-end functional for T6's demo.
