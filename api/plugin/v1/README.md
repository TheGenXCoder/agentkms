# AgentKMS Plugin API — `plugin.proto`

This directory contains the canonical protobuf definition for the AgentKMS
plugin system. It mirrors the Go interfaces in
`internal/credentials/scope.go` so plugins can be written in **any language
that has a gRPC library** — Python, Rust, C#, Java, TypeScript, and more.

## What this defines

Four gRPC services, each corresponding to a Go interface:

| Service | Go interface | Required? |
|---|---|---|
| `ScopeValidatorService` | `ScopeValidator` | Required per-Kind |
| `ScopeAnalyzerService` | `ScopeAnalyzer` | Optional per-Kind |
| `ScopeSerializerService` | `ScopeSerializer` | Required for upstream vending |
| `CredentialVenderService` | `CredentialVender` | Required for upstream vending |

A plugin binary typically implements one or more of these services. AgentKMS
loads plugins at startup via `hashicorp/go-plugin` and communicates with them
over a local gRPC socket.

## Generating stubs

### Go (via `buf`)

```sh
buf generate
```

Buf configuration lives in `buf.gen.yaml` at the repo root (to be added).
Generated Go stubs will be placed in `api/plugin/v1/` alongside this file.

> Go stubs are **not** committed — they are a build artifact. Run
> `buf generate` (or `make proto`) after cloning the repo.

### Go (via `protoc` directly)

```sh
protoc \
  -I api \
  -I third_party/googleapis \
  --go_out=. \
  --go-grpc_out=. \
  api/plugin/v1/plugin.proto
```

### Python

```sh
python -m grpc_tools.protoc \
  -I api \
  -I third_party/googleapis \
  --python_out=sdk/python/agentkms_plugin \
  --grpc_python_out=sdk/python/agentkms_plugin \
  api/plugin/v1/plugin.proto
```

### Rust (via `tonic-build` in `build.rs`)

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .compile(
            &["api/plugin/v1/plugin.proto"],
            &["api", "third_party/googleapis"],
        )?;
    Ok(())
}
```

### TypeScript / Node (via `@grpc/proto-loader` or `ts-proto`)

```sh
protoc \
  -I api \
  -I third_party/googleapis \
  --plugin=protoc-gen-ts_proto=./node_modules/.bin/protoc-gen-ts_proto \
  --ts_proto_out=sdk/ts/src \
  api/plugin/v1/plugin.proto
```

### C# / .NET

```sh
# Add the .proto file to your .csproj <Protobuf> item group:
# <Protobuf Include="api/plugin/v1/plugin.proto" GrpcServices="Both" />
# Then: dotnet build
```

### Java / Kotlin (via Gradle)

Add to `build.gradle`:

```groovy
protobuf {
    protoc { artifact = "com.google.protobuf:protoc:3.25.0" }
    plugins { grpc { artifact = "io.grpc:protoc-gen-grpc-java:1.62.2" } }
    generateProtoTasks {
        all()*.plugins { grpc {} }
    }
}
```

## Well-known type dependencies

The proto imports:

- `google/protobuf/struct.proto` — for `Scope.params` and `ScopeBounds.max_params`
  (`google.protobuf.Struct` maps to `map[string]any` in Go, `dict` in Python,
  `serde_json::Value` in Rust, etc.)
- `google/protobuf/timestamp.proto` — for time fields

When using `buf`, these are resolved from the Buf Schema Registry automatically.
When using `protoc` directly, include the googleapis/protobuf well-known types
in your include path (typically bundled with your `protoc` installation).

## Plugin development guide

A full plugin development guide — covering the plugin binary lifecycle,
`hashicorp/go-plugin` handshake, health checking, and end-to-end examples —
is planned at `docs/plugin-development.md`.

Until that doc exists, refer to:

- `internal/credentials/scope.go` — canonical Go interfaces
- `internal/plugin/` — plugin host/loader (if present)
- `hashicorp/go-plugin` docs — https://github.com/hashicorp/go-plugin
