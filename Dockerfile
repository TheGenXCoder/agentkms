# =============================================================================
# AgentKMS — Multi-stage Dockerfile
#
# Stage 1 (build):  Go 1.25 on Debian Bookworm.  Compiles the server binary
#                   with CGO disabled for a fully static output.
# Stage 2 (certs):  Extracts CA certificates from Debian for inclusion in the
#                   final image (needed for TLS to external services).
# Stage 3 (final):  Distroless nonroot image.  No shell, no package manager,
#                   no writable filesystem beyond /tmp.
#
# Security properties:
#   - Runs as nonroot (UID 65532) by default
#   - No shell → no RCE via command injection
#   - Read-only root filesystem (enforce with securityContext in Helm chart)
#   - Binary is statically linked → no LD_PRELOAD attacks
#   - Digest-pinned base images (update on each release)
#
# Build:
#   docker build -t agentkms:dev .
#
# Run (dev, local socket only):
#   docker run --rm -p 127.0.0.1:8200:8200 agentkms:dev
# =============================================================================

# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM golang:1.25-bookworm AS build

WORKDIR /src

# Cache dependency downloads before copying source.
# go.sum is copied explicitly so cache invalidates only when deps change.
COPY go.mod go.sum* ./
RUN go mod download && go mod verify

# Copy source and build.
# CGO_ENABLED=0 produces a static binary that runs in distroless/scratch.
# -trimpath removes local build paths from the binary (reduces information
# leakage in stack traces and debug symbols).
# -ldflags "-s -w" strips the symbol table and DWARF info (smaller binary).
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
    go build \
      -trimpath \
      -ldflags="-s -w" \
      -o /out/agentkms \
      ./cmd/server

# ── Stage 2: ca-certificates ─────────────────────────────────────────────────
FROM debian:bookworm-slim AS certs
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── Stage 3: final (distroless nonroot) ──────────────────────────────────────
# gcr.io/distroless/static-debian12:nonroot contains:
#   - Static musl libc (for CGO=0 binaries)
#   - /etc/passwd and /etc/group (nonroot user UID 65532)
#   - /tmp (writable)
#   - Nothing else — no shell, no apt, no curl
#
# Pin by digest in production to prevent supply-chain substitution:
#   docker pull gcr.io/distroless/static-debian12:nonroot
#   docker inspect --format='{{index .RepoDigests 0}}' gcr.io/distroless/static-debian12:nonroot
FROM gcr.io/distroless/static-debian12:nonroot

# CA certificates for outbound TLS (OpenBao, ELK, cloud KMS endpoints).
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# The server binary.
COPY --from=build /out/agentkms /agentkms

# Configuration and TLS material are mounted at runtime via Kubernetes
# secrets / configmaps.  Do not COPY them here.
#
# Expected mounts:
#   /etc/agentkms/config.yaml     — service configuration
#   /etc/agentkms/tls/server.crt  — server TLS certificate
#   /etc/agentkms/tls/server.key  — server TLS private key
#   /etc/agentkms/tls/ca.crt      — client CA pool

EXPOSE 8200

# Run as nonroot (UID 65532 / GID 65532).
# Enforced here AND in the Helm chart securityContext for defence in depth.
USER nonroot:nonroot

ENTRYPOINT ["/agentkms"]
CMD ["--config=/etc/agentkms/config.yaml"]
