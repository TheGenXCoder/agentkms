#!/usr/bin/env bash
# Generate Python gRPC stubs from the AgentKMS plugin proto.
#
# Run this once before using plugin.py in gRPC server mode.
# The generated files (plugin_pb2.py, plugin_pb2_grpc.py) are .gitignored
# because they are build artifacts.
#
# Requirements:
#   pip install grpcio-tools>=1.60.0 protobuf>=4.25.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
PROTO_DIR="${REPO_ROOT}/api/plugin/v1"

echo "Generating Python gRPC stubs..."
echo "  proto: ${PROTO_DIR}/plugin.proto"
echo "  out:   ${SCRIPT_DIR}/"

python -m grpc_tools.protoc \
    -I "${PROTO_DIR}" \
    --python_out="${SCRIPT_DIR}" \
    --grpc_python_out="${SCRIPT_DIR}" \
    "${PROTO_DIR}/plugin.proto"

echo "Done. Generated:"
echo "  plugin_pb2.py       — message classes"
echo "  plugin_pb2_grpc.py  — service stubs + servicer base classes"
