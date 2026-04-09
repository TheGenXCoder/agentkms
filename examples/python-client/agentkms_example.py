"""
Example: Using AgentKMS from Python.

Full lifecycle:
  1. Authenticate via mTLS → receive session token
  2. Fetch LLM credentials → use them for an API call
  3. Revoke session token on shutdown

No external dependencies beyond the standard library.
"""

import json
import os
import ssl
import urllib.request
from pathlib import Path


AKMS_ADDR = "https://127.0.0.1:8443"


def create_ssl_context() -> ssl.SSLContext:
    """Create an SSL context with mTLS using dev certificates."""
    home = Path.home()
    cert_dir = home / ".agentkms" / "dev"
    clients_dir = cert_dir / "clients"

    # Find the first client directory
    client_dir = next(clients_dir.iterdir())

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(
        certfile=str(client_dir / "client.crt"),
        keyfile=str(client_dir / "client.key"),
    )
    ctx.load_verify_locations(cafile=str(cert_dir / "ca.crt"))
    return ctx


def authenticate(ctx: ssl.SSLContext) -> str:
    """Authenticate via mTLS and receive a session token."""
    req = urllib.request.Request(
        f"{AKMS_ADDR}/auth/session",
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, context=ctx) as resp:
        data = json.loads(resp.read())
        return data["token"]


def fetch_credential(ctx: ssl.SSLContext, token: str, provider: str) -> str:
    """Fetch a short-lived LLM API key."""
    req = urllib.request.Request(
        f"{AKMS_ADDR}/credentials/llm/{provider}",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req, context=ctx) as resp:
        data = json.loads(resp.read())
        return data["api_key"]


def revoke(ctx: ssl.SSLContext, token: str) -> None:
    """Revoke the session token."""
    req = urllib.request.Request(
        f"{AKMS_ADDR}/auth/revoke",
        method="POST",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req, context=ctx) as resp:
        pass  # 200 OK = revoked


def main():
    ctx = create_ssl_context()

    # Step 1: Authenticate
    token = authenticate(ctx)
    print(f"Authenticated. Token expires in 15 minutes.")

    # Step 2: Fetch credentials
    api_key = fetch_credential(ctx, token, "anthropic")
    print(f"Got Anthropic API key: {api_key[:7]}...{api_key[-4:]}")

    # Use the key for your LLM call here...
    # The key is in memory only — never write it to disk.

    # Step 3: Revoke when done
    try:
        revoke(ctx, token)
        print("Session revoked. Credentials cleared.")
    except Exception as e:
        print(f"Warning: revocation failed: {e}")


if __name__ == "__main__":
    main()
