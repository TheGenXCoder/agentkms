/**
 * AgentKMS HTTP client (PI-02).
 *
 * Thin HTTP client for the AgentKMS REST API.  All requests go over mTLS using
 * the developer's client certificate from their AgentKMSIdentity.
 *
 * This file contains ZERO cryptographic logic.  It only serialises/deserialises
 * JSON and makes HTTP calls over mTLS.
 *
 * Security contract:
 *   - mTLS: every request uses the client certificate loaded into the https.Agent.
 *   - rejectUnauthorized: true — the server certificate is always verified.
 *     For the local dev server, provide a ca.crt in ~/.agentkms/dev/.
 *   - Key material (LLMCredential.key, AgentKMSIdentity.key) NEVER appears in
 *     error messages, thrown values, or any other observable output.
 *   - All error messages are generic operational strings; response bodies are
 *     never forwarded to callers (they may contain internal details).
 *   - Session tokens are short-lived (15 min) and kept in memory only.
 */

import { request as httpsRequest, Agent } from "node:https";
import type { AgentKMSIdentity } from "./identity";

// ── Public Response Types ─────────────────────────────────────────────────

export interface SessionToken {
  /** Opaque bearer token. In-memory only — never write to disk. */
  token: string;
  /** Token expiry as Unix milliseconds. */
  expiresAt: number;
  identity: {
    callerId: string;
    teamId: string;
    agentSession: string;
  };
}

/**
 * Short-lived LLM provider credential returned by AgentKMS.
 *
 * Implemented as a class (not an interface) so that `toJSON()` can redact
 * the API key from any accidental serialisation (JSON.stringify, error
 * serialisers, debug loggers).  The `key` field is still directly readable
 * in process memory — it must remain so for the provider override — but it
 * will never surface in a serialised representation.
 */
export class LLMCredential {
  /**
   * Short-lived provider API key.
   * SECRET — in-memory only, never log, never persist.
   * Valid for ~60 minutes; tied to the issuing session.
   */
  readonly key: string;
  /** Credential expiry as Unix milliseconds. */
  readonly expiresAt: number;
  /** Scope string from AgentKMS, e.g. "session:abc123". */
  readonly scope: string;

  constructor(key: string, expiresAt: number, scope: string) {
    // Validate at the trust boundary: a null, empty, or non-string key from
    // the server is a protocol violation.  Fail fast rather than storing a
    // bad credential that would silently cause auth failures downstream.
    if (!key || typeof key !== "string") {
      throw new Error(
        "AgentKMS: received an invalid credential from the server " +
        "(key is missing or not a string). " +
        "Check the AgentKMS server configuration.",
      );
    }
    this.key      = key;
    this.expiresAt = expiresAt;
    this.scope    = scope;
  }

  /**
   * Prevent accidental key exposure when this object is serialised.
   * JSON.stringify(credential) → { key: "[REDACTED]", expiresAt, scope }
   */
  toJSON(): Record<string, unknown> {
    return { key: "[REDACTED]", expiresAt: this.expiresAt, scope: this.scope };
  }
}

export interface SignResult {
  /** Base64-encoded signature. */
  signature: string;
  /** Key version used. Always report this alongside signatures. */
  keyVersion: number;
}

export interface EncryptResult {
  /** Base64-encoded ciphertext. */
  ciphertext: string;
  /** Key version used. */
  keyVersion: number;
}

export interface DecryptResult {
  /** Base64-encoded plaintext. */
  plaintext: string;
}

export interface KeyMeta {
  id: string;
  algorithm: string;
  versions: number;
  createdAt: string;
  rotatedAt: string | null;
}

// ── Wire Types (snake_case API response shapes) ───────────────────────────

interface AuthSessionResponse {
  token: string;
  expires_at: string;
  identity: { caller_id: string; team_id: string; agent_session: string };
}

interface CredentialResponse {
  key: string;
  expires_at: string;
  scope: string;
}

interface SignResponse {
  signature: string;
  key_version: number;
}

interface EncryptResponse {
  ciphertext: string;
  key_version: number;
}

interface DecryptResponse {
  plaintext: string;
}

interface KeysResponse {
  keys: Array<{
    id: string;
    algorithm: string;
    versions: number;
    created_at: string;
    rotated_at: string | null;
  }>;
}

// ── Client ────────────────────────────────────────────────────────────────

/**
 * HTTP client for the AgentKMS REST API.
 *
 * Instantiate once per identity.  The underlying https.Agent holds the mTLS
 * client certificate for the lifetime of the instance.
 */
export class AgentKMSClient {
  private readonly serviceUrl: string;
  private readonly agent: Agent;

  constructor(identity: AgentKMSIdentity) {
    this.serviceUrl = identity.serviceUrl.replace(/\/$/, "");

    // The private key lives here in the Agent's heap for mTLS.
    // This is the only place it appears in process memory beyond the initial
    // loadIdentity() read.  It is never copied elsewhere.
    this.agent = new Agent({
      cert: identity.cert,
      key:  identity.key,  // SECRET — in Agent heap only, not logged
      ca:   identity.caCert,
      // Always verify the server certificate.
      // For the local dev server: place the dev CA cert at ~/.agentkms/dev/ca.crt.
      // For production: server cert must be signed by a CA in the system store or
      // the provided ca.crt.
      rejectUnauthorized: true,
    });
  }

  // ── Authentication ────────────────────────────────────────────────────

  /**
   * Authenticate via the mTLS client certificate.
   * POST /auth/session — no body; identity comes from the TLS handshake.
   */
  async auth(signal?: AbortSignal): Promise<SessionToken> {
    const raw = await this.request<AuthSessionResponse>(
      "POST", "/auth/session", undefined, undefined, signal,
    );
    return toSessionToken(raw);
  }

  /**
   * Refresh a session token before it expires.
   * POST /auth/refresh
   */
  async refreshToken(token: SessionToken, signal?: AbortSignal): Promise<SessionToken> {
    const raw = await this.request<AuthSessionResponse>(
      "POST", "/auth/refresh", undefined, token.token, signal,
    );
    return toSessionToken(raw);
  }

  /**
   * Revoke the session token server-side.
   * POST /auth/revoke  →  204 No Content
   *
   * Best-effort.  The token expires naturally in 15 min if this call fails.
   */
  async revokeToken(token: SessionToken, signal?: AbortSignal): Promise<void> {
    await this.request<unknown>(
      "POST", "/auth/revoke", undefined, token.token, signal,
    );
  }

  // ── Credential Vending ────────────────────────────────────────────────

  /**
   * Fetch a short-lived LLM credential for the given provider.
   * GET /credentials/llm/{provider}
   *
   * SECURITY: The returned LLMCredential.key is a live provider API key.
   *   - Store only in the runtimeKeys map (in-memory, never persisted).
   *   - Never log or include in error messages.
   *   - Valid ~60 min; tied to the issuing session.
   */
  async getLLMCredential(
    provider: string,
    token: SessionToken,
    signal?: AbortSignal,
  ): Promise<LLMCredential> {
    const raw = await this.request<CredentialResponse>(
      "GET",
      `/credentials/llm/${encodeURIComponent(provider)}`,
      undefined,
      token.token,
      signal,
    );
    // Construct LLMCredential as a class instance so toJSON() redacts the key
    // if this object is ever accidentally serialised.
    return new LLMCredential(
      raw.key,                    // SECRET — caller must not log
      Date.parse(raw.expires_at),
      raw.scope,
    );
  }

  // ── Cryptographic Operations ──────────────────────────────────────────

  /**
   * Sign a payload hash using an AgentKMS-managed key.
   * POST /sign/{key-id}
   *
   * Only the hash is sent — the payload itself never leaves the caller's process.
   * The private signing key never leaves the AgentKMS backend.
   */
  async sign(
    keyId:       string,
    payloadHash: string,
    algorithm:   string,
    token:       SessionToken,
    signal?:     AbortSignal,
  ): Promise<SignResult> {
    const raw = await this.request<SignResponse>(
      "POST",
      `/sign/${encodeURIComponent(keyId)}`,
      { payload_hash: payloadHash, algorithm },
      token.token,
      signal,
    );
    return { signature: raw.signature, keyVersion: raw.key_version };
  }

  /**
   * Encrypt data using an AgentKMS-managed key.
   * POST /encrypt/{key-id}
   *
   * @param plaintext  Base64-encoded bytes to encrypt.
   * @param context    Optional additional authenticated data (AAD).
   */
  async encrypt(
    keyId:     string,
    plaintext: string,
    token:     SessionToken,
    context?:  string,
    signal?:   AbortSignal,
  ): Promise<EncryptResult> {
    const body: Record<string, string> = { plaintext };
    if (context !== undefined) body.context = context;

    const raw = await this.request<EncryptResponse>(
      "POST",
      `/encrypt/${encodeURIComponent(keyId)}`,
      body,
      token.token,
      signal,
    );
    return { ciphertext: raw.ciphertext, keyVersion: raw.key_version };
  }

  /**
   * Decrypt ciphertext using an AgentKMS-managed key.
   * POST /decrypt/{key-id}
   *
   * @param ciphertext  Base64-encoded ciphertext to decrypt.
   * @param context     Optional AAD — must match the value used during encryption.
   * @returns           Base64-encoded plaintext.
   */
  async decrypt(
    keyId:      string,
    ciphertext: string,
    token:      SessionToken,
    context?:   string,
    signal?:    AbortSignal,
  ): Promise<DecryptResult> {
    const body: Record<string, string> = { ciphertext };
    if (context !== undefined) body.context = context;

    const raw = await this.request<DecryptResponse>(
      "POST",
      `/decrypt/${encodeURIComponent(keyId)}`,
      body,
      token.token,
      signal,
    );
    return { plaintext: raw.plaintext };
  }

  // ── Key Management ────────────────────────────────────────────────────

  /**
   * List key metadata accessible to the current session identity.
   * GET /keys[?scope=...]
   *
   * Returns metadata only — id, algorithm, versions, dates.
   * Key material is never returned.
   */
  async listKeys(
    token:   SessionToken,
    scope?:  string,
    signal?: AbortSignal,
  ): Promise<KeyMeta[]> {
    const qs  = scope ? `?scope=${encodeURIComponent(scope)}` : "";
    const raw = await this.request<KeysResponse>(
      "GET", `/keys${qs}`, undefined, token.token, signal,
    );
    return raw.keys.map(k => ({
      id:        k.id,
      algorithm: k.algorithm,
      versions:  k.versions,
      createdAt: k.created_at,
      rotatedAt: k.rotated_at,
    }));
  }

  // ── Transport ─────────────────────────────────────────────────────────

  /**
   * Low-level HTTP request helper.
   *
   * Error messages are intentionally generic — response bodies may contain
   * internal details and must never be forwarded to callers.
   *
   * A 30-second default timeout is applied to every request to prevent a hung
   * AgentKMS server from blocking Pi startup or session lifecycle hooks
   * indefinitely.
   */
  private readonly REQUEST_TIMEOUT_MS = 30_000;

  private request<T>(
    method:   "GET" | "POST",
    path:     string,
    body?:    unknown,
    token?:   string,
    signal?:  AbortSignal,
  ): Promise<T> {
    return new Promise((resolve, reject) => {
      if (signal?.aborted) {
        reject(new DOMException("Request aborted", "AbortError"));
        return;
      }

      const url     = new URL(this.serviceUrl + path);
      const bodyStr = body !== undefined ? JSON.stringify(body) : "";

      const headers: Record<string, string | number> = {
        "Content-Type": "application/json",
        "User-Agent":   "agentkms-pi-extension/0.1.0",
      };
      if (bodyStr) {
        headers["Content-Length"] = Buffer.byteLength(bodyStr);
      }
      if (token) {
        // SECURITY: bearer token in header. Not logged.
        headers["Authorization"] = `Bearer ${token}`;
      }

      const req = httpsRequest(
        {
          hostname: url.hostname,
          port:     url.port ? parseInt(url.port, 10) : 443,
          path:     url.pathname + url.search,
          method,
          agent:    this.agent,
          headers,
        },
        (res) => {
          const chunks: Buffer[] = [];
          let totalBytes = 0;
          const MAX_RESPONSE_BYTES = 1 * 1024 * 1024; // 1 MiB — matches Go server limit

          res.on("data", (chunk: Buffer) => {
            totalBytes += chunk.length;
            if (totalBytes > MAX_RESPONSE_BYTES) {
              req.destroy();
              reject(new Error(
                `AgentKMS: response too large from ${path} (limit: ${MAX_RESPONSE_BYTES} bytes)`,
              ));
              return;
            }
            chunks.push(chunk);
          });
          res.on("end", () => {
            const status   = res.statusCode ?? 0;
            const bodyText = Buffer.concat(chunks).toString("utf8");

            if (status === 204) {
              resolve(undefined as unknown as T);
              return;
            }

            if (status >= 200 && status < 300) {
              try {
                resolve(JSON.parse(bodyText) as T);
              } catch {
                // Don't forward bodyText — may contain sensitive data
                reject(new Error(
                  `AgentKMS: unexpected response format from ${path} (HTTP ${status})`,
                ));
              }
              return;
            }

            // Non-2xx: don't include response body in error.
            // The body may contain internal state that aids an attacker.
            reject(new Error(
              `AgentKMS: request failed — ${path} returned HTTP ${status}`,
            ));
          });
          res.on("error", () => {
            reject(new Error(`AgentKMS: response stream error on ${path}`));
          });
        },
      );

      req.on("error", () => {
        // Don't forward the original Node error — it may expose network topology
        // or certificate details.
        reject(new Error("AgentKMS: connection failed — is the service reachable?"));
      });

      // AbortSignal support
      if (signal) {
        const onAbort = () => {
          req.destroy();
          reject(new DOMException("Request aborted", "AbortError"));
        };
        signal.addEventListener("abort", onAbort, { once: true });
        req.on("close", () => signal.removeEventListener("abort", onAbort));
      }

      // Enforce a hard request timeout.  If no response header arrives within
      // REQUEST_TIMEOUT_MS, destroy the socket and reject with a clear error.
      req.setTimeout(this.REQUEST_TIMEOUT_MS, () => {
        req.destroy();
        reject(new Error(
          `AgentKMS: request timed out after ${this.REQUEST_TIMEOUT_MS / 1000}s — ` +
          "is the AgentKMS service reachable?",
        ));
      });

      if (bodyStr) req.write(bodyStr);
      req.end();
    });
  }
}

// ── Internal Helpers ──────────────────────────────────────────────────────

function toSessionToken(raw: AuthSessionResponse): SessionToken {
  return {
    token:     raw.token,
    expiresAt: Date.parse(raw.expires_at),
    identity: {
      callerId:     raw.identity.caller_id,
      teamId:       raw.identity.team_id,
      agentSession: raw.identity.agent_session,
    },
  };
}
