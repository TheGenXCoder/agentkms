/**
 * AgentKMS crypto tools (PI-10, PI-11, PI-12).
 *
 * Registers three tools the LLM can call to perform cryptographic operations
 * via AgentKMS:
 *
 *   crypto_sign    — sign a payload hash with an AgentKMS-managed key
 *   crypto_encrypt — encrypt data with an AgentKMS-managed key
 *   crypto_decrypt — decrypt data with an AgentKMS-managed key
 *
 * Key design decisions:
 *   - Payload is NEVER sent to AgentKMS — only the SHA-256 hash is sent for
 *     signing.  This minimises data exposure and matches the API contract.
 *   - Private key material never appears at any layer.  The tools return only
 *     signatures, ciphertext, or plaintext.
 *   - payload_hash is intentionally excluded from tool result `details` to
 *     avoid accumulating potentially-sensitive input material in session history.
 *   - key_id and key_version are always included in results so callers can
 *     record provenance.
 */

import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { Type }              from "@sinclair/typebox";
import { StringEnum }        from "@mariozechner/pi-ai";
import type { AgentKMSClient, SessionToken } from "./client";

// ── Types ─────────────────────────────────────────────────────────────────

type GetToken  = () => SessionToken | null;
type GetClient = () => AgentKMSClient | null;

// ── Registration ──────────────────────────────────────────────────────────

/**
 * Register all AgentKMS crypto tools with Pi.
 *
 * @param pi         Pi extension API
 * @param getToken   Returns the current active session token (or null)
 * @param getClient  Returns the initialised AgentKMS HTTP client (or null)
 */
export function registerCryptoTools(
  pi:        ExtensionAPI,
  getToken:  GetToken,
  getClient: GetClient,
): void {
  registerSignTool(pi, getToken, getClient);
  registerEncryptTool(pi, getToken, getClient);
  registerDecryptTool(pi, getToken, getClient);
}

// ── crypto_sign ───────────────────────────────────────────────────────────

function registerSignTool(
  pi:        ExtensionAPI,
  getToken:  GetToken,
  getClient: GetClient,
): void {
  pi.registerTool({
    name:  "crypto_sign",
    label: "Sign Payload (AgentKMS)",
    description:
      "Sign a payload hash using an AgentKMS-managed asymmetric key. " +
      "Returns the base64-encoded signature and the key version used. " +
      "The private key never leaves AgentKMS. " +
      "IMPORTANT: payload_hash must be the hex-encoded SHA-256 hash of the payload " +
      "— do NOT send the payload itself.",
    promptSnippet:
      "Sign a SHA-256 payload hash with an AgentKMS-managed key (no key exposure)",
    parameters: Type.Object({
      key_id: Type.String({
        description:
          "AgentKMS key identifier, e.g. 'payments/signing-key' or 'personal/alice/jwt-key'",
      }),
      payload_hash: Type.String({
        description:
          "Hex-encoded SHA-256 hash of the payload to sign. " +
          "NOT the payload itself — hash it first.",
      }),
      algorithm: StringEnum(["ES256", "RS256", "EdDSA"] as const, {
        description: "Signing algorithm. ES256 is recommended for new keys.",
      }),
    }),

    async execute(_toolCallId, params, signal, _onUpdate, _ctx) {
      const token  = requireToken(getToken);
      const client = requireClient(getClient);

      // Validate payload_hash format before sending to the server.
      // A valid SHA-256 hex digest is exactly 64 lowercase or uppercase hex chars.
      // Defence-in-depth: the server also validates, but rejecting early prevents
      // accidental submission of the raw payload instead of its hash.
      if (!/^[0-9a-fA-F]{64}$/.test(params.payload_hash)) {
        throw new Error(
          "AgentKMS crypto_sign: payload_hash must be a hex-encoded SHA-256 hash " +
          "(exactly 64 hex characters). Hash the payload first.",
        );
      }

      const result = await client.sign(
        params.key_id,
        params.payload_hash,
        params.algorithm,
        token,
        signal,
      );

      return {
        content: [
          {
            type: "text" as const,
            text: [
              `Signature:    ${result.signature}`,
              `Key ID:       ${params.key_id}`,
              `Key version:  ${result.keyVersion}`,
              `Algorithm:    ${params.algorithm}`,
            ].join("\n"),
          },
        ],
        // SECURITY: payload_hash omitted — do not accumulate potentially-sensitive
        // input material in session history.
        // key_id and key_version are metadata and are safe to store.
        details: {
          key_id:      params.key_id,
          key_version: result.keyVersion,
          algorithm:   params.algorithm,
        },
      };
    },
  });
}

// ── crypto_encrypt ────────────────────────────────────────────────────────

function registerEncryptTool(
  pi:        ExtensionAPI,
  getToken:  GetToken,
  getClient: GetClient,
): void {
  pi.registerTool({
    name:  "crypto_encrypt",
    label: "Encrypt Data (AgentKMS)",
    description:
      "Encrypt data using an AgentKMS-managed key. " +
      "The plaintext must be base64-encoded. " +
      "Returns base64-encoded ciphertext and the key version used. " +
      "The encryption key never leaves AgentKMS.",
    promptSnippet: "Encrypt base64-encoded data with an AgentKMS-managed key",
    parameters: Type.Object({
      key_id: Type.String({
        description: "AgentKMS key identifier",
      }),
      plaintext: Type.String({
        description: "Base64-encoded bytes to encrypt",
      }),
      context: Type.Optional(
        Type.String({
          description:
            "Optional additional authenticated data (AAD). " +
            "Must be provided again to decrypt — store it alongside the ciphertext.",
        }),
      ),
    }),

    async execute(_toolCallId, params, signal, _onUpdate, _ctx) {
      const token  = requireToken(getToken);
      const client = requireClient(getClient);

      const result = await client.encrypt(
        params.key_id,
        params.plaintext,
        token,
        params.context,
        signal,
      );

      return {
        content: [
          {
            type: "text" as const,
            text: [
              `Ciphertext:  ${result.ciphertext}`,
              `Key ID:      ${params.key_id}`,
              `Key version: ${result.keyVersion}`,
              ...(params.context !== undefined
                ? [`Context:     ${params.context}`]
                : []),
            ].join("\n"),
          },
        ],
        details: {
          key_id:      params.key_id,
          key_version: result.keyVersion,
        },
      };
    },
  });
}

// ── crypto_decrypt ────────────────────────────────────────────────────────

function registerDecryptTool(
  pi:        ExtensionAPI,
  getToken:  GetToken,
  getClient: GetClient,
): void {
  pi.registerTool({
    name:  "crypto_decrypt",
    label: "Decrypt Data (AgentKMS)",
    description:
      "Decrypt ciphertext using an AgentKMS-managed key. " +
      "Returns base64-encoded plaintext. " +
      "If a context (AAD) was provided during encryption, it must be provided here too.",
    promptSnippet: "Decrypt AgentKMS-encrypted data",
    parameters: Type.Object({
      key_id: Type.String({
        description: "AgentKMS key identifier (must match the key used for encryption)",
      }),
      ciphertext: Type.String({
        description: "Base64-encoded ciphertext to decrypt",
      }),
      context: Type.Optional(
        Type.String({
          description:
            "Optional additional authenticated data (AAD). " +
            "Must match the value used during encryption.",
        }),
      ),
    }),

    async execute(_toolCallId, params, signal, _onUpdate, _ctx) {
      const token  = requireToken(getToken);
      const client = requireClient(getClient);

      const result = await client.decrypt(
        params.key_id,
        params.ciphertext,
        token,
        params.context,
        signal,
      );

      return {
        content: [
          {
            type: "text" as const,
            text: [
              `Plaintext (base64): ${result.plaintext}`,
              `Key ID:             ${params.key_id}`,
            ].join("\n"),
          },
        ],
        details: {
          key_id: params.key_id,
        },
      };
    },
  });
}

// ── Helpers ───────────────────────────────────────────────────────────────

function requireToken(getToken: GetToken): SessionToken {
  const token = getToken();
  if (!token) {
    throw new Error(
      "AgentKMS: no active session. " +
      "Ensure the session_start hook completed successfully. " +
      "If not, check that agentkms-dev is running and your identity is enrolled.",
    );
  }
  return token;
}

function requireClient(getClient: GetClient): AgentKMSClient {
  const client = getClient();
  if (!client) {
    throw new Error(
      "AgentKMS: client not initialised — no identity found. " +
      "Run `agentkms enroll` or `agentkms-dev enroll`.",
    );
  }
  return client;
}
