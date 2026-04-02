/**
 * AgentKMS Pi Extension — main entry point.
 *
 * Implements the full lifecycle described in docs/architecture.md §6.2:
 *
 *   session_start          (PI-04) — mTLS auth, LLM credential injection
 *   before_provider_request (PI-06) — proactive token + key refresh
 *   session_shutdown       (PI-07) — server-side token revocation
 *   tool_call              (PI-08) — credential path protection
 *   model_select           (PI-09) — credential fetch on provider switch
 *
 * Provider overrides (PI-05) and crypto tools (PI-10–12) are registered at
 * extension load time via provider.ts and tools.ts.
 *
 * Security invariants enforced here:
 *   - All state (sessionToken, runtimeKeys) is in-memory only — never written
 *     to disk, never logged.
 *   - On session_shutdown, clearSession() zeroes all in-memory credentials and
 *     the server-side session token is revoked.
 *   - getApiKey() in provider.ts always reads from runtimeKeys, so token
 *     refreshes in before_provider_request are reflected on the very next
 *     LLM call without any additional coordination.
 *   - If AgentKMS is unreachable during session_start, the user is notified
 *     and the extension is inert for that session (no crash, no fallback to
 *     env vars).
 */

import type { ExtensionAPI }      from "@mariozechner/pi-coding-agent";
import { isToolCallEventType }    from "@mariozechner/pi-coding-agent";
import { loadIdentity, loadManagedProviders } from "./identity";
import { AgentKMSClient }         from "./client";
import type { SessionToken, LLMCredential } from "./client";
import { setupProviderOverrides } from "./provider";
import { registerCryptoTools }   from "./tools";

// ── Extension State ───────────────────────────────────────────────────────
//
// All mutable state is module-level so that provider.ts getApiKey() and
// tools.ts execute() can read it through the getter closures below.
// None of this state is ever written to disk.

/** Active session token (15 min TTL). null when not authenticated. */
let sessionToken: SessionToken | null = null;

/**
 * Short-lived LLM credentials keyed by Pi provider name (60 min TTL).
 * Populated by session_start; refreshed proactively by before_provider_request;
 * read by provider.ts getApiKey() on every LLM request;
 * cleared by session_shutdown.
 */
const runtimeKeys = new Map<string, LLMCredential>();

/** Initialised HTTP client. null if no identity was found on disk. */
let client: AgentKMSClient | null = null;

// ── TTL Thresholds ────────────────────────────────────────────────────────

const TOKEN_REFRESH_THRESHOLD_MS = 5  * 60 * 1000;  //  5 min before expiry
const CRED_REFRESH_THRESHOLD_MS  = 10 * 60 * 1000;  // 10 min before expiry

// ── Credential Path Protection ────────────────────────────────────────────

/**
 * Path substrings that indicate a credential file read.
 * The tool_call hook blocks the read tool if any of these appear in the path.
 * This is defence-in-depth; the primary security layer is zero-key-exposure
 * in AgentKMS itself.
 */
const BLOCKED_PATH_PATTERNS = [
  ".env",
  "auth.json",
  ".agentkms/",
  "credentials",
  "client.key",
  "client.crt",    // cert itself; sent in every handshake but still a defence
  "ca.key",        // CA private key — most sensitive file in the dev PKI
  ".netrc",
  // Package registry auth tokens
  ".npmrc",
  ".pypirc",
  // Docker registry credentials
  ".docker/config.json",
  // Common SSH private-key file names
  "id_rsa",
  "id_ed25519",
  "id_ecdsa",
  "id_dsa",
  ".ssh/",
];

// ── Getters for sub-modules ───────────────────────────────────────────────

function getSessionToken(): SessionToken | null { return sessionToken; }
function getClient(): AgentKMSClient | null { return client; }

// ── State Cleanup ─────────────────────────────────────────────────────────

function clearSession(): void {
  sessionToken = null;
  runtimeKeys.clear();
  // client is NOT cleared — the identity and https.Agent are session-independent
}

// ── Extension Entry Point ─────────────────────────────────────────────────

export default function (pi: ExtensionAPI) {

  // Load identity at extension init time.
  // This reads cert/key from disk once and constructs the https.Agent.
  // The private key lives in the Agent object and is not copied further.
  const identity = loadIdentity();
  if (identity) {
    client = new AgentKMSClient(identity);
  }

  // Resolve the managed provider list.  If no identity was found, use the
  // default list so that provider overrides are still registered (they'll just
  // return empty keys until a session is established, which is the correct
  // fail-closed behaviour).
  const managedProviders: string[] = identity
    ? loadManagedProviders(identity)
    : ["anthropic", "openai", "google"];

  // Register provider overrides at load time.
  // getApiKey() reads from runtimeKeys — empty until session_start runs.
  setupProviderOverrides(pi, runtimeKeys, managedProviders);

  // Register crypto tools.
  registerCryptoTools(pi, getSessionToken, getClient);

  // ── session_start (PI-04) ────────────────────────────────────────────────

  pi.on("session_start", async (_event, ctx) => {
    // Identity missing → user needs to enroll.  Extension is inert this session.
    if (!identity || !client) {
      ctx.ui.notify(
        "AgentKMS: no identity found. " +
        "Run `agentkms enroll --team=<team>` (production) or " +
        "`agentkms-dev enroll` (local dev) to set up your identity.",
        "error",
      );
      return;
    }

    ctx.ui.setStatus("agentkms", "AgentKMS: authenticating…");

    // Step 1 — Authenticate via mTLS, receive a 15-min session token.
    try {
      sessionToken = await client.auth();
    } catch (err) {
      ctx.ui.setStatus("agentkms", "");
      ctx.ui.notify(
        `AgentKMS: authentication failed — ${(err as Error).message}`,
        "error",
      );
      return;
    }

    // Step 2 — Fetch short-lived LLM credentials for each managed provider
    // concurrently.  Failures are non-fatal (provider may not be configured).
    const credResults = await Promise.allSettled(
      managedProviders.map(provider =>
        client.getLLMCredential(provider, sessionToken!).then(cred => ({ provider, cred })),
      ),
    );

    const loaded: string[] = [];
    const failed: string[] = [];

    for (let i = 0; i < credResults.length; i++) {
      const result   = credResults[i];
      const provider = managedProviders[i];
      if (result.status === "fulfilled") {
        runtimeKeys.set(result.value.provider, result.value.cred);
        loaded.push(result.value.provider);
      } else {
        // Not a hard failure — provider key may just not be configured yet.
        failed.push(provider);
      }
    }

    ctx.ui.setStatus("agentkms", "");

    if (loaded.length === 0) {
      ctx.ui.notify(
        "AgentKMS: authenticated ✓ — " +
        "no LLM credentials available. Check provider configuration in AgentKMS.",
        "warning",
      );
    } else {
      ctx.ui.notify(
        `AgentKMS: authenticated ✓ — providers: ${loaded.join(", ")}`,
        "info",
      );
      if (failed.length > 0) {
        ctx.ui.notify(
          `AgentKMS: credentials unavailable for: ${failed.join(", ")}`,
          "warning",
        );
      }
    }
  });

  // ── before_provider_request (PI-06) ──────────────────────────────────────

  pi.on("before_provider_request", async (_event, _ctx) => {
    if (!sessionToken || !client) return;

    // Proactively refresh session token if within 5 min of expiry.
    if (sessionToken.expiresAt - Date.now() < TOKEN_REFRESH_THRESHOLD_MS) {
      try {
        sessionToken = await client.refreshToken(sessionToken);
      } catch {
        // Non-fatal — current token may still be valid for this request.
        // It expires naturally if refresh fails repeatedly.
      }
    }

    // Proactively refresh any LLM credentials within 10 min of expiry.
    // getApiKey() in provider.ts reads runtimeKeys directly, so the next LLM
    // call picks up the fresh key without any extra coordination.
    for (const [provider, cred] of runtimeKeys) {
      if (cred.expiresAt - Date.now() < CRED_REFRESH_THRESHOLD_MS) {
        try {
          const newCred = await client.getLLMCredential(provider, sessionToken);
          runtimeKeys.set(provider, newCred);
        } catch {
          // Non-fatal — credential expires naturally; Pi will call refreshToken()
        }
      }
    }
  });

  // ── session_shutdown (PI-07) ──────────────────────────────────────────────

  pi.on("session_shutdown", async (_event, _ctx) => {
    if (!sessionToken || !client) {
      clearSession();
      return;
    }

    try {
      // Revoke server-side.  This immediately invalidates all LLM credentials
      // scoped to this session — they cannot be used even if somehow observed.
      await client.revokeToken(sessionToken);
    } catch {
      // Best-effort.  The token expires naturally in ≤15 min.
    } finally {
      clearSession();
    }
  });

  // ── tool_call — credential path protection (PI-08) ────────────────────────

  pi.on("tool_call", async (event, ctx) => {
    // Intercept `read` (exfiltration), `write` (overwrite), and `edit`
    // (in-place modification) of credential files.  All three can compromise
    // or destroy the developer's private key material.
    const isRead  = isToolCallEventType("read",  event);
    const isWrite = isToolCallEventType("write", event);
    const isEdit  = isToolCallEventType("edit",  event);
    if (!isRead && !isWrite && !isEdit) return;

    const path = event.input.path ?? "";
    if (!BLOCKED_PATH_PATTERNS.some(pattern => path.includes(pattern))) return;

    const opName = isRead ? "read" : isWrite ? "write" : "edit";

    // Notify the user so the block is visible (not silent).
    ctx.ui.notify(
      `AgentKMS: blocked ${opName} of sensitive path: ${path}`,
      "warning",
    );

    // TODO: send a structured audit event to AgentKMS once a client-side audit
    // endpoint is available in the API.  Currently audit is server-side only for
    // crypto operations.  Tracking: backlog item AU-10.

    return { block: true, reason: `AgentKMS: ${opName} blocked — sensitive path (${path})` };
  });

  // ── model_select (PI-09) ──────────────────────────────────────────────────

  pi.on("model_select", async (event, ctx) => {
    const provider = event.model.provider;

    // Only act for providers we manage.
    if (!managedProviders.includes(provider)) return;
    if (!sessionToken || !client) return;

    // Fetch (or refresh) credentials for the newly selected provider.
    const existing    = runtimeKeys.get(provider);
    const needsRefresh = !existing ||
      (existing.expiresAt - Date.now() < CRED_REFRESH_THRESHOLD_MS);

    if (needsRefresh) {
      try {
        const cred = await client.getLLMCredential(provider, sessionToken);
        runtimeKeys.set(provider, cred);
      } catch {
        ctx.ui.notify(
          `AgentKMS: could not fetch credentials for provider '${provider}'. ` +
          "Check provider configuration in AgentKMS.",
          "warning",
        );
      }
    }
  });
}
