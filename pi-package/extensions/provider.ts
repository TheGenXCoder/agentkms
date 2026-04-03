/**
 * AgentKMS provider overrides (PI-05).
 *
 * Registers Pi provider overrides so that getApiKey() reads from the runtime
 * key map populated by AgentKMS during session_start, rather than from env
 * vars or auth.json.
 *
 * This is the core LLM credential injection mechanism described in
 * docs/architecture.md §6.2 "Provider Override — The Key Injection Mechanism".
 *
 * How it works:
 *   1. setupProviderOverrides() is called at extension load time with an
 *      initially-empty runtimeKeys map.
 *   2. session_start populates runtimeKeys with short-lived keys from AgentKMS.
 *   3. When Pi calls getApiKey() before each LLM request, it reads the current
 *      key directly from runtimeKeys — ignoring the stored OAuth credential.
 *   4. before_provider_request proactively refreshes runtimeKeys when keys near
 *      expiry, so getApiKey() always returns a fresh value.
 *   5. On session_shutdown, runtimeKeys is cleared — all keys are gone from
 *      memory immediately, and the session is revoked server-side.
 *
 * Security contract:
 *   - getApiKey() never logs, serialises, or stores the returned key.
 *   - login() and refreshToken() do not perform interactive flows.
 *   - If runtimeKeys has no entry for a provider (AgentKMS not connected or
 *     provider not configured), getApiKey() returns "".  This causes the LLM
 *     call to fail with an auth error — the correct behaviour for an enterprise
 *     deployment where bypassing AgentKMS is not allowed.
 */

import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import type { LLMCredential } from "./client";

// ── Constants ─────────────────────────────────────────────────────────────

/**
 * Default set of Pi provider names managed by AgentKMS.
 * Can be overridden via ~/.agentkms/config.json "providers" field.
 */
export const DEFAULT_MANAGED_PROVIDERS = ["anthropic", "openai", "google"] as const;

// ── Setup ─────────────────────────────────────────────────────────────────

/**
 * Register Pi provider overrides for all managed providers.
 *
 * Must be called during extension factory execution (before session_start) so
 * that Pi queues the overrides before the runner initialises.
 *
 * @param pi          Pi extension API
 * @param runtimeKeys Shared in-memory map: providerName → short-lived credential.
 *                    session_start writes to this; session_shutdown clears it.
 * @param providers   Provider names to override (default: DEFAULT_MANAGED_PROVIDERS)
 */
export function setupProviderOverrides(
  pi:          ExtensionAPI,
  runtimeKeys: Map<string, LLMCredential>,
  providers:   string[] = [...DEFAULT_MANAGED_PROVIDERS],
): void {
  for (const provider of providers) {
    pi.registerProvider(provider, {
      // We provide oauth so Pi uses getApiKey() from this config rather than
      // reading an env var.  We intentionally do NOT specify `models` so that
      // Pi keeps all existing model definitions for this provider.
      oauth: {
        name: `${provider} (via AgentKMS)`,

        /**
         * Called by Pi the first time it needs credentials for this provider
         * (lazy, on first LLM request after startup).
         *
         * session_start has already populated runtimeKeys by this point.
         * We return the current key immediately — no browser flow, no user
         * interaction.  The expires value is set so Pi will call refreshToken()
         * near expiry rather than immediately.
         */
        async login(_callbacks) {
          const cred = runtimeKeys.get(provider);
          return {
            refresh: "agentkms-managed",
            access:  cred?.key ?? "",
            expires: cred?.expiresAt ?? 0,
          };
        },

        /**
         * Called by Pi when the stored credential nears expiry.
         *
         * before_provider_request proactively refreshes runtimeKeys before
         * this is called, so the map always has a fresh entry.  We return
         * whatever is currently in runtimeKeys — never the stale cred argument.
         */
        async refreshToken(_creds) {
          const cred = runtimeKeys.get(provider);
          return {
            refresh: "agentkms-managed",
            access:  cred?.key ?? "",
            expires: cred?.expiresAt ?? 0,
          };
        },

        /**
         * Called by Pi immediately before every LLM HTTP request.
         *
         * This is the critical injection point.  We ignore the `_creds`
         * argument entirely and read directly from runtimeKeys, which is always
         * kept fresh by before_provider_request.
         *
         * SECURITY: The returned string is a live API key.  Pi uses it as-is
         * in the Authorization header — it is never logged here.
         */
        getApiKey(_creds) {
          return runtimeKeys.get(provider)?.key ?? "";
        },
      },
    });
  }
}
