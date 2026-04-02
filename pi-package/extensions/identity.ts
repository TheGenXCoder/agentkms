/**
 * AgentKMS identity loader (PI-03).
 *
 * Reads the developer's mTLS client certificate and key from disk.
 * Search order:
 *   1. ~/.agentkms/           (production / team enrollment via `agentkms enroll`)
 *   2. ~/.agentkms/dev/       (local dev mode via `agentkms-dev enroll`)
 *
 * Also reads optional config.json from the same directory for service URL and
 * managed provider list overrides.
 *
 * Security contract:
 *   - The private key (identity.key) is read into memory once and passed to
 *     AgentKMSClient where it lives in the https.Agent for the lifetime of the
 *     session.  It is never logged, never included in error messages, and never
 *     written back to disk.
 *   - If cert or key cannot be read the function returns null.  Callers must
 *     treat a null identity as "AgentKMS unavailable" and notify the user.
 */

import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

// ── Public Types ──────────────────────────────────────────────────────────

export interface AgentKMSIdentity {
  /** Absolute path to the PEM client certificate (not secret). */
  certPath: string;
  /** Absolute path to the PEM private key (secret — do not log). */
  keyPath: string;
  /** PEM-encoded client certificate. */
  cert: string;
  /**
   * PEM-encoded private key.
   * SECRET — never log, never include in error messages, never persist.
   */
  key: string;
  /**
   * PEM-encoded CA certificate used to verify the AgentKMS server certificate.
   * undefined → Node.js default CA store (suitable for production).
   */
  caCert?: string;
  /** AgentKMS service base URL, e.g. "https://agentkms.internal:8443". */
  serviceUrl: string;
  /** True when loaded from ~/.agentkms/dev/ (local agentkms-dev server). */
  isDev: boolean;
}

export interface AgentKMSConfig {
  /** Override the AgentKMS service URL. */
  serviceUrl?: string;
  /**
   * Override the list of LLM provider names whose credentials are managed by
   * AgentKMS.  Provider names must match Pi provider names exactly.
   * Default: ["anthropic", "openai", "google"]
   */
  providers?: string[];
}

// ── Internal Helpers ──────────────────────────────────────────────────────

const DEFAULT_DEV_SERVICE_URL  = "https://localhost:8443";
const DEFAULT_PROD_SERVICE_URL = "https://agentkms.internal:8443";

function readFileSafe(path: string): string | undefined {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return undefined;
  }
}

function loadConfig(dir: string): AgentKMSConfig {
  const raw = readFileSafe(join(dir, "config.json"));
  if (raw) {
    try {
      return JSON.parse(raw) as AgentKMSConfig;
    } catch {
      // Corrupt config — fall through to defaults
    }
  }
  return {};
}

function tryLoadIdentity(dir: string, isDev: boolean): AgentKMSIdentity | null {
  const certPath = join(dir, "client.crt");
  const keyPath  = join(dir, "client.key");

  if (!existsSync(certPath) || !existsSync(keyPath)) return null;

  const cert = readFileSafe(certPath);
  const key  = readFileSafe(keyPath);
  if (!cert || !key) return null;

  // Basic PEM format validation — defence-in-depth before passing the key
  // to the https.Agent.  If the key file contains binary garbage or was
  // accidentally overwritten, fail here rather than at the TLS handshake
  // where Node.js may produce a confusing OpenSSL error message.
  if (!cert.includes("-----BEGIN") || !key.includes("-----BEGIN")) return null;

  const config  = loadConfig(dir);
  const caCert  = readFileSafe(join(dir, "ca.crt")); // optional — undefined if not present
  const defaultServiceUrl = isDev ? DEFAULT_DEV_SERVICE_URL : DEFAULT_PROD_SERVICE_URL;

  return {
    certPath,
    keyPath,
    cert,
    key,     // SECRET — only passed to AgentKMSClient constructor, never logged
    caCert,
    serviceUrl: config.serviceUrl ?? defaultServiceUrl,
    isDev,
  };
}

// ── Public API ────────────────────────────────────────────────────────────

/**
 * Load the AgentKMS mTLS identity from disk.
 *
 * Returns null if no identity is found.  The caller should notify the user to
 * run `agentkms enroll` (production) or `agentkms-dev enroll` (local dev).
 */
export function loadIdentity(): AgentKMSIdentity | null {
  const base = homedir();
  return (
    tryLoadIdentity(join(base, ".agentkms"), false) ??
    tryLoadIdentity(join(base, ".agentkms", "dev"), true) ??
    null
  );
}

/**
 * Load the managed provider list from the identity config.
 * Falls back to the default set if no config is present.
 */
export function loadManagedProviders(identity: AgentKMSIdentity): string[] {
  // loadManagedProviders is called once at extension startup.  We re-read
  // config.json here (rather than requiring the caller to cache it) so that
  // the call site stays simple and avoids caching state at the module level.
  const dir = identity.isDev
    ? join(homedir(), ".agentkms", "dev")
    : join(homedir(), ".agentkms");
  const config = loadConfig(dir);
  return config.providers ?? ["anthropic", "openai", "google"];
}
