/**
 * AgentKMS Coordinator Extension
 *
 * Provides in-session awareness of the parallel development streams.
 * Each Pi instance loads this extension and knows:
 *   - Which stream it's in (from cwd vs coord.json paths)
 *   - What to work on next (reads backlog.md from its own worktree)
 *   - Status across all streams (reads all worktree backlogs)
 *
 * Commands:
 *   /coord status  — full progress table across all streams
 *   /coord next    — next TODO item in this stream
 *   /coord focus   — reprint this stream's focus context
 *   /coord gates   — show which gates are open/locked
 *
 * Loaded automatically from .pi/extensions/ in any worktree of this project.
 * Config is written by scripts/coordinate.sh setup → .pi/coord.json
 */

import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";

// ── Types ─────────────────────────────────────────────────────────────────

interface StreamDef {
  name: string;
  branch: string;
  path: string;
  ids: string[];
  focus: string;
}

interface CoordConfig {
  project: string;
  repoRoot: string;
  streams: StreamDef[];
}

type ItemStatus = "done" | "in-progress" | "blocked" | "todo" | "missing";

// ── Config Loading ────────────────────────────────────────────────────────

function findCoordConfig(startDir: string): CoordConfig | null {
  // Walk up from cwd looking for .pi/coord.json
  // Handles: main worktree and sibling worktrees (../project-stream/...)
  const candidates: string[] = [];

  // Check current dir and parents
  let dir = startDir;
  for (let i = 0; i < 6; i++) {
    candidates.push(join(dir, ".pi", "coord.json"));
    const parent = resolve(dir, "..");
    if (parent === dir) break;
    dir = parent;
  }

  // Also check sibling directories (worktrees are siblings of main)
  const parentDir = resolve(startDir, "..");
  try {
    const { readdirSync } = require("node:fs");
    for (const entry of readdirSync(parentDir)) {
      candidates.push(join(parentDir, entry, ".pi", "coord.json"));
    }
  } catch { /* ignore */ }

  for (const path of candidates) {
    if (existsSync(path)) {
      try {
        return JSON.parse(readFileSync(path, "utf8")) as CoordConfig;
      } catch { /* corrupt config — keep searching */ }
    }
  }
  return null;
}

// ── Backlog Parsing ───────────────────────────────────────────────────────

function parseBacklog(backlogPath: string): Map<string, ItemStatus> {
  const result = new Map<string, ItemStatus>();
  if (!existsSync(backlogPath)) return result;

  const lines = readFileSync(backlogPath, "utf8").split("\n");
  for (const line of lines) {
    // Match table rows: | ID | Pri | Phase | Status | Task | Notes |
    const match = line.match(/^\|\s*([A-Z]+-\d+)\s*\|[^|]*\|[^|]*\|\s*(\[.?\])\s*\|/);
    if (!match) continue;
    const [, id, status] = match;
    if      (status === "[x]") result.set(id, "done");
    else if (status === "[~]") result.set(id, "in-progress");
    else if (status === "[!]") result.set(id, "blocked");
    else                       result.set(id, "todo");
  }
  return result;
}

function streamStats(stream: StreamDef): {
  done: number; inProgress: number; blocked: number; todo: number; total: number; pct: number;
  statusMap: Map<string, ItemStatus>;
} {
  const backlogPath = join(stream.path, "docs", "backlog.md");
  const statusMap = parseBacklog(backlogPath);

  let done = 0, inProgress = 0, blocked = 0, todo = 0;
  for (const id of stream.ids) {
    switch (statusMap.get(id) ?? "todo") {
      case "done":        done++;        break;
      case "in-progress": inProgress++;  break;
      case "blocked":     blocked++;     break;
      default:            todo++;        break;
    }
  }

  const total = stream.ids.length;
  const pct = total > 0 ? Math.round((done / total) * 100) : 0;
  return { done, inProgress, blocked, todo, total, pct, statusMap };
}

// ── Gate Checking ─────────────────────────────────────────────────────────

// Foundation gate IDs — must all be [x] before parallel streams open
const FOUNDATION_GATE = ["F-01", "F-02", "F-03", "F-04", "F-05", "F-06", "F-07", "F-08"];

function gateStatus(config: CoordConfig, stream: StreamDef): "open" | "locked" {
  if (stream.name === "main") return "open";

  // Find main stream to check its backlog
  const main = config.streams.find(s => s.name === "main");
  if (!main) return "locked";

  const backlogPath = join(main.path, "docs", "backlog.md");
  const statusMap = parseBacklog(backlogPath);

  for (const id of FOUNDATION_GATE) {
    if (statusMap.get(id) !== "done") return "locked";
  }
  return "open";
}

// ── Rendering ─────────────────────────────────────────────────────────────

function progressBar(pct: number, width = 12): string {
  const filled = Math.round((pct / 100) * width);
  return "█".repeat(filled) + "░".repeat(width - filled);
}

function renderStatusTable(config: CoordConfig): string {
  const lines: string[] = [
    "",
    `── ${config.project} · Stream Status ${"─".repeat(34)}`,
    `  ${"Stream".padEnd(14)} ${"Gate".padEnd(8)} ${"Progress".padEnd(16)} Items`,
    `  ${"─".repeat(60)}`,
  ];

  for (const stream of config.streams) {
    const stats = streamStats(stream);
    const gate = gateStatus(config, stream);
    const gateIcon = gate === "open" ? "🔓 open " : "🔒 lock ";
    const bar = progressBar(stats.pct);

    const extras: string[] = [];
    if (stats.inProgress > 0) extras.push(`~${stats.inProgress}`);
    if (stats.blocked > 0)    extras.push(`!${stats.blocked}`);
    if (stats.todo > 0)       extras.push(`□${stats.todo}`);
    if (stats.done === stats.total && stats.total > 0) extras.push("✓ complete");

    const extraStr = extras.join(" ");
    lines.push(
      `  ${stream.name.padEnd(14)} ${gateIcon} ${bar} ${String(stats.pct).padStart(3)}%  ✓${stats.done}/${stats.total}  ${extraStr}`
    );
  }

  lines.push(`  ${"─".repeat(60)}`);
  lines.push("");
  return lines.join("\n");
}

function renderGates(config: CoordConfig): string {
  const lines: string[] = ["", `── ${config.project} · Gate Status ${"─".repeat(36)}`];

  // Foundation gate
  const main = config.streams.find(s => s.name === "main");
  if (main) {
    const backlogPath = join(main.path, "docs", "backlog.md");
    const statusMap = parseBacklog(backlogPath);
    const gateLines: string[] = [];
    let allDone = true;
    for (const id of FOUNDATION_GATE) {
      const s = statusMap.get(id) ?? "todo";
      if (s !== "done") allDone = false;
      const icon = s === "done" ? "✓" : s === "in-progress" ? "~" : "□";
      gateLines.push(`    ${icon} ${id}`);
    }
    const gateIcon = allDone ? "🔓" : "🔒";
    lines.push(`  ${gateIcon} Foundation Gate (unlocks all parallel streams):`);
    lines.push(...gateLines);
  }

  lines.push("");
  return lines.join("\n");
}

// ── Review Brief ─────────────────────────────────────────────────────────────

// Per-stream adversarial review guidance.
// Keeps the brief specific to each stream's security surface.
const STREAM_REVIEW_GUIDANCE: Record<string, { invariants: string[]; adversarialCases: string[] }> = {
  auth: {
    invariants: [
      "Token material MUST NOT appear in any log line, error message, or response body",
      "mTLS must validate the full cert chain against the CA — cert presence alone is insufficient",
      "A revoked token must be rejected on the very next request after revocation",
      "A token issued for identity A must be rejected when presented by identity B (no cross-identity replay)",
      "TLS 1.3 minimum — TLS 1.2 and below must be rejected at the listener level",
      "Client certificate is required on every connection — no-cert clients must fail the TLS handshake",
    ],
    adversarialCases: [
      "Present an expired client certificate → TLS handshake must fail",
      "Present a cert signed by an unknown/untrusted CA → handshake must fail",
      "Present no client certificate → handshake must fail",
      "Call /auth/session with a valid cert then call /sign with a revoked token → 401",
      "Capture a session token and replay it after calling /auth/revoke → 401",
      "Present a syntactically valid but HMAC-invalid token → 401, no timing leak",
      "Fuzz the token format (empty, too short, non-base64, correct length wrong bytes) → 401 each time",
      "Call /auth/refresh with an already-expired token → 401",
      "Verify error responses contain no token bytes, no HMAC keys, no cert fields beyond caller ID",
    ],
  },
  api: {
    invariants: [
      "No key material in ANY response body, header, error message, or log line",
      "Every handler must check: session token valid, policy allows, THEN call backend",
      "payload_hash must be exactly 32 bytes (SHA-256) — reject anything else before policy check",
      "Key IDs must match the allowed format — reject malformed IDs before policy check",
      "algorithm must be one of the defined enum values — reject unknown algorithms",
      "Audit event must be written BEFORE the response is sent, regardless of outcome",
    ],
    adversarialCases: [
      "Call /sign with a raw payload instead of a hash → 400, payload not echoed in error",
      "Call /sign with a 31-byte hash (too short) → 400",
      "Call /sign with an unknown algorithm string → 400",
      "Call /sign with a key ID that does not exist → 404, no backend detail in error",
      "Call /encrypt with nil/empty body → 400",
      "Call /keys and verify: no private key bytes, no AES key bytes in any field",
      "Send a request with no session token → 401 before any backend call",
      "Send a request with a malformed session token → 401 before any backend call",
      "Verify audit log contains the event for EVERY case above, including denials",
    ],
  },
  policy: {
    invariants: [
      "Deny-by-default: an empty rule set must deny ALL operations for ALL identities",
      "Allow rules must be explicit and specific — no wildcards unless intentionally designed",
      "A rule granting team A access must not grant access to team B",
      "Operation-type scoping: a signing key allow-rule must not permit encrypt/decrypt",
      "Rate limit state must not persist across policy reloads in a way that resets limits",
    ],
    adversarialCases: [
      "Load an empty policy → every Evaluate call must return Deny",
      "Load a policy granting team-A sign on key-X → team-B request for key-X must be denied",
      "Load a policy granting sign on key-X → encrypt request on key-X must be denied",
      "Load a policy with a key prefix rule → request for key outside prefix must be denied",
      "Attempt YAML injection in key ID field → must not execute or alter policy",
      "Load a policy file with invalid YAML → loader must return error, not silently allow all",
      "Load a policy with duplicate rule IDs → loader must reject or last-wins consistently",
    ],
  },
  backend: {
    invariants: [
      "No Backend method may return, log, or expose private key material",
      "Sign returns only signature bytes and key version — nothing else",
      "Encrypt returns only ciphertext — plaintext must not be echoed",
      "Decrypt returns only plaintext — key material must not be included",
      "RotateKey and ListKeys return KeyMeta only — no key-material fields",
      "All errors must be safe: no key bytes in error messages",
    ],
    adversarialCases: [
      "Call Sign and inspect SignResult for any bytes that look like a private key",
      "Call Encrypt and verify ciphertext does not contain the plaintext verbatim",
      "Call Decrypt with a truncated ciphertext → ErrInvalidInput, no key bytes in error",
      "Call Sign on an encryption key → ErrKeyTypeMismatch",
      "Call Encrypt on a signing key → ErrKeyTypeMismatch",
      "Call any method with a non-existent key ID → ErrKeyNotFound, no backend detail leaked",
      "Rotate a key then decrypt old ciphertext → must succeed using retained old version",
      "Call Sign with a 31-byte payloadHash → ErrInvalidInput",
    ],
  },
  "local-dev": {
    invariants: [
      "The dev server must enforce the same mTLS + token lifecycle as production — no shortcuts",
      "Dev certs must not be trusted by any non-local AgentKMS instance",
      "In-memory backend must never write key material to disk",
      "Policy must be loaded from file and enforced — no allow-all fallback",
      "All audit events must be written to the file sink — no silent drops",
    ],
    adversarialCases: [
      "Start server, connect without a client cert → TLS handshake failure",
      "Start server with an empty policy file → all operations denied",
      "Perform a sign operation and verify the audit log contains the event",
      "Revoke a token then use it → 401",
      "Verify the dev cert cannot be used against a different CA's server",
      "Shut down server → Flush must have been called, no missing audit events",
    ],
  },
  "pi-pkg": {
    invariants: [
      "Zero cryptographic logic in TypeScript — all crypto calls go to the AgentKMS service",
      "LLM API keys must only exist in the in-memory runtimeKeys map — never written to disk",
      "session_shutdown must revoke the server-side token before clearing local state",
      "tool_call hook must block reads to .env, auth.json, .agentkms/, credentials paths",
      "mTLS client cert path must be read from ~/.agentkms/ — never hardcoded",
    ],
    adversarialCases: [
      "Inspect the runtimeKeys map: values must be strings (keys), not logged or persisted",
      "Simulate session_shutdown with a network failure: token still expires naturally in 15min",
      "Attempt to read .env via the read tool → tool_call hook must block it",
      "Simulate a missing ~/.agentkms/client.crt → session_start must notify and abort cleanly",
      "Simulate a 401 from AgentKMS on token refresh → Pi must not crash, must re-authenticate",
      "Verify no API key appears in any console.log, pi.ui.notify, or tool result text",
    ],
  },
};

function renderReviewBrief(config: CoordConfig, stream: StreamDef): string {
  const backlogPath = join(stream.path, "docs", "backlog.md");
  const statusMap = parseBacklog(backlogPath);
  const stats = streamStats(stream);

  const guidance = STREAM_REVIEW_GUIDANCE[stream.name];

  const itemLines = stream.ids.map(id => {
    const s = statusMap.get(id) ?? "todo";
    const icon = s === "done" ? "[x]" : s === "in-progress" ? "[~]" : s === "blocked" ? "[!]" : "[ ]";
    return `    ${icon} ${id}`;
  }).join("\n");

  const isTS = stream.name === "pi-pkg";
  const qualityScript = `bash ${config.repoRoot}/scripts/quality_check.sh`;
  // Note: project script delegates to global skill: ~/.pi/agent/skills/quality-gate
  const qualityNote = isTS
    ? "(TypeScript stream — manual checks: no crypto imports, runtimeKeys in-memory only, toJSON redacts keys)"
    : qualityScript;

  let brief = [
    "",
    `${"-".repeat(66)}`,
    `  AgentKMS · Review Brief  [Adversarial + Quality]`,
    `${"-".repeat(66)}`,
    "",
    `  Stream:   ${stream.name}`,
    `  Branch:   ${stream.branch}`,
    `  Progress: ${stats.done}/${stats.total} items done (${stats.pct}%)`,
    "",
    `  ⚠️  INDEPENDENT SESSION REQUIRED`,
    `  Do not use the session that wrote this code.`,
    `  Open a NEW Pi session with /new or a fresh terminal.`,
    `  Paste this entire brief as your opening message.`,
    "",
    `  Backlog items under review:`,
    itemLines,
    "",
  ].join("\n");

  // Part 1: Adversarial security
  brief += `  ── PART 1: Adversarial Security Review ──────────────────────────────\n\n`;
  if (guidance) {
    brief += `  Security invariants to verify:\n`;
    for (const inv of guidance.invariants) {
      brief += `    • ${inv}\n`;
    }
    brief += `\n  Adversarial cases to run:\n`;
    for (const ac of guidance.adversarialCases) {
      brief += `    → ${ac}\n`;
    }
    brief += "\n";
  } else {
    brief += `  (No stream-specific guidance — review security invariants from AGENTS.md)\n\n`;
  }

  // Part 2: Code quality gate
  brief += [
    `  ── PART 2: Code Quality Gate ────────────────────────────────────────`,
    "",
    `  Run the quality check script and report each result:`,
    `    ${qualityNote}`,
    "",
    `  Quality checks:`,
    `    □ go vet — zero issues`,
    `    □ Coverage >= threshold (internal/auth|policy|audit >= 85%, others >= 80%)`,
    `    □ Every exported function in internal/ and pkg/ has at least one test`,
    `    □ Every t.Skip/t.Skipf has a linked issue: // TODO(#NNN): skip until YYYY-MM-DD`,
    `    □ Architecture conformance: implementation matches docs/architecture.md`,
    "",
    `  ── PART 3: Instructions ──────────────────────────────────────────────`,
    "",
    `  1. Read every modified/added file. Path: ${stream.path}`,
    `  2. Part 1: verify each invariant and adversarial case. PASS/FAIL each.`,
    `  3. Part 2: run the quality script. PASS/FAIL each check.`,
    `  4. Report all findings with severity: CRITICAL/HIGH/MEDIUM/LOW.`,
    `  5. The implementing session must address ALL findings before marking [x].`,
    "",
    `${"-".repeat(66)}`,
    "",
  ].join("\n");

  return brief;
}

// ── Extension ─────────────────────────────────────────────────────────────

export default function (pi: ExtensionAPI) {
  let config: CoordConfig | null = null;
  let currentStream: StreamDef | null = null;

  // ── Session Start: detect stream, inject context ──────────────────────

  pi.on("session_start", async (_event, ctx) => {
    config = findCoordConfig(ctx.cwd);
    if (!config) return;

    // Identify which stream this Pi instance is in by matching cwd
    const cwdResolved = resolve(ctx.cwd);
    currentStream = config.streams.find(s => resolve(s.path) === cwdResolved) ?? null;

    if (currentStream) {
      // Status bar shows stream name at a glance
      ctx.ui.setStatus("coord", `stream:${currentStream.name}`);

      // Show gate status if this stream's gate might still be locked
      const gate = gateStatus(config, currentStream);
      if (gate === "locked") {
        ctx.ui.notify(
          `⚠️  Coordinator: stream "${currentStream.name}" gate is LOCKED.\n` +
          `Foundation items F-01–F-08 must be [x] on main before this stream is active.\n` +
          `Run /coord gates to see which items remain.`,
          "error"
        );
      } else {
        ctx.ui.notify(
          `Coordinator: stream "${currentStream.name}" · branch "${currentStream.branch}"\n` +
          `Run /coord next to see your next task, /coord status for full overview.`,
          "info"
        );
      }
    } else if (config) {
      // We're in a Pi session inside the project but not a recognised stream dir
      // (e.g. running pi from the repo root outside of a worktree mapping)
      ctx.ui.setStatus("coord", `coord:unattached`);
      ctx.ui.notify(
        `Coordinator: project "${config.project}" detected but this directory is not a registered stream.\n` +
        `Run /coord status for full overview.`,
        "info"
      );
    }
  });

  // ── /coord command ────────────────────────────────────────────────────

  pi.registerCommand("coord", {
    description: "Coordinator: status | next | focus | gates",
    handler: async (args, ctx) => {
      if (!config) {
        ctx.ui.notify(
          "Coordinator: no .pi/coord.json found.\n" +
          "Run: ./scripts/coordinate.sh setup",
          "error"
        );
        return;
      }

      const subcmd = (args ?? "status").trim().split(/\s+/)[0];

      switch (subcmd) {
        case "status":
          ctx.ui.notify(renderStatusTable(config), "info");
          break;

        case "next": {
          const stream = currentStream ?? config.streams[0];
          const backlogPath = join(stream.path, "docs", "backlog.md");
          const statusMap = parseBacklog(backlogPath);

          const nextItems = stream.ids.filter(id => {
            const s = statusMap.get(id);
            return s === "todo" || s === "in-progress" || s === undefined;
          });

          if (nextItems.length === 0) {
            ctx.ui.notify(
              `✓ Stream "${stream.name}" is complete! All items done.\n` +
              `Run /coord status to check overall project state.`,
              "info"
            );
            break;
          }

          const nextId = nextItems[0];
          const inProgressItems = nextItems.filter(id => statusMap.get(id) === "in-progress");
          const remaining = nextItems.length;

          let msg = `Stream: ${stream.name} · Branch: ${stream.branch}\n\n`;

          if (inProgressItems.length > 0) {
            msg += `In progress: ${inProgressItems.join(", ")}\n`;
          }

          msg += `Next task:   ${nextId}\n`;
          msg += `Remaining:   ${remaining} item(s)\n\n`;
          msg += `Find ${nextId} in docs/backlog.md for full details and acceptance criteria.\n`;
          msg += `When done, mark it [x] in docs/backlog.md, then run /coord next.`;

          ctx.ui.notify(msg, "info");
          break;
        }

        case "focus": {
          const stream = currentStream;
          if (!stream) {
            ctx.ui.notify(
              "Not in a registered stream directory.\n" +
              "Run /coord status to see all streams.",
              "error"
            );
            break;
          }
          ctx.ui.notify(
            `Stream:  ${stream.name}\n` +
            `Branch:  ${stream.branch}\n` +
            `Path:    ${stream.path}\n\n` +
            `Focus:\n${stream.focus}`,
            "info"
          );
          break;
        }

        case "gates":
          ctx.ui.notify(renderGates(config), "info");
          break;

        case "review": {
          const stream = currentStream;
          if (!stream) {
            ctx.ui.notify(
              "Not in a registered stream directory. Run /coord status.",
              "error"
            );
            break;
          }
          ctx.ui.notify(renderReviewBrief(config, stream), "info");
          break;
        }

        default:
          ctx.ui.notify(
            "Usage: /coord <subcommand>\n\n" +
            "  status  — Progress table across all streams\n" +
            "  next    — Next TODO item in this stream\n" +
            "  focus   — This stream's focus and context\n" +
            "  gates   — Gate status (what must complete before streams unlock)\n" +
            "  review  — Print adversarial review brief for independent session",
            "info"
          );
      }
    },
  });
}
