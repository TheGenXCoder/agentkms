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

        default:
          ctx.ui.notify(
            "Usage: /coord <subcommand>\n\n" +
            "  status  — Progress table across all streams\n" +
            "  next    — Next TODO item in this stream\n" +
            "  focus   — This stream's focus and context\n" +
            "  gates   — Gate status (what must complete before streams unlock)",
            "info"
          );
      }
    },
  });
}
