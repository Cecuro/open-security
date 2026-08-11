/**
 * Coverage attribution for grep.
 *
 * pi's grep reports each hit relative to the directory it was asked to search,
 * and falls back to `basename` when the target was a single file. The ledger
 * holds repo-relative paths. Those two disagreed for every scoped search, so a
 * probe that narrowed its grep — the common case — recorded no coverage at all,
 * silently, against the one number the report asks to be trusted.
 */

import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createGrepToolDefinition } from "@earendil-works/pi-coding-agent";
import { describe, expect, it } from "vitest";

import { instrumentGrep } from "../src/agents/session.js";
import type { RunContext } from "../src/agents/tool.js";
import { Ledger } from "../src/db/db.js";
import { testScanConfig } from "./config.js";

function setup() {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "opensec-cov-")));
  const root = join(base, "repo");
  mkdirSync(join(root, "src", "handlers"), { recursive: true });
  writeFileSync(join(root, "src", "handlers", "upload.ts"), "const token = 'abc';\n");
  writeFileSync(join(root, "top.ts"), "const token = 'zzz';\n");

  const ledger = Ledger.open(join(base, "l.db"));
  const repoId = ledger.upsertRepo(root, "r", null);
  ledger.createScan({ id: "s", repoId, revision: null, config: testScanConfig() });
  ledger.insertFiles("s", [
    { path: "src/handlers/upload.ts", sha: "1", bytes: 21, excludedReason: null },
    { path: "top.ts", sha: "2", bytes: 21, excludedReason: null },
  ]);

  const ctx: RunContext = {
    scanId: "s", workerId: "probe-1", repoRoot: root, profile: "local", ledger, nonce: "N", readGroup: "pass-1",
  };
  const tool = instrumentGrep(createGrepToolDefinition(root) as never, ctx) as never as {
    execute: (i: string, p: unknown, s?: unknown, u?: unknown, c?: unknown) => Promise<unknown>;
  };
  const touched = () =>
    ledger.listWork("s", 50).files.filter((f) => f.first_touched_at !== null).map((f) => f.path);

  return { tool, touched, ledger };
}

describe("grep coverage is attributed to the repo-relative path", () => {
  it("records the touch for a whole-repo grep", async () => {
    const env = setup();
    await env.tool.execute("g", { pattern: "token" });
    expect(env.touched().sort()).toEqual(["src/handlers/upload.ts", "top.ts"]);
  });

  it("records the touch for a grep scoped to a subdirectory", async () => {
    const env = setup();
    await env.tool.execute("g", { pattern: "token", path: "src" });
    expect(env.touched()).toEqual(["src/handlers/upload.ts"]);
  });

  it("records the touch for a grep scoped to a single file", async () => {
    const env = setup();
    await env.tool.execute("g", { pattern: "token", path: "src/handlers/upload.ts" });
    expect(env.touched()).toEqual(["src/handlers/upload.ts"]);
  });

  it("marks a searched file with zero bytes read — searched is not reviewed", async () => {
    const env = setup();
    await env.tool.execute("g", { pattern: "token", path: "src" });
    const f = env.ledger.listWork("s", 50).files.find((x) => x.path === "src/handlers/upload.ts");
    expect(f?.first_touched_at).not.toBeNull();
    expect(f?.bytes_read).toBe(0);
  });

  it("does not invent coverage for a path outside the scan inventory", async () => {
    const env = setup();
    await env.tool.execute("g", { pattern: "nothing-matches-this-anywhere" });
    expect(env.touched()).toEqual([]);
  });
});
