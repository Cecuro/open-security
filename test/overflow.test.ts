/**
 * Oversized tool results: run once, keep everything, page the record.
 *
 * Truncation with a continuation hint is correct for `read` — `offset=401`
 * returns the rest of the same file. It is wrong for anything whose second run
 * is not the first one continued: a shell command with side effects, or a
 * subagent, which costs another full agent run and answers *differently* rather
 * than resuming. Those spill to a file the caller can read.
 */

import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import {
	createSubagentTool,
	MAX_INLINE_REPORT_BYTES,
	type SubagentDeps,
} from "../src/agents/subagent.js";
import { readableFrom } from "../src/agents/session.js";
import type { RunContext } from "../src/agents/tool.js";
import { Ledger } from "../src/db/db.js";
import { loadPrompts } from "../src/scan/prompts.js";

function setup(reportText: string) {
	const base = mkdtempSync(join(tmpdir(), "opensec-overflow-"));
	const root = join(base, "repo");
	mkdirSync(root);
	writeFileSync(join(root, "app.js"), "l1\nl2\n");
	const overflowDir = join(base, "overflow", "probe-1");

	const ledger = Ledger.open(join(base, "l.db"));
	const repoId = ledger.upsertRepo(root, "r", null);
	ledger.createScan({ id: "s", repoId, revision: null, profile: "static", configHash: "c" });
	ledger.insertFiles("s", [{ path: "app.js", sha: "1", bytes: 6, excludedReason: null }]);

	const ctx: RunContext = {
		scanId: "s",
		workerId: "probe-1",
		repoRoot: root,
		profile: "static",
		ledger,
		// A realistic nonce. `randomBytes(9).toString("hex")` in a real run — a
		// one-character nonce would have sanitize() strip that letter out of
		// ordinary prose, which says nothing about the code.
		nonce: "a1b2c3d4e5f60718293a",
		overflowDir,
	};

	let runs = 0;
	const deps: SubagentDeps = {
		prompts: loadPrompts(),
		run: async () => {
			runs += 1;
			return { text: reportText, tokensIn: 1, tokensOut: 1, costUsd: 0 };
		},
		checkBudget: () => {},
		bill: () => {},
		tracePath: (w) => join(base, `${w}.jsonl`),
	};

	const call = async (tool: NonNullable<ReturnType<typeof createSubagentTool>>) => {
		const r = await tool.execute(
			"t",
			{ task: "trace it", description: "d" } as never,
			undefined,
			undefined,
			{} as never,
		);
		return r.content.map((c) => ("text" in c ? c.text : "")).join("");
	};

	return { ctx, deps, call, overflowDir, base, runs: () => runs };
}

describe("a subagent report larger than the inline budget", () => {
	const huge = `HEAD-MARKER\n${"x".repeat(MAX_INLINE_REPORT_BYTES)}\nTAIL-MARKER`;

	it("inlines the head, writes the whole thing down, and names the path", async () => {
		const env = setup(huge);
		const out = await env.call(createSubagentTool(env.ctx, env.deps)!);

		expect(out).toContain("HEAD-MARKER");
		// The tail is NOT in the parent's context...
		expect(out).not.toContain("TAIL-MARKER");
		// ...but it is on disk, in full, and the parent is told where.
		const file = join(env.overflowDir, "probe-1_sub-1.md");
		expect(out).toContain(file);
		const saved = readFileSync(file, "utf8");
		expect(saved).toBe(huge);
		expect(saved).toContain("TAIL-MARKER");
	});

	it("budgets the inline head in bytes, not UTF-16 units, and never splits a code point", async () => {
		// "é" is one JS character but two UTF-8 bytes: a character-counted slice
		// would inline twice the budget, and a byte-counted one that cuts blindly
		// would end mid-sequence and render a replacement character.
		const env = setup("é".repeat(MAX_INLINE_REPORT_BYTES));
		const out = await env.call(createSubagentTool(env.ctx, env.deps)!);
		const head = out.split("\n\n[")[0] ?? "";
		expect(Buffer.byteLength(head, "utf8")).toBeLessThanOrEqual(MAX_INLINE_REPORT_BYTES);
		expect(head).not.toContain("�");
	});

	it("tells the parent not to re-delegate, because a rerun is a different answer", async () => {
		const env = setup(huge);
		const out = await env.call(createSubagentTool(env.ctx, env.deps)!);
		expect(out).toMatch(/does not resume/i);
		// One execution. The record is paged, not regenerated.
		expect(env.runs()).toBe(1);
	});

	it("says so plainly when it could not be written down", async () => {
		const env = setup(huge);
		// No overflow directory: the report cannot be preserved, and the parent
		// must be told that what it has is incomplete rather than left to assume.
		const tool = createSubagentTool({ ...env.ctx, overflowDir: undefined }, env.deps)!;
		const out = await env.call(tool);
		expect(out).toContain("HEAD-MARKER");
		expect(out).toContain("it is lost");
		expect(out).toMatch(/narrower question/);
	});
});

describe("the read boundary lets the parent page what it spilled, and nothing else", () => {
	const huge = `HEAD-MARKER\n${"x".repeat(MAX_INLINE_REPORT_BYTES)}\nTAIL-MARKER`;

	it("permits the overflow file it was just handed", async () => {
		const env = setup(huge);
		await env.call(createSubagentTool(env.ctx, env.deps)!);
		const file = join(env.overflowDir, "probe-1_sub-1.md");
		// Pointing an agent at a path it is then refused is worse than not
		// spilling at all. This is the assertion that keeps the loop closed.
		expect(readableFrom(env.ctx, file)).toBe(true);
	});

	it("still refuses everything else outside the repo", () => {
		const env = setup("short");
		expect(readableFrom(env.ctx, "/etc/passwd")).toBe(false);
		expect(readableFrom(env.ctx, join(homedir(), ".ssh", "id_rsa"))).toBe(false);
		// The scan directory one level up holds other workers' traces and findings.
		expect(readableFrom(env.ctx, join(env.overflowDir, "..", "probe-2", "report.md"))).toBe(
			false,
		);
		// And a worker with no overflow directory gets no extra reach at all.
		expect(readableFrom({ ...env.ctx, overflowDir: undefined }, join(env.overflowDir, "x.md"))).toBe(
			false,
		);
	});

	it("does not let the overflow path be used to escape by traversal", () => {
		const env = setup("short");
		expect(readableFrom(env.ctx, join(env.overflowDir, "..", "..", "..", "etc", "passwd"))).toBe(
			false,
		);
	});
});

describe("an ordinary report is untouched", () => {
	it("passes through with no path, no notice, no file", async () => {
		const env = setup("Answer: yes. Traced app.js:1 → app.js:2. Nothing on the path.");
		const out = await env.call(createSubagentTool(env.ctx, env.deps)!);
		expect(out).toBe("Answer: yes. Traced app.js:1 → app.js:2. Nothing on the path.");
		expect(out).not.toContain("Truncated");
	});

	it("still degrades an empty answer into 'unsettled' rather than a negative result", async () => {
		const env = setup("   ");
		const out = await env.call(createSubagentTool(env.ctx, env.deps)!);
		expect(out).toContain("unsettled");
	});
});
