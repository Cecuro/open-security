import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import {
	createSubagentTool,
	MAX_CONCURRENT,
	MAX_DEPTH,
	MAX_PER_PARENT,
	type SubagentDeps,
} from "../src/agents/subagent.js";
import { createOpensecTool, type RunContext, SUBAGENT_VERBS } from "../src/agents/tool.js";
import { Ledger } from "../src/db/db.js";
import { loadPrompts } from "../src/scan/prompts.js";

function setup(over: Partial<RunContext> = {}) {
	const base = mkdtempSync(join(tmpdir(), "opensec-sub-"));
	const root = join(base, "repo");
	mkdirSync(root);
	writeFileSync(join(root, "app.js"), "l1\nl2\n");

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
		nonce: "N",
		...over,
	};

	const calls: Array<{ workerId: string; verbs?: string[]; depth?: number }> = [];
	const deps: SubagentDeps = {
		prompts: loadPrompts(),
		run: async (a) => {
			calls.push({ workerId: a.ctx.workerId, verbs: a.ctx.verbs, depth: a.ctx.depth });
			return { text: "child report", tokensIn: 10, tokensOut: 5, costUsd: 0.01 };
		},
		checkBudget: () => {},
		bill: () => {},
		tracePath: (w) => join(base, `${w}.jsonl`),
	};

	return { ctx, deps, calls, ledger, base };
}

async function call(tool: NonNullable<ReturnType<typeof createSubagentTool>>, p: object) {
	const r = await tool.execute("t", p as never, undefined, undefined, {} as never);
	return r.content.map((c) => ("text" in c ? c.text : "")).join("");
}

describe("subagents run in-process and inherit the scan", () => {
	it("gives the child a scoped worker id, the next depth, and read-only verbs", async () => {
		const env = setup();
		const tool = createSubagentTool(env.ctx, env.deps);
		expect(tool).not.toBeNull();

		const out = await call(tool!, {
			agent_type: "tracer",
			task: "follow req.query.host to exec",
			description: "trace ping input",
		});

		expect(out).toBe("child report");
		expect(env.calls).toHaveLength(1);
		expect(env.calls[0]?.workerId).toBe("probe-1/tracer-1");
		expect(env.calls[0]?.depth).toBe(1);
		expect(env.calls[0]?.verbs).toEqual(SUBAGENT_VERBS);
	});

	it("is absent entirely at the depth limit, rather than present and always failing", () => {
		const env = setup({ depth: MAX_DEPTH });
		expect(createSubagentTool(env.ctx, env.deps)).toBeNull();
	});

	it("caps how many times one parent may delegate", async () => {
		const env = setup();
		const tool = createSubagentTool(env.ctx, env.deps)!;
		for (let i = 0; i < MAX_PER_PARENT; i++) {
			await call(tool, { agent_type: "tracer", task: `t${i}`, description: "d" });
		}
		await expect(
			call(tool, { agent_type: "tracer", task: "one too many", description: "d" }),
		).rejects.toThrow(/already delegated/);
		expect(env.calls).toHaveLength(MAX_PER_PARENT);
	});

	it("refuses to spawn when the scan is out of budget", async () => {
		const env = setup();
		const tool = createSubagentTool(env.ctx, {
			...env.deps,
			checkBudget: () => {
				throw new Error("budget exhausted: spent $3.0000 of $3");
			},
		})!;
		await expect(
			call(tool, { agent_type: "skeptic", task: "t", description: "d" }),
		).rejects.toThrow(/budget exhausted/);
	});

	it("holds concurrent subagents under the cap", async () => {
		const env = setup();
		let release: (() => void) | undefined;
		const gate = new Promise<void>((r) => {
			release = r;
		});
		const tool = createSubagentTool(env.ctx, {
			...env.deps,
			run: async () => {
				await gate;
				return { text: "ok", tokensIn: 0, tokensOut: 0, costUsd: 0 };
			},
		})!;

		const inflight = Array.from({ length: MAX_CONCURRENT }, (_, i) =>
			call(tool, { agent_type: "tracer", task: `t${i}`, description: "d" }),
		);
		await expect(
			call(tool, { agent_type: "tracer", task: "over", description: "d" }),
		).rejects.toThrow(/already running/);
		release?.();
		await Promise.all(inflight);
	});

	it("treats an empty child answer as unsettled, not as a negative result", async () => {
		const env = setup();
		const tool = createSubagentTool(env.ctx, {
			...env.deps,
			run: async () => ({ text: "   ", tokensIn: 0, tokensOut: 0, costUsd: 0 }),
		})!;
		const out = await call(tool, { agent_type: "skeptic", task: "t", description: "d" });
		expect(out).toContain("unsettled");
	});
});

describe("verb scoping", () => {
	it("stops a subagent from recording findings its parent never saw", async () => {
		const env = setup({ workerId: "probe-1/skeptic-1", verbs: SUBAGENT_VERBS, depth: 1 });
		const tool = createOpensecTool(env.ctx);
		const run = async (p: object) => {
			const r = await tool.execute("t", p as never, undefined, undefined, {} as never);
			return r.content.map((c) => ("text" in c ? c.text : "")).join("");
		};

		await expect(
			run({
				verb: "candidate.create",
				title: "t",
				summary: "s",
				evidence: "e",
				locations: [{ path: "app.js", start_line: 1, end_line: 1 }],
			}),
		).rejects.toThrow(/not available to probe-1\/skeptic-1/);

		// It can still page the worklist and record what it ruled out.
		expect(JSON.parse(await run({ verb: "work.next" })).total).toBe(1);
		await run({ verb: "lead.record", text: "checked, nothing there", status: "dead_end" });
		expect(env.ledger.listLeads("s")).toHaveLength(1);
	});

	it("leaves phase agents with all four verbs", async () => {
		const env = setup();
		const tool = createOpensecTool(env.ctx);
		const r = await tool.execute(
			"t",
			{
				verb: "candidate.create",
				title: "t",
				summary: "s",
				evidence: "e",
				locations: [{ path: "app.js", start_line: 1, end_line: 1 }],
			} as never,
			undefined,
			undefined,
			{} as never,
		);
		expect(JSON.parse(r.content.map((c) => ("text" in c ? c.text : "")).join("")).id).toBe("c1");
	});
});
