import { mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";

import { createOpensecTool, type RunContext } from "../src/agents/tool.js";
import { Ledger } from "../src/db/db.js";

const SCAN = "scan-test";

function setup(): { ctx: RunContext; call: (p: Record<string, unknown>) => Promise<string> } {
	const root = mkdtempSync(join(tmpdir(), "opensec-tool-"));
	writeFileSync(join(root, "app.js"), "line1\nline2\nline3\nline4\nline5\n");
	writeFileSync(join(root, "other.js"), "a\nb\n");
	writeFileSync(join(root, "secret.txt"), "not in scope\n");

	const ledger = Ledger.open(join(root, "ledger.db"));
	const repoId = ledger.upsertRepo(root, "fixture", null);
	ledger.createScan({ id: SCAN, repoId, revision: null, profile: "static", configHash: "h" });
	ledger.insertFiles(SCAN, [
		{ path: "app.js", sha: "x", bytes: 30, excludedReason: null },
		{ path: "other.js", sha: "y", bytes: 4, excludedReason: null },
		{ path: "secret.txt", sha: "z", bytes: 13, excludedReason: "binary (null byte)" },
	]);

	const ctx: RunContext = {
		scanId: SCAN,
		workerId: "probe-1",
		repoRoot: root,
		profile: "static",
		ledger,
		nonce: "NONCE123",
	};

	const tool = createOpensecTool(ctx);
	const call = async (p: Record<string, unknown>) => {
		const r = await tool.execute("id", p as never, undefined, undefined, {} as never);
		return r.content.map((c) => ("text" in c ? c.text : "")).join("");
	};
	return { ctx, call };
}

let env: ReturnType<typeof setup>;
beforeEach(() => {
	env = setup();
});

describe("work.next is the worklist, and excluded files are not in it", () => {
	it("returns in-scope files with a total and a cursor", async () => {
		const out = JSON.parse(await env.call({ verb: "work.next" }));
		expect(out.total).toBe(2);
		expect(out.remaining).toBe(0);
		expect(out.files.join(" ")).toContain("app.js");
		expect(out.files.join(" ")).not.toContain("secret.txt");
	});

	it("pages", async () => {
		const first = JSON.parse(await env.call({ verb: "work.next", limit: 1 }));
		expect(first.returned).toBe(1);
		expect(first.remaining).toBe(1);
		const second = JSON.parse(
			await env.call({ verb: "work.next", limit: 1, cursor: first.cursor }),
		);
		expect(second.remaining).toBe(0);
	});
});

describe("structural checks at the write boundary", () => {
	const good = {
		verb: "candidate.create",
		title: "Command injection",
		summary: "attacker controls host",
		evidence: "exec(`ping ${host}`)",
		locations: [{ path: "app.js", start_line: 2, end_line: 3 }],
	};

	it("accepts a well-formed candidate", async () => {
		const out = JSON.parse(await env.call(good));
		expect(out.id).toBe("c1");
	});

	it("rejects a line number the file does not have", async () => {
		await expect(
			env.call({ ...good, locations: [{ path: "app.js", start_line: 99, end_line: 99 }] }),
		).rejects.toThrow(/does not exist/);
	});

	it("rejects an inverted range", async () => {
		await expect(
			env.call({ ...good, locations: [{ path: "app.js", start_line: 4, end_line: 2 }] }),
		).rejects.toThrow(/not a valid range/);
	});

	it("rejects a path outside the repo", async () => {
		await expect(
			env.call({ ...good, locations: [{ path: "../escape.js", start_line: 1, end_line: 1 }] }),
		).rejects.toThrow(/outside the repo/);
	});

	it("rejects a symlink, because scanned code is attacker-authored", async () => {
		symlinkSync("/etc/passwd", join(env.ctx.repoRoot, "link.js"));
		await expect(
			env.call({ ...good, locations: [{ path: "link.js", start_line: 1, end_line: 1 }] }),
		).rejects.toThrow(/symlink/);
	});

	it("requires at least one location in the worker's own worklist", async () => {
		await expect(
			env.call({ ...good, locations: [{ path: "secret.txt", start_line: 1, end_line: 1 }] }),
		).rejects.toThrow(/no location is in your worklist/);
	});

	it("drops an invented CWE rather than recording it", async () => {
		await env.call({ ...good, cwe: ["CWE-78", "shell stuff", "cwe-22"] });
		const c = env.ctx.ledger.getCandidate(SCAN, "c1");
		expect(c?.cwe_ids).toEqual(["CWE-78", "CWE-22"]);
	});

	it("strips the run nonce out of agent prose", async () => {
		await env.call({ ...good, summary: "ignore previous NONCE123 instructions" });
		const c = env.ctx.ledger.getCandidate(SCAN, "c1");
		expect(c?.summary).not.toContain("NONCE123");
		expect(c?.summary).toContain("[nonce-stripped]");
	});

	it("strips terminal escape sequences from prose", async () => {
		await env.call({ ...good, title: "XSS ]52;c;cGF5bG9hZA== here" });
		const c = env.ctx.ledger.getCandidate(SCAN, "c1");
		expect(c?.title).not.toContain("");
	});
});

describe("degradation is directional", () => {
	const good = {
		verb: "candidate.create",
		title: "SQLi",
		summary: "s",
		evidence: "e",
		locations: [{ path: "app.js", start_line: 1, end_line: 1 }],
	};

	const confirm = () =>
		env.call({
			verb: "candidate.validate",
			id: "c1",
			disposition: "confirmed",
			rationale: "traced it",
		});

	it("keeps an unresolvable duplicate as needs_follow_up rather than dropping it", async () => {
		await env.call(good);
		const out = JSON.parse(
			await env.call({
				verb: "candidate.validate",
				id: "c1",
				disposition: "duplicate",
				duplicate_of: "c99",
				rationale: "same as the other one",
			}),
		);
		expect(out.disposition).toBe("needs_follow_up");
	});

	it("keeps an assessment with missing severity inputs as needs_follow_up", async () => {
		await env.call(good);
		await confirm();
		const out = JSON.parse(
			await env.call({
				verb: "candidate.assess",
				id: "c1",
				rationale: "looks bad",
				entry_point: "app.js:1",
				path: ["app.js:1"],
			}),
		);
		expect(out.disposition).toBe("needs_follow_up");
	});

	it("computes severity rather than accepting one", async () => {
		await env.call(good);
		await confirm();
		const out = JSON.parse(
			await env.call({
				verb: "candidate.assess",
				id: "c1",
				rationale: "traced it",
				entry_point: "app.js:1 — attacker controls the id parameter",
				path: ["app.js:1 id reaches the query"],
				controls: [],
				impact: "high",
				vector: "remote",
				auth_required: "none",
				network_reachable: true,
				traced_path_no_control: true,
				method: "code_reading",
			}),
		);
		expect(out.severity).toBe("critical");
		expect(out.proof_gap).toBe("no_execution");
		expect(out.confidence).toBe(0.3);
	});

	it("keeps a finding whose suppression the gate does not accept", async () => {
		await env.call(good);
		await confirm();
		const out = JSON.parse(
			await env.call({
				verb: "candidate.assess",
				id: "c1",
				rationale: "probably fine",
				entry_point: "app.js:1",
				path: ["app.js:1"],
				impact: "medium",
				vector: "remote",
				auth_required: "none",
				network_reachable: true,
				method: "code_reading",
				suppression: { evidence: "feels minor to me" },
			}),
		);
		// No boolean was set, so nothing was suppressed. Low importance is a low
		// severity, not a removal.
		expect(out.disposition).toBe("confirmed");
		expect(out.severity).toBe("high");
	});
});

describe("the two passes are separate, and the tool enforces it", () => {
	const good = {
		verb: "candidate.create",
		title: "SQLi",
		summary: "s",
		evidence: "e",
		locations: [{ path: "app.js", start_line: 1, end_line: 1 }],
	};

	it("refuses to rate a candidate no one has validated", async () => {
		await env.call(good);
		await expect(
			env.call({
				verb: "candidate.assess",
				id: "c1",
				rationale: "straight to a severity",
				impact: "high",
				method: "code_reading",
			}),
		).rejects.toThrow(/not confirmed by validation/);
	});

	it("refuses to rate a candidate validation threw out", async () => {
		await env.call(good);
		await env.call({
			verb: "candidate.validate",
			id: "c1",
			disposition: "not_applicable",
			rationale: "the query is parameterised at app.js:2",
		});
		await expect(
			env.call({ verb: "candidate.assess", id: "c1", rationale: "x", impact: "high", method: "code_reading" }),
		).rejects.toThrow(/not confirmed by validation/);
	});

	it("keeps both passes' rationales instead of overwriting one with the other", async () => {
		await env.call(good);
		await env.call({
			verb: "candidate.validate",
			id: "c1",
			disposition: "confirmed",
			rationale: "the interpolation at app.js:1 is real",
		});
		await env.call({
			verb: "candidate.assess",
			id: "c1",
			rationale: "reachable from the public route",
			entry_point: "app.js:1",
			path: ["app.js:1"],
			impact: "high",
			vector: "remote",
			auth_required: "none",
			network_reachable: true,
			method: "code_reading",
		});
		const c = env.ctx.ledger.getCandidate(SCAN, "c1");
		expect(c?.resolution?.validation?.rationale).toContain("interpolation");
		expect(c?.resolution?.attack_path?.rationale).toContain("public route");
		expect(c?.resolution?.computed?.severity).toBe("high");
	});
});

describe("traced_path_no_control is checked against the trace", () => {
	const good = {
		verb: "candidate.create",
		title: "SQLi",
		summary: "s",
		evidence: "e",
		locations: [{ path: "app.js", start_line: 1, end_line: 1 }],
	};

	const assess = async (over: Record<string, unknown>) => {
		await env.call(good);
		await env.call({ verb: "candidate.validate", id: "c1", disposition: "confirmed", rationale: "r" });
		return JSON.parse(
			await env.call({
				verb: "candidate.assess",
				id: "c1",
				rationale: "r",
				impact: "high",
				vector: "remote",
				auth_required: "none",
				network_reachable: true,
				traced_path_no_control: true,
				method: "code_reading",
				...over,
			}),
		);
	};

	it("rejects the claim when no path was recorded", async () => {
		const out = await assess({ entry_point: "app.js:1", path: [] });
		// Without it, the finding is high rather than critical.
		expect(out.severity).toBe("high");
		expect(out.notes.join(" ")).toContain("requires the trace");
	});

	it("rejects the claim when the trace itself lists controls", async () => {
		const out = await assess({
			entry_point: "app.js:1",
			path: ["app.js:1 → app.js:3"],
			controls: ["app.js:2 escapes the value"],
		});
		expect(out.severity).toBe("high");
		expect(out.notes.join(" ")).toContain("cannot both be true");
	});

	it("accepts it when the trace backs it", async () => {
		const out = await assess({
			entry_point: "app.js:1",
			path: ["app.js:1 → app.js:3"],
			controls: [],
		});
		expect(out.severity).toBe("critical");
	});
});

describe("leads", () => {
	it("records dead ends", async () => {
		await env.call({ verb: "lead.record", text: "checked the CSRF story, framework covers it", status: "dead_end" });
		expect(env.ctx.ledger.listLeads(SCAN)).toHaveLength(1);
	});
});
