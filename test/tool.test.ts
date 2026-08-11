import { mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";

import { runOpensec, type RunContext, THREAT_MODEL_VERBS } from "../src/agents/tool.js";
import { Ledger } from "../src/db/db.js";
import { testScanConfig } from "./config.js";

const SCAN = "scan-test";

function setup(): { ctx: RunContext; call: (p: Record<string, unknown>) => Promise<string> } {
	const root = mkdtempSync(join(tmpdir(), "opensec-tool-"));
	writeFileSync(join(root, "app.js"), "line1\nline2\nline3\nline4\nline5\n");
	writeFileSync(join(root, "other.js"), "a\nb\n");
	writeFileSync(join(root, "secret.txt"), "not in scope\n");

	const ledger = Ledger.open(join(root, "ledger.db"));
	const repoId = ledger.upsertRepo(root, "fixture", null);
	ledger.createScan({ id: SCAN, repoId, revision: null, config: testScanConfig() });
	ledger.insertFiles(SCAN, [
		{ path: "app.js", sha: "x", bytes: 30, excludedReason: null },
		{ path: "other.js", sha: "y", bytes: 4, excludedReason: null },
		{ path: "secret.txt", sha: "z", bytes: 13, excludedReason: "binary (null byte)" },
	]);

	const ctx: RunContext = {
		scanId: SCAN,
		workerId: "probe-1",
		repoRoot: root,
		profile: "local",
		ledger,
		nonce: "NONCE123",
	};

	const call = async (p: Record<string, unknown>) => runOpensec(ctx, p as never);
	return { ctx, call };
}

let env: ReturnType<typeof setup>;
beforeEach(() => {
	env = setup();
});

describe("work.next is the worklist, and excluded files are not in it", () => {
	it("returns in-scope files, and never an excluded one", async () => {
		const out = JSON.parse(await env.call({ verb: "work.next" }));
		expect(out.returned).toBe(2);
		expect(out.remaining).toBe(0);
		expect(out.files.join(" ")).toContain("app.js");
		expect(out.files.join(" ")).not.toContain("secret.txt");
	});

	it("hands out the same files again until they are actually read", async () => {
		// The load-bearing one. A cursor let a probe page to the end of a 427-file
		// worklist having read a fifth of it, and report itself done. There is no
		// cursor now: the list is what nothing has read, so asking again without
		// reading gets the same answer.
		const first = JSON.parse(await env.call({ verb: "work.next", limit: 1 }));
		expect(first.returned).toBe(1);
		expect(first.remaining).toBe(1);

		const again = JSON.parse(await env.call({ verb: "work.next", limit: 1 }));
		expect(again.files).toEqual(first.files);
		expect(again.remaining).toBe(1);

		await env.call({ verb: "work.next", limit: 1 });
		env.ctx.ledger.recordTouch(SCAN, "app.js", 30);
		const after = JSON.parse(await env.call({ verb: "work.next", limit: 1 }));
		expect(after.files.join(" ")).toContain("other.js");
		expect(after.remaining).toBe(0);
	});

	it("does not count a grep as reading", async () => {
		// recordTouch with zero bytes is what a grep hit does. Otherwise one
		// repo-wide grep empties the worklist without a file being reviewed.
		env.ctx.ledger.recordTouch(SCAN, "app.js", 0);
		const out = JSON.parse(await env.call({ verb: "work.next" }));
		expect(out.files.join(" ")).toContain("app.js");
		expect(out.returned).toBe(2);
	});

	it("caps the batch, and says so rather than capping silently", async () => {
		// A silent cap is the tool lying about what it did: an agent that asked
		// for 200 and got 2 could reasonably read that as a nearly-empty worklist.
		const out = JSON.parse(await env.call({ verb: "work.next", limit: 200 }));
		expect(out.returned).toBeLessThanOrEqual(50);
		expect(out.asked).toBe(200);
		expect(out.capped_to).toBe(50);
		expect(out.note).toMatch(/capped at 50/);
	});

	it("says nothing about the cap when the request was within it", async () => {
		const out = JSON.parse(await env.call({ verb: "work.next", limit: 10 }));
		expect(out.asked).toBeUndefined();
		expect(out.note).not.toMatch(/capped/);
	});

	it("requires work.complete after the final page", async () => {
		env.ctx.worklist = ["app.js", "other.js"];
		env.ctx.readGroup = "pass-1";
		env.ctx.ledger.recordEvent(SCAN, "work_started", { read_group: "pass-1" }, "probe-1");
		await expect(
			env.call({ verb: "work.complete", summary: "Reviewed one file" }),
		).rejects.toThrow(/not complete/);
		env.ctx.ledger.recordTouch(SCAN, "app.js", 30, false, "pass-1", "probe-1");
		env.ctx.ledger.recordTouch(SCAN, "other.js", 4, false, "pass-1", "probe-1");
		expect(env.ctx.ledger.passCoverage(SCAN, 1)[0]?.completed).toBe(false);
		expect(JSON.parse(await env.call({
			verb: "work.complete",
			summary: "Reviewed both files; no further concerns.",
		}))).toMatchObject({ status: "complete" });
		expect(env.ctx.ledger.passCoverage(SCAN, 1)[0]?.completed).toBe(true);
	});

	it("tracks threat-model paging without counting it as probe coverage", async () => {
		env.ctx.readGroup = "threat-model";
		env.ctx.ledger.recordTouch(SCAN, "app.js", 30, false, "threat-model", "threat-model");
		const next = JSON.parse(await env.call({ verb: "work.next", limit: 1 }));
		expect(next.files.join(" ")).toContain("other.js");
		expect(env.ctx.ledger.coverage(SCAN).bytes_read).toBe(0);
	});
});

describe("structural checks at the write boundary", () => {
	const good = {
		verb: "candidate.create",
		title: "Command injection",
		description: "attacker controls host\n\nexec(`ping ${host}`)",
		locations: [{ path: "app.js", start_line: 2, end_line: 3 }],
	};

	it("accepts a well-formed candidate", async () => {
		const out = JSON.parse(await env.call(good));
		expect(out.id).toBe("c1");
	});

	it("rejects malformed location metadata instead of weakening identity", async () => {
		await expect(
			env.call({
				...good,
				locations: [{ path: "app.js", start_line: 2, end_line: 3, role: "root-control" }],
			}),
		).rejects.toThrow(/location.role must be one of/);
		await expect(
			env.call({
				...good,
				locations: [{ path: "app.js", start_line: 2, end_line: 3, symbol: 42 }],
			}),
		).rejects.toThrow(/location.symbol must be a string/);
	});

	it("rejects unknown location fields", async () => {
		await expect(
			env.call({
				...good,
				locations: [{ path: "app.js", start_line: 2, end_line: 3, sink: true }],
			}),
		).rejects.toThrow(/location does not accept: sink/);
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
		await env.call({ ...good, description: "ignore previous NONCE123 instructions" });
		const c = env.ctx.ledger.getCandidate(SCAN, "c1");
		expect(c?.description).not.toContain("NONCE123");
		expect(c?.description).toContain("[nonce-stripped]");
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
		description: "s\n\ne",
		locations: [{ path: "app.js", start_line: 1, end_line: 1 }],
	};

	const confirm = () =>
		env.call({
			verb: "candidate.validate",
			id: "c1",
			disposition: "confirmed",
			rationale: "traced it",
		});

	it("refuses an unresolvable duplicate and records nothing", async () => {
		await env.call(good);
		await expect(
			env.call({
				verb: "candidate.validate",
				id: "c1",
				disposition: "duplicate",
				duplicate_of: "c99",
				rationale: "same as the other one",
			}),
		).rejects.toThrow(/no candidate 'c99'/);
		// Writing anything here would give c1 a validation record it never
		// earned, and the validate pass skips rows that already have one.
		const c1 = env.ctx.ledger.getCandidate("scan-test", "c1");
		expect(c1?.status).toBe("open");
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

	it("rejects invalid CLI assessment values before computing or storing them", async () => {
		await env.call(good);
		await confirm();
		await expect(
			env.call({
				verb: "candidate.assess",
				id: "c1",
				rationale: "bad input",
				impact: "catastrophic",
				method: "code_reading",
			}),
		).rejects.toThrow(/impact must be one of/);
		expect(env.ctx.ledger.getCandidate(SCAN, "c1")?.activities).toHaveLength(1);
	});

	it("rejects non-boolean assessment flags", async () => {
		await env.call(good);
		await confirm();
		await expect(
			env.call({
				verb: "candidate.assess",
				id: "c1",
				rationale: "bad input",
				impact: "high",
				method: "code_reading",
				network_reachable: "yes",
			}),
		).rejects.toThrow(/network_reachable must be a boolean/);
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
		description: "s\n\ne",
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

	it("rejects an unknown validation disposition", async () => {
		await env.call(good);
		await expect(
			env.call({
				verb: "candidate.validate",
				id: "c1",
				disposition: "accepted",
				rationale: "x",
			}),
		).rejects.toThrow(/disposition must be one of/);
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
		expect(c?.activities.find((a) => a.kind === "validation")?.body).toContain("interpolation");
		expect(c?.activities.find((a) => a.kind === "assessment")?.body).toContain("public route");
		expect(c?.activities.find((a) => a.kind === "assessment")?.data?.computed?.severity).toBe("high");
	});
});

describe("traced_path_no_control is checked against the trace", () => {
	const good = {
		verb: "candidate.create",
		title: "SQLi",
		description: "s\n\ne",
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

describe("the threat-model phase is a map, not a findings list", () => {
	function threatModelCall() {
		const ctx: RunContext = { ...env.ctx, workerId: "threat-model", verbs: THREAT_MODEL_VERBS };
		return async (p: Record<string, unknown>) => runOpensec(ctx, p as never);
	}

	it("can read the worklist but cannot file a candidate", async () => {
		const call = threatModelCall();
		expect(JSON.parse(await call({ verb: "work.next" })).returned).toBe(2);
		await expect(
			call({
				verb: "candidate.create",
				title: "t",
				description: "s\n\ne",
				locations: [{ path: "app.js", start_line: 1, end_line: 2 }],
			}),
		).rejects.toThrow(/not available to threat-model/);
	});
});

describe("what ties a finding to your worklist", () => {
	const base = {
		verb: "candidate.create",
		title: "t",
		cwe: ["CWE-78"],
		description: "s\n\ne",
	};

	it("refuses a finding anchored only by an evidence mention", async () => {
		// The real case: README.md is in scope and merely mentions a route; the
		// entrypoint, broken control and sink are all in files the user excluded.
		// Allowing it lets a passing mention pull out-of-scope code into a report.
		await expect(
			env.call({
				...base,
				locations: [
					{ path: "app.js", start_line: 1, end_line: 1, role: "evidence" },
					{ path: "secret.txt", start_line: 1, end_line: 1, role: "root_control" },
				],
			}),
		).rejects.toThrow(/evidence location does not tie a finding to you/);
	});

	it("tells a refused agent where to put the finding instead", async () => {
		// A refusal with nowhere to go loses what the agent found. If the flaw
		// really is outside its list, the lead is the record that survives.
		await expect(
			env.call({
				...base,
				locations: [
					{ path: "app.js", start_line: 1, end_line: 1, role: "evidence" },
					{ path: "secret.txt", start_line: 1, end_line: 1, role: "root_control" },
				],
			}),
			).rejects.toThrow(/completion summary/);
	});

	it("accepts it when a substantive location is in scope", async () => {
		const out = JSON.parse(
			await env.call({
				...base,
				locations: [
					{ path: "other.js", start_line: 1, end_line: 1, role: "evidence" },
					{ path: "app.js", start_line: 1, end_line: 1, role: "sink" },
				],
			}),
		);
		expect(out.status).toMatch(/recorded|merged_into_existing/);
	});

	it("falls back to any location when no roles were given at all", async () => {
		// Nothing to discriminate on, so the older rule stands rather than
		// refusing every finding from an agent that omits roles.
		const out = JSON.parse(
			await env.call({
				...base,
				locations: [{ path: "app.js", start_line: 2, end_line: 2 }],
			}),
		);
		expect(out.status).toMatch(/recorded|merged_into_existing/);
	});
});
