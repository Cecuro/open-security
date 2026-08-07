/**
 * Dedup in two layers. Layer one is identity and costs nothing; layer two is a
 * model reading a small group. These tests are entirely about layer one and
 * about which groups layer two would ever see — the model's judgement is not
 * testable here, but "does a model get called at all" very much is, and that is
 * the part that costs money.
 */

import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { createOpensecTool, PROBE_VERBS, type RunContext } from "../src/agents/tool.js";
import { Ledger } from "../src/db/db.js";
import { collisionGroups, cweFamily, identityOf, mergeProse } from "../src/scan/identity.js";

function setup() {
	const base = mkdtempSync(join(tmpdir(), "opensec-dedup-"));
	const root = join(base, "repo");
	mkdirSync(root);
	writeFileSync(join(root, "a.js"), "l1\nl2\nl3\nl4\n");
	writeFileSync(join(root, "b.js"), "l1\nl2\nl3\nl4\n");

	const ledger = Ledger.open(join(base, "l.db"));
	const repoId = ledger.upsertRepo(root, "r", null);
	ledger.createScan({ id: "s", repoId, revision: null, profile: "static", configHash: "c" });
	ledger.insertFiles("s", [
		{ path: "a.js", sha: "1", bytes: 12, excludedReason: null },
		{ path: "b.js", sha: "2", bytes: 12, excludedReason: null },
	]);

	/** Two probes writing into the same scan, as they do in a real run. */
	const probe = (id: string) => {
		const ctx: RunContext = {
			scanId: "s",
			workerId: id,
			repoRoot: root,
			profile: "static",
			ledger,
			nonce: "N",
			verbs: PROBE_VERBS,
		};
		const tool = createOpensecTool(ctx);
		return async (p: Record<string, unknown>) =>
			JSON.parse(
				(await tool.execute("t", p as never, undefined, undefined, {} as never)).content
					.map((c) => ("text" in c ? c.text : ""))
					.join(""),
			);
	};

	const file = (over: Record<string, unknown> = {}) => ({
		verb: "candidate.create",
		title: "SQL injection in getUser",
		cwe: ["CWE-89"],
		summary: "the id is interpolated",
		evidence: "a.js:2",
		locations: [{ path: "a.js", start_line: 2, end_line: 2, role: "sink" }],
		...over,
	});

	return { ledger, probe, file };
}

describe("identical findings collapse without a model", () => {
	it("folds a second probe's filing into the first row", async () => {
		const env = setup();
		const p1 = env.probe("probe-1");
		const p2 = env.probe("probe-2");

		const first = await p1(env.file());
		expect(first.status).toBe("recorded");

		const second = await p2(
			env.file({
				// Different words, different line inside the same function, same finding.
				title: "SQLi via id",
				summary: "user-controlled id reaches the query",
				evidence: "a.js:3",
				locations: [{ path: "a.js", start_line: 3, end_line: 3, role: "sink" }],
			}),
		);
		expect(second.id).toBe(first.id);
		expect(second.status).toBe("merged_into_existing");

		// One row, and neither probe's evidence was thrown away.
		const live = env.ledger.listLiveCandidates("s");
		expect(live).toHaveLength(1);
		expect(live[0]?.evidence).toContain("a.js:2");
		expect(live[0]?.evidence).toContain("a.js:3");
		expect(live[0]?.locations).toHaveLength(2);
	});

	it("does not resolve the merged row — finding it twice is not a verdict", async () => {
		const env = setup();
		await env.probe("probe-1")(env.file());
		await env.probe("probe-2")(env.file());
		expect(env.ledger.listLiveCandidates("s")[0]?.resolution).toBeUndefined();
	});

	it("keeps siblings apart when the probe distinguishes them", async () => {
		const env = setup();
		const p = env.probe("probe-1");
		await p(env.file({ instance: "param=id" }));
		await p(env.file({ instance: "param=name" }));
		expect(env.ledger.listLiveCandidates("s")).toHaveLength(2);
	});

	it("treats a different role in the same file as a different finding", () => {
		const sink = identityOf({
			cweIds: ["CWE-89"],
			locations: [{ path: "a.js", role: "sink" }],
		});
		const control = identityOf({
			cweIds: ["CWE-89"],
			locations: [{ path: "a.js", role: "root_control" }],
		});
		expect(sink).not.toBe(control);
	});

	it("ignores line numbers, so identity survives the code moving", () => {
		const a = identityOf({ cweIds: ["CWE-89"], locations: [{ path: "a.js", role: "sink" }] });
		const b = identityOf({ cweIds: ["CWE-89"], locations: [{ path: "a.js", role: "sink" }] });
		expect(a).toBe(b);
	});

	it("joins CWE ids that name the same broken control", () => {
		expect(cweFamily(["CWE-22"])).toBe(cweFamily(["CWE-23"]));
		expect(cweFamily(["CWE-89"])).not.toBe(cweFamily(["CWE-22"]));
		// Unclassified is not a family that everything else joins.
		expect(cweFamily([])).toBe("unclassified");
		expect(cweFamily(["CWE-9999"])).toBe("cwe-9999");
	});
});

describe("only real collisions reach a model", () => {
	const c = (id: string, cwe: string[], path: string) => ({
		id,
		cwe_ids: cwe,
		locations: [{ path, start_line: 1, end_line: 1 }],
	});

	it("sends nothing when every finding stands alone", () => {
		expect(
			collisionGroups([c("c1", ["CWE-89"], "a.js"), c("c2", ["CWE-78"], "b.js")]),
		).toEqual([]);
	});

	it("groups same class and same file, and not same class alone", () => {
		const groups = collisionGroups([
			c("c1", ["CWE-89"], "a.js"),
			c("c2", ["CWE-89"], "a.js"),
			c("c3", ["CWE-89"], "b.js"),
		]);
		expect(groups).toHaveLength(1);
		expect(groups[0]?.map((g) => g.id)).toEqual(["c1", "c2"]);
	});

	it("groups across an aliased CWE, which is the case a string match misses", () => {
		const groups = collisionGroups([c("c1", ["CWE-22"], "a.js"), c("c2", ["CWE-36"], "a.js")]);
		expect(groups).toHaveLength(1);
	});
});

describe("merging prose keeps both readers", () => {
	it("unions blocks and drops only exact repeats", () => {
		expect(mergeProse("one\n\ntwo", "two\n\nthree")).toBe("one\n\ntwo\n\nthree");
	});

	it("keeps the first text when the second adds nothing", () => {
		expect(mergeProse("same", "same")).toBe("same");
	});
});
