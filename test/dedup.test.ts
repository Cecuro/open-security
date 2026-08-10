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

import { runOpensec, PROBE_VERBS, type RunContext } from "../src/agents/tool.js";
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
	ledger.createScan({ id: "s", repoId, revision: null, profile: "local", configHash: "c" });
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
			profile: "local",
			ledger,
			nonce: "N",
			verbs: PROBE_VERBS,
		};
		return async (p: Record<string, unknown>) => JSON.parse(runOpensec(ctx, p as never));
	};

	const file = (over: Record<string, unknown> = {}) => ({
		verb: "candidate.create",
		title: "SQL injection in getUser",
		cwe: ["CWE-89"],
		description: "the id is interpolated\n\na.js:2",
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
					description: "user-controlled id reaches the query\n\na.js:3",
				locations: [{ path: "a.js", start_line: 3, end_line: 3, role: "sink" }],
			}),
		);
		expect(second.id).toBe(first.id);
		expect(second.status).toBe("merged_into_existing");

		// One row, and neither probe's evidence was thrown away.
		const live = env.ledger.listLiveCandidates("s");
		expect(live).toHaveLength(1);
		expect(live[0]?.description).toContain("a.js:2");
		expect(live[0]?.description).toContain("a.js:3");
		expect(live[0]?.locations).toHaveLength(2);
	});

	it("does not resolve the merged row — finding it twice is not a verdict", async () => {
		const env = setup();
		await env.probe("probe-1")(env.file());
		await env.probe("probe-2")(env.file());
		expect(env.ledger.listLiveCandidates("s")[0]?.status).toBe("open");
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

describe("what reaches the reducer is keyed on the broken control", () => {
	const at = (id: string, cwe: string[], locs: Array<[string, string?]>) => ({
		id,
		cwe_ids: cwe,
		locations: locs.map(([path, role]) => ({
			path,
			start_line: 1,
			end_line: 1,
			...(role ? { role: role as "root_control" | "entrypoint" | "sink" } : {}),
		})),
	});

	it("leaves findings in unrelated files alone", () => {
		expect(
			collisionGroups([at("c1", ["CWE-89"], [["a.js"]]), at("c2", ["CWE-78"], [["b.js"]])]),
		).toEqual([]);
	});

	it("groups two descriptions of one bug that agree on nothing but the broken control", () => {
		// The case that reached a real report twice: same liquidation flaw, filed
		// once from the implementation with no CWE and once from the entry point
		// with CWE-682, root_control lines 44 apart in the same file. Keying on
		// the primary location and the CWE family missed it three separate ways.
		const groups = collisionGroups([
			at("c1", [], [["perps.rs", "entrypoint"], ["perps.rs", "root_control"]]),
			at("c6", ["CWE-682"], [["contract.rs", "entrypoint"], ["perps.rs", "root_control"]]),
		]);
		expect(groups).toHaveLength(1);
		expect(groups[0]?.map((g) => g.id)).toEqual(["c1", "c6"]);
	});

	it("prefers root_control over the primary location", () => {
		// Two findings sharing a primary file but breaking different controls are
		// not the same finding, and asking about them is not free.
		const groups = collisionGroups([
			at("c1", ["CWE-89"], [["route.ts", "entrypoint"], ["db.ts", "root_control"]]),
			at("c2", ["CWE-89"], [["route.ts", "entrypoint"], ["auth.ts", "root_control"]]),
		]);
		expect(groups).toEqual([]);
	});

	it("falls back to the primary location when no root_control was given", () => {
		const groups = collisionGroups([
			at("c1", ["CWE-22"], [["a.js"]]),
			at("c2", ["CWE-36"], [["a.js"]]),
		]);
		expect(groups).toHaveLength(1);
	});

	it("groups regardless of class, because the reducer is what decides", () => {
		// Recall-first on purpose: an unnecessary group costs one reducer call it
		// is free to refuse, while a missed one is a duplicate nothing catches.
		const groups = collisionGroups([
			at("c1", ["CWE-89"], [["x.rs", "root_control"]]),
			at("c2", ["CWE-682"], [["x.rs", "root_control"]]),
		]);
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
