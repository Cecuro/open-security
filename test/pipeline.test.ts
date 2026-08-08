/**
 * The whole M0 loop minus the model: inventory → worklist → candidates →
 * resolutions → computed severity → markdown. Everything an agent would do is
 * done here by calling the same tool the agent calls.
 */

import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { createOpensecTool, type RunContext } from "../src/agents/tool.js";
import { Ledger } from "../src/db/db.js";
import { inventory } from "../src/scan/inventory.js";
import { renderMarkdown } from "../src/scan/render.js";

const FIXTURE = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "vuln-app");
const SCAN = "scan-pipeline";

describe("the M0 loop, without a model", () => {
	it("goes from a directory to a report with file:line and a defensible severity", async () => {
		// --- phase 0: inventory ------------------------------------------------
		const inv = await inventory(FIXTURE);
		expect(inv.inScope.map((f) => f.path).sort()).toEqual(["db.js", "server.js"]);
		// Byte-identical ordering across runs.
		expect(inv.entries.map((e) => e.path)).toEqual([...inv.entries.map((e) => e.path)].sort());

		const ledger = Ledger.open(join(mkdtempSync(join(tmpdir(), "opensec-e2e-")), "l.db"));
		const repoId = ledger.upsertRepo(FIXTURE, "vuln-app", null);
		ledger.createScan({
			id: SCAN,
			repoId,
			revision: "deadbeef",
			profile: "static",
			configHash: "cfg",
		});
		ledger.insertFiles(
			SCAN,
			inv.entries.map((e) => ({
				path: e.path,
				sha: e.sha,
				bytes: e.bytes,
				excludedReason: e.excludedReason,
			})),
		);

		const ctx: RunContext = {
			scanId: SCAN,
			workerId: "probe-1",
			repoRoot: FIXTURE,
			profile: "static",
			ledger,
			nonce: "N0NCE",
		};
		const tool = createOpensecTool(ctx);
		const call = async (p: Record<string, unknown>) => {
			const r = await tool.execute("t", p as never, undefined, undefined, {} as never);
			return JSON.parse(r.content.map((c) => ("text" in c ? c.text : "")).join(""));
		};

		// --- phase 2: the probe ------------------------------------------------
		const work = await call({ verb: "work.next" });
		expect(work.returned).toBe(2);
		expect(work.remaining).toBe(0);

		const cmdi = await call({
			verb: "candidate.create",
			title: "Command injection in /api/ping",
			cwe: ["CWE-78"],
			summary: "req.query.host reaches exec() unquoted, so a shell metacharacter runs commands.",
			evidence: "server.js:18 exec(`ping -c 1 ${host}`) with host from req.query at server.js:17",
			locations: [{ path: "server.js", start_line: 16, end_line: 22, symbol: "GET /api/ping" }],
		});
		expect(cmdi.id).toBe("c1");

		const sqli = await call({
			verb: "candidate.create",
			title: "SQL injection in getUser",
			cwe: ["CWE-89"],
			summary: "The id path parameter is interpolated into a SELECT.",
			evidence: "db.js:9 conn.get(`... WHERE id = '${id}'`), reached from server.js:37",
			locations: [{ path: "db.js", start_line: 8, end_line: 10, symbol: "getUser" }],
		});
		expect(sqli.id).toBe("c2");

		await call({
			verb: "lead.record",
			text: "Checked /api/admin/reset for auth bypass — constant-time comparison is missing but the token is not attacker-observable here.",
			status: "dead_end",
		});

		// Coverage comes from reads, so simulate the reads the probe made.
		ledger.recordTouch(SCAN, "server.js", 1200);
		ledger.recordTouch(SCAN, "db.js", 380);

		// --- phase 3a: validate ------------------------------------------------
		// No severity here. This pass only decides whether the finding is real.
		for (const [id, why] of [
			["c1", "req.query.host at server.js:17 does reach exec at server.js:18."],
			["c2", "The id parameter is interpolated at db.js:9, as filed."],
		] as const) {
			const v = await call({
				verb: "candidate.validate",
				id,
				disposition: "confirmed",
				rationale: why,
			});
			expect(v.disposition).toBe("confirmed");
		}

		// --- phase 3b: attack path ---------------------------------------------
		const r1 = await call({
			verb: "candidate.assess",
			id: "c1",
			rationale: "Nothing validates, escapes or allowlists the host between the two.",
			entry_point: "server.js:17 — GET /api/ping, attacker controls the host query parameter",
			path: ["server.js:17 host = req.query.host", "server.js:18 exec(`ping -c 1 ${host}`)"],
			controls: [],
			impact: "high",
			vector: "remote",
			auth_required: "none",
			network_reachable: true,
			traced_path_no_control: true,
			method: "code_reading",
		});
		expect(r1.severity).toBe("critical");
		expect(r1.proof_gap).toBe("no_execution");
		expect(r1.confidence).toBe(0.3);

		const r2 = await call({
			verb: "candidate.assess",
			id: "c2",
			rationale: "The route requires an Authorization header, so an unauthenticated attacker cannot reach it.",
			entry_point: "server.js:37 — GET /api/user/:id, behind an Authorization check",
			path: ["server.js:37 id from the path", "db.js:9 interpolated into the SELECT"],
			controls: ["server.js:35 requires an Authorization header"],
			impact: "high",
			vector: "remote",
			auth_required: "user",
			network_reachable: true,
			method: "code_reading",
		});
		// Same impact, different auth: the matrix, not the model, makes it high.
		expect(r2.severity).toBe("high");

		// --- phase 4: report ---------------------------------------------------
		const scan = ledger.getScan(SCAN);
		expect(scan).toBeDefined();
		const md = renderMarkdown({
			scan: scan!,
			repoName: "vuln-app",
			repoPath: FIXTURE,
			candidates: ledger.listCandidates(SCAN),
			coverage: ledger.coverage(SCAN),
			leads: ledger.listLeads(SCAN),
			extensions: inv.extensions,
			excludedFiles: ledger.excludedCount(SCAN),
			modelRef: "test/none",
			promptHash: "abc123",
		});

		expect(md).toContain("critical (unproven)");
		// Both passes are attributed separately in the report.
		expect(md).toContain("**Validation**");
		expect(md).toContain("**Attack path**");
		expect(md).toContain("**No control was found on this path.**");
		expect(md).toContain("Controls on this path:");
		expect(md).toContain("`server.js:16`");
		expect(md).toContain("Command injection in /api/ping");
		expect(md).toContain("2 / 2 files touched");
		expect(md).toContain("laziness detector");
		expect(md).toContain("Leads that went nowhere");
		// The static profile must say so in the report, not just in the config.
		expect(md).toContain("Nothing was executed");

		ledger.close();
	});

	it("orders findings by severity and separates the ones it could not settle", async () => {
		const ledger = Ledger.open(join(mkdtempSync(join(tmpdir(), "opensec-e2e2-")), "l.db"));
		const repoId = ledger.upsertRepo(FIXTURE, "vuln-app", null);
		ledger.createScan({ id: "s2", repoId, revision: null, profile: "static", configHash: "c" });
		ledger.insertFiles("s2", [
			{ path: "server.js", sha: "a", bytes: 100, excludedReason: null },
		]);

		const ctx: RunContext = {
			scanId: "s2",
			workerId: "probe-1",
			repoRoot: FIXTURE,
			profile: "static",
			ledger,
			nonce: "n",
		};
		const tool = createOpensecTool(ctx);
		const call = async (p: Record<string, unknown>) =>
			JSON.parse(
				(await tool.execute("t", p as never, undefined, undefined, {} as never)).content
					.map((c) => ("text" in c ? c.text : ""))
					.join(""),
			);

		await call({
			verb: "candidate.create",
			title: "Unsettled thing",
			summary: "s",
			evidence: "e",
			locations: [{ path: "server.js", start_line: 1, end_line: 1 }],
		});
		await call({
			verb: "candidate.validate",
			id: "c1",
			disposition: "needs_follow_up",
			rationale: "Could not determine whether this route is mounted.",
		});

		const md = renderMarkdown({
			scan: ledger.getScan("s2")!,
			repoName: "vuln-app",
			repoPath: FIXTURE,
			candidates: ledger.listCandidates("s2"),
			coverage: ledger.coverage("s2"),
			leads: [],
			extensions: ["js"],
			excludedFiles: 0,
			modelRef: "test/none",
			promptHash: "h",
		});

		expect(md).toContain("_No confirmed findings._");
		expect(md).toContain("That is not the same as a clean scan");
		expect(md).toContain("Needs follow-up");
		ledger.close();
	});
});
