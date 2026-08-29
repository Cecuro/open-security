/**
 * A failed scan's work is recoverable. The two halves of that claim:
 * reportScan renders everything the ledger holds without agents, a repo, or a
 * model; and resume re-enters at the phase the scan stopped in rather than
 * re-running (and re-billing) the phases that finished.
 */

import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { Ledger, scanArtifactDir } from "../src/db/db.js";
import { PHASE_ORDER, phaseBefore, reportScan, Scanner } from "../src/sdk/scanner.js";
import type { Phase } from "../src/types.js";
import { testScanConfig } from "./config.js";

const artifacts: string[] = [];
afterEach(() => {
	for (const d of artifacts.splice(0)) rmSync(d, { recursive: true, force: true });
});

function openLedger(): Ledger {
	return Ledger.open(join(mkdtempSync(join(tmpdir(), "opensec-resume-")), "l.db"));
}

/** A scan as a crash mid-validate leaves it: findings filed, one verdict in. */
function seedFailedScan(ledger: Ledger, scanId: string): void {
	const repoId = ledger.upsertRepo("/tmp/some-repo", "some-repo", null);
	ledger.createScan({
		id: scanId,
		repoId,
		revision: "cafebabe",
		config: testScanConfig("local", {
			modelRef: "prov/model-x",
			promptHash: "ph123",
			passes: 2,
		}),
	});
	ledger.insertFiles(scanId, [
		{ path: "a.ts", sha: "s1", bytes: 100, excludedReason: null },
		{ path: "img.png", sha: "", bytes: 0, excludedReason: "binary (.png)" },
	]);
	ledger.setThreatModel(scanId, "the threat model", "generated:/home/x/threat-model.md");
	ledger.recordTouch(scanId, "a.ts", 100);

	ledger.upsertCandidate({
		scanId,
		workerId: "probe-1",
		title: "SQL injection in getUser",
		cweIds: ["CWE-89"],
		locations: [{ path: "a.ts", start_line: 1, end_line: 2 }],
		description: "id is interpolated\n\na.ts:1",
	});
	ledger.addCandidateActivity({
		scanId,
		candidateId: "c1",
		workerId: "validate-c1",
		kind: "validation",
		body: "traced it",
		status: "confirmed",
		data: { disposition: "confirmed" },
	});
	ledger.upsertCandidate({
		scanId,
		workerId: "probe-2",
		title: "Unvalidated thing",
		cweIds: [],
		locations: [{ path: "a.ts", start_line: 3, end_line: 3 }],
		description: "s\n\ne",
	});
	ledger.setPhase(scanId, "validate");
	ledger.finishScan(scanId, "failed");
}

describe("reportScan renders from the ledger alone", () => {
	it("turns a failed scan's recorded work into the same report a live scan writes", () => {
		const ledger = openLedger();
		const scanId = `resume-test-${process.pid}-a`;
		artifacts.push(scanArtifactDir(scanId));
		seedFailedScan(ledger, scanId);

		const result = reportScan(ledger, scanId);

		// The work that finished is all there.
		expect(result.markdown).toContain("SQL injection in getUser");
		expect(result.markdown).toContain("Unvalidated thing");
		expect(result.markdown).toContain("Needs follow-up");
		// Provenance comes from the scan row, not from live Scanner state.
		expect(result.markdown).toContain("prov/model-x");
		expect(result.markdown).toContain("ph123");
		expect(result.markdown).toContain("2 pass(es), each over all 1 files");
		expect(result.markdown).toContain("threat-model.md");
		expect(result.markdown).toContain("1 / 1 files touched");
		// And it is written to disk like a live report.
		expect(readFileSync(result.reportPath, "utf8")).toBe(result.markdown);
		const json = JSON.parse(readFileSync(result.jsonPath, "utf8"));
		expect(json.scan.id).toBe(scanId);
		expect(json.candidates).toHaveLength(2);

		ledger.close();
	});

	it("names the fix when the scan id is unknown", () => {
		const ledger = openLedger();
		expect(() => reportScan(ledger, "no-such-scan")).toThrow(/opensec report/);
		ledger.close();
	});

	it("renders normalized provenance stored on a new scan", () => {
		const ledger = openLedger();
		const scanId = `resume-test-${process.pid}-b`;
		artifacts.push(scanArtifactDir(scanId));
		const repoId = ledger.upsertRepo("/tmp/old-repo", "old-repo", null);
		ledger.createScan({ id: scanId, repoId, revision: null, config: testScanConfig() });
		ledger.insertFiles(scanId, [{ path: "x.js", sha: "s", bytes: 5, excludedReason: null }]);
		ledger.finishScan(scanId, "failed");

		const result = reportScan(ledger, scanId);
		expect(result.markdown).toContain("test/model");
		expect(result.markdown).toContain("test-prompts");
		expect(result.markdown).toContain("1 pass(es), each over all 1 files");
		ledger.close();
	});

	it("writes a completed scan's terminal state into findings.json", () => {
		const ledger = openLedger();
		const scanId = `resume-test-${process.pid}-completed`;
		artifacts.push(scanArtifactDir(scanId));
		const repoId = ledger.upsertRepo("/tmp/completed-repo", "completed-repo", null);
		ledger.createScan({ id: scanId, repoId, revision: null, config: testScanConfig() });
		ledger.finishScan(scanId, "completed");

		const result = reportScan(ledger, scanId);
		const json = JSON.parse(readFileSync(result.jsonPath, "utf8"));
		expect(json.scan).toMatchObject({ status: "completed", phase: "report" });
		expect(json.scan.completed_at).toBeTypeOf("string");
		ledger.close();
	});
});

describe("resume re-enters at the recorded phase", () => {
	it("refuses a legacy static scan instead of changing its execution model", async () => {
		const db = join(mkdtempSync(join(tmpdir(), "opensec-static-resume-")), "l.db");
		const ledger = Ledger.open(db);
		const repoId = ledger.upsertRepo("/tmp/legacy-repo", "legacy-repo", null);
		ledger.createScan({
			id: "legacy-static",
			repoId,
			revision: null,
			config: { ...testScanConfig(), profile: "static" as never },
		});
		ledger.finishScan("legacy-static", "failed");
		ledger.close();

		await expect(Scanner.resume("legacy-static", { db })).rejects.toThrow(
			"used the removed static profile",
		);
	});

	it("refuses to change the number of passes on resume", async () => {
		const db = join(mkdtempSync(join(tmpdir(), "opensec-pass-resume-")), "l.db");
		const ledger = Ledger.open(db);
		const repoId = ledger.upsertRepo("/tmp", "tmp", null);
		ledger.createScan({
			id: "two-pass",
			repoId,
			revision: null,
			config: testScanConfig("local", { passes: 2 }),
		});
		ledger.finishScan("two-pass", "failed");
		ledger.close();

		await expect(Scanner.resume("two-pass", { db, passes: 1 })).rejects.toThrow(
			"started with 2 pass(es)",
		);
	});

	it("orders phases the way run() executes them", () => {
		const expected: Phase[] = [
			"inventory",
			"threat_model",
			"discovery",
			"reduce",
			"validate",
			"assessment",
			"report",
		];
		expect(PHASE_ORDER).toEqual(expected);
	});

	it("skips exactly the phases before the one the scan stopped in", () => {
		// Failed mid-validate: discovery agents must not run (and bill) again.
		expect(phaseBefore("inventory", "validate")).toBe(true);
		expect(phaseBefore("discovery", "validate")).toBe(true);
		expect(phaseBefore("reduce", "validate")).toBe(true);
		expect(phaseBefore("validate", "validate")).toBe(false);
		expect(phaseBefore("assessment", "validate")).toBe(false);
		// A fresh scan starts at inventory and skips nothing.
		for (const p of PHASE_ORDER) expect(phaseBefore(p, "inventory")).toBe(false);
	});

	it("reopenScan puts a failed scan back into running with no completed_at", () => {
		const ledger = openLedger();
		const scanId = `resume-test-${process.pid}-c`;
		seedFailedScan(ledger, scanId);
		expect(ledger.getScan(scanId)?.status).toBe("failed");

		ledger.reopenScan(scanId);
		const scan = ledger.getScan(scanId);
		expect(scan?.status).toBe("running");
		expect(scan?.completed_at).toBeNull();
		// The phase it stopped in survives — it is where resume re-enters.
		expect(scan?.phase).toBe("validate");
		ledger.close();
	});

	it("keeps the recorded coverage: resuming must not wipe touches", () => {
		const ledger = openLedger();
		const scanId = `resume-test-${process.pid}-d`;
		seedFailedScan(ledger, scanId);
		// The resume path reads state instead of re-running inventory, so what it
		// needs must all be derivable from the ledger.
		expect(ledger.hasFiles(scanId)).toBe(true);
		expect(ledger.listInScopePaths(scanId)).toEqual(["a.ts"]);
		expect(ledger.coverage(scanId).files_touched).toBe(1);
		expect(ledger.getRepo(ledger.getScan(scanId)!.repo_id)?.path).toBe("/tmp/some-repo");
		ledger.close();
	});

	it("counts prior worker attempts so resumed traces do not overwrite each other", () => {
		const ledger = openLedger();
		const scanId = `resume-test-${process.pid}-attempts`;
		seedFailedScan(ledger, scanId);
		expect(ledger.workerAttemptCount(scanId, "probe-1")).toBe(0);
		ledger.recordEvent(scanId, "agent_start", {}, "probe-1");
		ledger.recordEvent(scanId, "agent_start", {}, "probe-1");
		expect(ledger.workerAttemptCount(scanId, "probe-1")).toBe(2);
		ledger.recordEvent(scanId, "agent_start", {}, "probe-1/sub-1");
		expect(ledger.workerAttemptCount(scanId, "probe-1/sub-1")).toBe(1);
		expect(ledger.workerAttemptCount(scanId, "probe-1_sub-1")).toBe(0);
		ledger.close();
	});

	it("listScans shows what 'opensec report' with no id prints", () => {
		const ledger = openLedger();
		const scanId = `resume-test-${process.pid}-e`;
		seedFailedScan(ledger, scanId);
		const scans = ledger.listScans(10);
		expect(scans).toHaveLength(1);
		expect(scans[0]).toMatchObject({
			id: scanId,
			repo_name: "some-repo",
			status: "failed",
			phase: "validate",
		});
		ledger.close();
	});
});
