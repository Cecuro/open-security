import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { Ledger } from "../src/db/db.js";
import { startReviewServer, type RunningReviewServer } from "../src/review/server.js";
import { testScanConfig } from "./config.js";

function fixture(): { db: string; scanId: string } {
	const db = join(mkdtempSync(join(tmpdir(), "opensec-review-")), "ledger.db");
	const ledger = Ledger.open(db);
	const repoId = ledger.upsertRepo("/tmp/review-repo", "review-repo", null);
	ledger.createScan({ id: "scan-review", repoId, revision: "abcdef123456", config: testScanConfig() });
	ledger.insertFiles("scan-review", [
		{ path: "src/server.ts", sha: "sha", bytes: 100, excludedReason: null },
	]);
	ledger.recordTouch("scan-review", "src/server.ts", 100);
	const candidate = ledger.upsertCandidate({
		scanId: "scan-review",
		workerId: "probe-1",
		title: "Request bypasses authorization",
		cweIds: ["CWE-862"],
		locations: [{ path: "src/server.ts", start_line: 12, end_line: 14 }],
		description: "An unauthenticated request reaches the handler.",
	});
	ledger.addCandidateActivity({
		scanId: "scan-review",
		candidateId: candidate.id,
		workerId: "assessment-1",
		kind: "assessment",
		body: "The route has no guard.",
		status: "confirmed",
		data: {
			disposition: "confirmed",
			computed: {
				severity: "high",
				likelihood: "high",
				confidence: 0.3,
				reportable: true,
				rationale: ["Remote input reaches a privileged action."],
			},
		},
	});
	ledger.finishScan("scan-review", "completed");
	ledger.close();
	return { db, scanId: "scan-review" };
}

describe("local review server", () => {
	let running: RunningReviewServer | undefined;
	afterEach(async () => {
		if (running) await running.close();
		running = undefined;
	});

	it("serves run data only with the page token", async () => {
		const { db } = fixture();
		running = await startReviewServer({ db });
		const page = await (await fetch(running.url)).text();
		const token = page.match(/name="opensec-token" content="([^"]+)"/)?.[1];
		expect(token).toBeTruthy();

		const denied = await fetch(new URL("/api/scans", running.url));
		expect(denied.status).toBe(403);

		const response = await fetch(new URL("/api/scans", running.url), {
			headers: { "X-OpenSec-Token": token as string },
		});
		expect(await response.json()).toMatchObject([
			{ id: "scan-review", repo_name: "review-repo", finding_count: 1 },
		]);
	});

	it("keeps state changes and comments in finding history", async () => {
		const { db, scanId } = fixture();
		running = await startReviewServer({ db, scanId });
		const page = await (await fetch(running.url)).text();
		const token = page.match(/name="opensec-token" content="([^"]+)"/)?.[1] as string;
		const endpoint = new URL(`/api/scans/${scanId}/candidates/c1/review`, running.url);
		const response = await fetch(endpoint, {
			method: "POST",
			headers: { "Content-Type": "application/json", "X-OpenSec-Token": token },
			body: JSON.stringify({ status: "needs_follow_up", comment: "Check the reverse proxy first." }),
		});
		expect(response.status).toBe(200);
		const candidate = await response.json();
		expect(candidate.status).toBe("needs_follow_up");
		expect(candidate.activities.slice(-2)).toMatchObject([
			{ kind: "review", worker_id: "reviewer" },
			{ kind: "comment", body: "Check the reverse proxy first." },
		]);
	});

	it("exports a self-contained read-only HTML snapshot", async () => {
		const { db, scanId } = fixture();
		running = await startReviewServer({ db });
		const page = await (await fetch(running.url)).text();
		const token = page.match(/name="opensec-token" content="([^"]+)"/)?.[1] as string;
		const response = await fetch(new URL(`/api/scans/${scanId}/export?format=html`, running.url), {
			headers: { "X-OpenSec-Token": token },
		});
		const html = await response.text();
		expect(response.headers.get("content-disposition")).toContain("review-repo-scan-review.html");
		expect(html).toContain("window.__OPENSEC_SNAPSHOT__");
		expect(html).toContain("Request bypasses authorization");
		expect(html).not.toContain('href="/assets/styles.css"');
		expect(html).not.toContain("/tmp/review-repo");
	});
});

describe("review history", () => {
	it("records a human review when the agent state is kept", () => {
		const { db, scanId } = fixture();
		const ledger = Ledger.open(db);
		const reviewed = ledger.reviewCandidate({ scanId, candidateId: "c1", status: "confirmed" });
		expect(reviewed.status).toBe("confirmed");
		expect(reviewed.activities.at(-1)).toMatchObject({
			kind: "review",
			body: "Reviewed as confirmed.",
		});
		ledger.close();
	});

	it("keeps a duplicate merge link when a comment is added", () => {
		const { db, scanId } = fixture();
		const ledger = Ledger.open(db);
		const duplicate = ledger.upsertCandidate({
			scanId,
			workerId: "probe-2",
			title: "A second filing",
			cweIds: ["CWE-862"],
			locations: [{ path: "src/server.ts", start_line: 20, end_line: 20 }],
			description: "Same root cause.",
		});
		ledger.addCandidateActivity({
			scanId,
			candidateId: duplicate.id,
			workerId: "reduce-1",
			kind: "duplicate",
			body: "Same authorization gap.",
			status: "duplicate",
			data: { disposition: "duplicate", duplicate_of: "c1" },
			duplicateOf: "c1",
		});

		const reviewed = ledger.reviewCandidate({
			scanId,
			candidateId: duplicate.id,
			comment: "Keep this filing as supporting evidence.",
		});
		expect(reviewed.status).toBe("duplicate");
		expect(reviewed.duplicate_of).toBe("c1");
		ledger.close();
	});
});
