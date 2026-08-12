import { mkdtempSync } from "node:fs";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { Ledger } from "../src/db/db.js";
import { startReviewServer, type RunningReviewServer } from "../src/review/server.js";
import { testScanConfig } from "./config.js";

function fixture(options: { completed?: boolean; partial?: boolean; title?: string; description?: string } = {}): { db: string; scanId: string } {
	const db = join(mkdtempSync(join(tmpdir(), "opensec-review-")), "ledger.db");
	const ledger = Ledger.open(db);
	const repoId = ledger.upsertRepo("/tmp/review-repo", "review-repo", null);
	ledger.createScan({ id: "scan-review", repoId, revision: "abcdef123456", config: testScanConfig() });
	ledger.insertFiles("scan-review", [
		{ path: "src/server.ts", sha: "sha", bytes: 100, excludedReason: null },
	]);
	ledger.recordTouch("scan-review", "src/server.ts", 100);
	ledger.recordEvent("scan-review", "work_started", { read_group: "pass-1" }, "probe-1");
	if (!options.partial) {
		ledger.recordEvent("scan-review", "work_complete", { read_group: "pass-1" }, "probe-1");
	}
	const candidate = ledger.upsertCandidate({
		scanId: "scan-review",
		workerId: "probe-1",
		title: options.title ?? "Request bypasses authorization",
		cweIds: ["CWE-862"],
		locations: [{ path: "src/server.ts", start_line: 12, end_line: 14 }],
		description: options.description ?? "An unauthenticated request reaches the handler.",
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
	if (options.completed !== false) {
		ledger.finishScan("scan-review", options.partial ? "partial" : "completed");
	}
	ledger.close();
	return { db, scanId: "scan-review" };
}

function getWithHost(url: string, host: string): Promise<{ status: number; body: string }> {
	return new Promise((resolve, reject) => {
		const target = new URL(url);
		const req = request({
			hostname: target.hostname,
			port: target.port,
			path: target.pathname,
			headers: { Host: host },
		}, (response) => {
			let body = "";
			response.setEncoding("utf8");
			response.on("data", (chunk) => { body += chunk; });
			response.on("end", () => resolve({ status: response.statusCode ?? 0, body }));
		});
		req.on("error", reject);
		req.end();
	});
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
		const pageResponse = await fetch(running.url);
		const page = await pageResponse.text();
		const token = page.match(/name="opensec-token" content="([^"]+)"/)?.[1];
		expect(token).toBeTruthy();
		expect(pageResponse.headers.get("content-security-policy")).toContain("script-src 'self';");
		expect(pageResponse.headers.get("content-security-policy")).not.toContain("script-src 'self' 'unsafe-inline'");

		const denied = await fetch(new URL("/api/scans", running.url));
		expect(denied.status).toBe(403);

		const response = await fetch(new URL("/api/scans", running.url), {
			headers: { "X-OpenSec-Token": token as string },
		});
		expect(await response.json()).toMatchObject([
			{ version: 1, id: "scan-review", repo_name: "review-repo", finding_count: 1, open_count: 1, severity_counts: { high: 1 } },
		]);
		const detail = await (await fetch(new URL("/api/scans/scan-review", running.url), {
			headers: { "X-OpenSec-Token": token as string },
		})).json();
		expect(detail).toMatchObject({ version: 1, repo: { name: "review-repo" } });
		expect(detail.repo).not.toHaveProperty("path");
		expect(detail.scan).not.toHaveProperty("config");
		expect(detail).not.toHaveProperty("events");
		expect(detail.passCoverage).toMatchObject([{ pass: 1, completed: true }]);
		expect(detail.candidates[0]).toMatchObject({ status: "open", reviewable: true, needs_review: true });
	});

	it("rejects non-loopback Host values before serving the page token", async () => {
		const { db } = fixture();
		running = await startReviewServer({ db });
		const response = await getWithHost(running.url, "attacker.invalid");
		expect(response.status).toBe(421);
		expect(response.body).not.toContain("opensec-token");
	});

	it("keeps state changes and comments in finding history", async () => {
		const { db, scanId } = fixture();
		running = await startReviewServer({ db, scanId });
		const page = await (await fetch(running.url)).text();
		const token = page.match(/name="opensec-token" content="([^"]+)"/)?.[1] as string;
		const endpoint = new URL(`/api/scans/${scanId}/candidates/c1/review`, running.url);
		const response = await fetch(endpoint, {
			method: "POST",
			headers: { "Content-Type": "application/json", "X-OpenSec-Token": token, Origin: new URL(running.url).origin },
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

	it("rejects cross-origin, malformed, and oversized review requests", async () => {
		const { db, scanId } = fixture();
		running = await startReviewServer({ db });
		const page = await (await fetch(running.url)).text();
		const token = page.match(/name="opensec-token" content="([^"]+)"/)?.[1] as string;
		const endpoint = new URL(`/api/scans/${scanId}/candidates/c1/review`, running.url);
		const base = { method: "POST", headers: { "Content-Type": "application/json", "X-OpenSec-Token": token } };
		expect((await fetch(endpoint, { ...base, headers: { ...base.headers, Origin: "https://attacker.invalid" }, body: "{}" })).status).toBe(403);
		expect((await fetch(endpoint, { ...base, headers: { ...base.headers, Origin: new URL(running.url).origin }, body: "{" })).status).toBe(400);
		expect((await fetch(endpoint, { ...base, headers: { ...base.headers, Origin: new URL(running.url).origin }, body: JSON.stringify({ comment: "x".repeat(20_001) }) })).status).toBe(400);
	});

	it("does not allow writes until a scan completes", async () => {
		const { db, scanId } = fixture({ completed: false });
		running = await startReviewServer({ db });
		const page = await (await fetch(running.url)).text();
		const token = page.match(/name="opensec-token" content="([^"]+)"/)?.[1] as string;
		const response = await fetch(new URL(`/api/scans/${scanId}/candidates/c1/review`, running.url), {
			method: "POST",
			headers: { "Content-Type": "application/json", "X-OpenSec-Token": token, Origin: new URL(running.url).origin },
			body: JSON.stringify({ status: "suppressed" }),
		});
		expect(response.status).toBe(400);
		expect(await response.json()).toMatchObject({ error: "findings can only be reviewed after a scan finishes" });
	});

	it("labels partial runs and keeps their recorded findings reviewable", async () => {
		const { db, scanId } = fixture({ partial: true });
		running = await startReviewServer({ db });
		const page = await (await fetch(running.url)).text();
		const token = page.match(/name="opensec-token" content="([^"]+)"/)?.[1] as string;
		const headers = { "X-OpenSec-Token": token };
		const detail = await (await fetch(new URL(`/api/scans/${scanId}`, running.url), { headers })).json();
		expect(detail.scan.status).toBe("partial");
		expect(detail.passCoverage).toMatchObject([{ pass: 1, completed: false }]);

		const response = await fetch(new URL(`/api/scans/${scanId}/candidates/c1/review`, running.url), {
			method: "POST",
			headers: { ...headers, "Content-Type": "application/json", Origin: new URL(running.url).origin },
			body: JSON.stringify({ comment: "Useful finding from a partial run." }),
		});
		expect(response.status).toBe(200);
	});

	it("reports follow-up as remaining and a confirmed human decision as reviewed", async () => {
		const { db, scanId } = fixture();
		running = await startReviewServer({ db });
		const page = await (await fetch(running.url)).text();
		const token = page.match(/name="opensec-token" content="([^"]+)"/)?.[1] as string;
		const headers = { "Content-Type": "application/json", "X-OpenSec-Token": token, Origin: new URL(running.url).origin };
		const endpoint = new URL(`/api/scans/${scanId}/candidates/c1/review`, running.url);
		await fetch(endpoint, { method: "POST", headers, body: JSON.stringify({ status: "needs_follow_up" }) });
		let scans = await (await fetch(new URL("/api/scans", running.url), { headers: { "X-OpenSec-Token": token } })).json();
		expect(scans[0]).toMatchObject({ open_count: 1, reviewed_count: 0 });
		await fetch(endpoint, { method: "POST", headers, body: JSON.stringify({ status: "confirmed" }) });
		scans = await (await fetch(new URL("/api/scans", running.url), { headers: { "X-OpenSec-Token": token } })).json();
		expect(scans[0]).toMatchObject({ open_count: 0, reviewed_count: 1, severity_counts: { high: 1 } });
	});

	it("exports a self-contained read-only HTML snapshot", async () => {
		const { db, scanId } = fixture({
			title: "</script><script>alert(1)</script>",
			description: "Private finding details",
		});
		running = await startReviewServer({ db });
		const page = await (await fetch(running.url)).text();
		const token = page.match(/name="opensec-token" content="([^"]+)"/)?.[1] as string;
		const response = await fetch(new URL(`/api/scans/${scanId}/export?format=html`, running.url), {
			headers: { "X-OpenSec-Token": token },
		});
		const html = await response.text();
		expect(response.headers.get("content-disposition")).toContain("review-repo-scan-review.html");
		expect(html).toContain("window.__OPENSEC_SNAPSHOT__");
		expect(html).toContain("Private finding details");
		expect(html).not.toContain('href="/assets/styles.css"');
		expect(html).not.toContain("/tmp/review-repo");
		expect(html).not.toContain("</script><script>alert(1)</script>");
		expect(html).not.toContain("config_hash");
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

	it("does not let later agent activity overwrite a human decision", () => {
		const { db, scanId } = fixture();
		const ledger = Ledger.open(db);
		ledger.reviewCandidate({ scanId, candidateId: "c1", status: "suppressed" });
		ledger.addCandidateActivity({
			scanId,
			candidateId: "c1",
			workerId: "assessment-late",
			kind: "assessment",
			body: "Late agent result.",
			status: "confirmed",
			data: { disposition: "confirmed" },
		});
		expect(ledger.getCandidate(scanId, "c1")?.status).toBe("suppressed");
		ledger.close();
	});
});
