import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Ledger } from "../db/db.js";
import { renderExport } from "../scan/export.js";
import { candidateComputed, type CandidateStatus } from "../types.js";

const assetsDir = join(dirname(fileURLToPath(import.meta.url)), "assets");
const statuses: CandidateStatus[] = [
	"open",
	"confirmed",
	"needs_follow_up",
	"suppressed",
	"not_applicable",
];

export interface ReviewServerOptions {
	db?: string;
	port?: number;
	scanId?: string;
}

export interface RunningReviewServer {
	server: Server;
	url: string;
	close(): Promise<void>;
}

export async function startReviewServer(options: ReviewServerOptions = {}): Promise<RunningReviewServer> {
	const ledger = Ledger.open(options.db);
	const token = randomBytes(24).toString("base64url");
	const server = createServer((request, response) => {
		handle(request, response, ledger, token).catch((error: unknown) => {
			if (!response.headersSent) json(response, 500, { error: (error as Error).message });
			else response.end();
		});
	});

	await new Promise<void>((resolve, reject) => {
		server.once("error", reject);
		server.listen(options.port ?? 0, "127.0.0.1", () => {
			server.off("error", reject);
			resolve();
		});
	});
	const address = server.address() as AddressInfo;
	const query = options.scanId ? `?scan=${encodeURIComponent(options.scanId)}` : "";
	const url = `http://127.0.0.1:${address.port}/${query}`;

	return {
		server,
		url,
		close: () => new Promise<void>((resolve, reject) => {
			server.close((error) => {
				ledger.close();
				if (error) reject(error);
				else resolve();
			});
		}),
	};
}

async function handle(
	request: IncomingMessage,
	response: ServerResponse,
	ledger: Ledger,
	token: string,
): Promise<void> {
	const url = new URL(request.url ?? "/", "http://localhost");
	securityHeaders(response);

	if (request.method === "GET" && url.pathname === "/") {
		const html = asset("index.html").replace("__OPENSEC_TOKEN__", token);
		return send(response, 200, html, "text/html; charset=utf-8");
	}
	if (request.method === "GET" && url.pathname === "/assets/styles.css") {
		return send(response, 200, asset("styles.css"), "text/css; charset=utf-8");
	}
	if (request.method === "GET" && url.pathname === "/assets/app.js") {
		return send(response, 200, asset("app.js"), "text/javascript; charset=utf-8");
	}
	if (url.pathname === "/favicon.ico") return send(response, 204, "", "image/x-icon");

	if (!url.pathname.startsWith("/api/")) return json(response, 404, { error: "not found" });
	if (request.headers["x-opensec-token"] !== token) return json(response, 403, { error: "invalid review token" });

	if (request.method === "GET" && url.pathname === "/api/scans") {
		return json(response, 200, reviewScans(ledger));
	}

	const parts = url.pathname.split("/").filter(Boolean).map(decodeURIComponent);
	const scanId = parts[2];
	if (!scanId || parts[0] !== "api" || parts[1] !== "scans") {
		return json(response, 404, { error: "not found" });
	}

	if (request.method === "GET" && parts.length === 3) {
		const detail = scanDetail(ledger, scanId);
		return detail ? json(response, 200, detail) : json(response, 404, { error: `no scan '${scanId}'` });
	}

	if (request.method === "GET" && parts[3] === "export" && parts.length === 4) {
		const detail = scanDetail(ledger, scanId);
		if (!detail) return json(response, 404, { error: `no scan '${scanId}'` });
		const format = url.searchParams.get("format");
		if (format === "html") {
			const html = renderSnapshot(detail);
			return download(response, html, `${safeName(detail.repo.name)}-${scanId}.html`, "text/html; charset=utf-8");
		}
		if (format !== "json" && format !== "csv" && format !== "sarif") {
			return json(response, 400, { error: "format must be html, json, csv, or sarif" });
		}
		const body = renderExport({ scan: detail.scan, coverage: detail.coverage, candidates: detail.candidates }, format);
		const mime = format === "csv" ? "text/csv; charset=utf-8" : "application/json; charset=utf-8";
		return download(response, body, `${safeName(detail.repo.name)}-${scanId}.${format}`, mime);
	}

	if (request.method === "POST" && parts[3] === "candidates" && parts[5] === "review" && parts.length === 6) {
		const candidateId = parts[4];
		if (!candidateId) return json(response, 400, { error: "finding id is required" });
		const body = await readJson(request);
		const status = body.status;
		const comment = body.comment;
		if (status !== undefined && !statuses.includes(status as CandidateStatus)) {
			return json(response, 400, { error: `unknown state '${String(status)}'` });
		}
		if (comment !== undefined && typeof comment !== "string") {
			return json(response, 400, { error: "comment must be text" });
		}
		if (typeof comment === "string" && comment.length > 10_000) {
			return json(response, 400, { error: "comment is longer than 10,000 characters" });
		}
		try {
			const candidate = ledger.reviewCandidate({
				scanId,
				candidateId,
				status: status as CandidateStatus | undefined,
				comment: comment as string | undefined,
			});
			return json(response, 200, candidate);
		} catch (error) {
			return json(response, 400, { error: (error as Error).message });
		}
	}

	return json(response, 404, { error: "not found" });
}

function reviewScans(ledger: Ledger) {
	return ledger.listScans(100).map((scan) => {
		const candidates = ledger.listCandidates(scan.id);
		const full = ledger.getScan(scan.id);
		const coverage = ledger.coverage(scan.id);
		const reviewable = candidates.filter(isReviewable);
		const reviewed = reviewable.filter(isHumanReviewed);
		const severityCounts = Object.fromEntries(
			["critical", "high", "medium", "low", "info"].map((severity) => [
				severity,
				reviewable.filter((candidate) => candidateComputed(candidate)?.severity === severity).length,
			]),
		);
		return {
			...scan,
			completed_at: full?.completed_at ?? null,
			revision: full?.revision ?? null,
			finding_count: candidates.length,
			open_count: reviewable.length - reviewed.length,
			reviewed_count: reviewed.length,
			reviewable_count: reviewable.length,
			duplicate_count: candidates.filter((candidate) => candidate.status === "duplicate").length,
			severity_counts: severityCounts,
			coverage_percent: coverage.bytes_in_scope
				? Math.round((coverage.bytes_read / coverage.bytes_in_scope) * 100)
				: 0,
		};
	});
}

function isReviewable(candidate: ReturnType<Ledger["listCandidates"]>[number]): boolean {
	const assessed = candidate.activities.findLast(
		(activity) =>
			(activity.kind === "assessment" || activity.kind === "validation") &&
			activity.data?.disposition !== undefined,
	)?.data?.disposition;
	return candidate.duplicate_of == null &&
		(assessed ?? candidate.status) === "confirmed" &&
		candidateComputed(candidate)?.reportable !== false;
}

function isHumanReviewed(candidate: ReturnType<Ledger["listCandidates"]>[number]): boolean {
	return candidate.activities.some((activity) => activity.kind === "review");
}

function scanDetail(ledger: Ledger, scanId: string) {
	const scan = ledger.getScan(scanId);
	if (!scan) return undefined;
	const repo = ledger.getRepo(scan.repo_id);
	if (!repo) return undefined;
	const candidates = ledger.listCandidates(scanId).map((candidate) => ({
		...candidate,
		computed: candidateComputed(candidate) ?? null,
	}));
	return {
		scan,
		repo,
		coverage: ledger.coverage(scanId),
		passCoverage: ledger.passCoverage(scanId, scan.passes ?? 1),
		threatModel: ledger.getThreatModel(scanId),
		candidates,
		events: ledger.listEvents(scanId, 50),
	};
}

function renderSnapshot(detail: NonNullable<ReturnType<typeof scanDetail>>): string {
	const shareable = {
		...detail,
		repo: { ...detail.repo, path: detail.repo.name },
		scan: { ...detail.scan, config: null },
		events: detail.events.map((event) => ({ ...event, detail_json: null })),
	};
	const snapshot = JSON.stringify(shareable).replaceAll("<", "\\u003c");
	return asset("index.html")
		.replace('<link rel="stylesheet" href="/assets/styles.css">', `<style>${asset("styles.css")}</style>`)
		.replace('<meta name="opensec-token" content="__OPENSEC_TOKEN__">', "")
		.replace('<script src="/assets/app.js" defer></script>', `<script>window.__OPENSEC_SNAPSHOT__=${snapshot};</script><script>${asset("app.js")}</script>`);
}

function asset(name: string): string {
	return readFileSync(join(assetsDir, name), "utf8");
}

async function readJson(request: IncomingMessage): Promise<Record<string, unknown>> {
	if (!request.headers["content-type"]?.startsWith("application/json")) throw new Error("content-type must be application/json");
	let body = "";
	for await (const chunk of request) {
		body += chunk;
		if (body.length > 20_000) throw new Error("request is too large");
	}
	return JSON.parse(body) as Record<string, unknown>;
}

function securityHeaders(response: ServerResponse): void {
	response.setHeader("Cache-Control", "no-store");
	response.setHeader("X-Content-Type-Options", "nosniff");
	response.setHeader("Referrer-Policy", "no-referrer");
	response.setHeader("X-Frame-Options", "DENY");
	response.setHeader(
		"Content-Security-Policy",
		"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
	);
}

function send(response: ServerResponse, status: number, body: string, contentType: string): void {
	response.writeHead(status, { "Content-Type": contentType, "Content-Length": Buffer.byteLength(body) });
	response.end(body);
}

function json(response: ServerResponse, status: number, value: unknown): void {
	send(response, status, `${JSON.stringify(value)}\n`, "application/json; charset=utf-8");
}

function download(response: ServerResponse, body: string, filename: string, contentType: string): void {
	response.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
	send(response, 200, body, contentType);
}

function safeName(value: string): string {
	return value.replace(/[^a-zA-Z0-9._-]+/g, "-").replace(/^-|-$/g, "") || "opensec";
}
