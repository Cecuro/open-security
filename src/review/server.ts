import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Ledger } from "../db/db.js";
import { renderExport } from "../scan/export.js";
import {
	candidateComputed,
	type Candidate,
	type CandidateActivity,
	type CandidateStatus,
	type Coverage,
	type PassCoverage,
	type ScanRecord,
} from "../types.js";

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

interface ReviewCandidateV1 {
	id: string;
	worker_id: string;
	title: string;
	cwe_ids: string[];
	locations: Candidate["locations"];
	description: string;
	status: CandidateStatus;
	created_at: string;
	activities: Array<Pick<CandidateActivity, "id" | "worker_id" | "kind" | "body" | "at">>;
	duplicate_of: string | null;
	computed: ReturnType<typeof candidateComputed> | null;
	reviewable: boolean;
	needs_review: boolean;
}

interface ReviewRunSummaryV1 {
	version: 1;
	id: string;
	repo_name: string;
	status: ScanRecord["status"];
	phase: ScanRecord["phase"];
	started_at: string;
	completed_at: string | null;
	revision: string | null;
	cost_usd: number;
	finding_count: number;
	open_count: number;
	reviewed_count: number;
	reviewable_count: number;
	duplicate_count: number;
	severity_counts: Record<string, number>;
	coverage_percent: number;
}

interface ReviewDetailV1 {
	version: 1;
	scan: Pick<ScanRecord, "id" | "revision" | "status" | "phase" | "model_ref" | "started_at" | "completed_at" | "cost_usd">;
	repo: { name: string };
	coverage: Coverage;
	passCoverage: PassCoverage[];
	threatModel: string | null;
	candidates: ReviewCandidateV1[];
}

export async function startReviewServer(options: ReviewServerOptions = {}): Promise<RunningReviewServer> {
	const ledger = Ledger.open(options.db);
	const token = randomBytes(24).toString("base64url");
	let origin: string | undefined;
	let ledgerClosed = false;
	let closePromise: Promise<void> | undefined;
	const closeLedger = () => {
		if (ledgerClosed) return;
		ledgerClosed = true;
		ledger.close();
	};
	const server = createServer((request, response) => {
		if (!origin) return json(response, 503, { error: "review server is starting" });
		handle(request, response, ledger, token, origin).catch((error: unknown) => {
			if (!response.headersSent) json(response, 500, { error: (error as Error).message });
			else response.end();
		});
	});

	try {
		await new Promise<void>((resolve, reject) => {
			server.once("error", reject);
			server.listen(options.port ?? 0, "127.0.0.1", () => {
				server.off("error", reject);
				resolve();
			});
		});
	} catch (error) {
		closeLedger();
		throw error;
	}
	const address = server.address() as AddressInfo;
	const query = options.scanId ? `?scan=${encodeURIComponent(options.scanId)}` : "";
	origin = `http://127.0.0.1:${address.port}`;
	const url = `${origin}/${query}`;

	return {
		server,
		url,
		close: () => {
			if (closePromise) return closePromise;
			closePromise = new Promise<void>((resolve, reject) => {
				if (!server.listening) {
					closeLedger();
					return resolve();
				}
				server.close((error) => {
					closeLedger();
					if (error) reject(error);
					else resolve();
				});
			});
			return closePromise;
		},
	};
}

async function handle(
	request: IncomingMessage,
	response: ServerResponse,
	ledger: Ledger,
	token: string,
	origin: string,
): Promise<void> {
	const url = new URL(request.url ?? "/", "http://localhost");
	securityHeaders(response);
	if (request.headers.host !== new URL(origin).host) {
		return json(response, 421, { error: "invalid review host" });
	}

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
		const scan = ledger.getScan(scanId);
		if (!scan) return json(response, 404, { error: `no scan '${scanId}'` });
		const body = renderExport({ scan, coverage: detail.coverage, candidates: ledger.listCandidates(scanId) }, format);
		const mime = format === "csv" ? "text/csv; charset=utf-8" : "application/json; charset=utf-8";
		return download(response, body, `${safeName(detail.repo.name)}-${scanId}.${format}`, mime);
	}

	if (request.method === "POST" && parts[3] === "candidates" && parts[5] === "review" && parts.length === 6) {
		if (request.headers.origin !== origin) return json(response, 403, { error: "invalid review origin" });
		const candidateId = parts[4];
		if (!candidateId) return json(response, 400, { error: "finding id is required" });
		let body: Record<string, unknown>;
		try {
			body = await readJson(request);
		} catch (error) {
			return json(response, 400, { error: (error as Error).message });
		}
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
			return json(response, 200, toReviewCandidate(candidate));
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
		return runSummary(scan, full, coverage, candidates.map(toReviewCandidate));
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

function toReviewCandidate(candidate: Candidate): ReviewCandidateV1 {
	const reviewable = isReviewable(candidate);
	const reviewed = candidate.activities.some((activity) => activity.kind === "review");
	const status = reviewable && !reviewed ? "open" : candidate.status;
	return {
		id: candidate.id,
		worker_id: candidate.worker_id,
		title: candidate.title,
		cwe_ids: candidate.cwe_ids,
		locations: candidate.locations,
		description: candidate.description,
		status,
		created_at: candidate.created_at,
		activities: candidate.activities.map(({ id, worker_id, kind, body, at }) => ({ id, worker_id, kind, body, at })),
		duplicate_of: candidate.duplicate_of ?? null,
		computed: candidateComputed(candidate) ?? null,
		reviewable,
		needs_review: reviewable && (!reviewed || status === "open" || status === "needs_follow_up"),
	};
}

function runSummary(
	scan: Pick<ScanRecord, "id" | "status" | "phase" | "started_at" | "cost_usd"> & { repo_name: string },
	full: ScanRecord | undefined,
	coverage: Coverage,
	candidates: ReviewCandidateV1[],
): ReviewRunSummaryV1 {
	const reviewable = candidates.filter((candidate) => candidate.reviewable);
	const remaining = reviewable.filter((candidate) => candidate.needs_review).length;
	const active = reviewable.filter(
		(candidate) => candidate.status !== "suppressed" && candidate.status !== "not_applicable",
	);
	const severityCounts = Object.fromEntries(
		["critical", "high", "medium", "low", "info"].map((severity) => [
			severity,
			active.filter((candidate) => candidate.computed?.severity === severity).length,
		]),
	);
	return {
		version: 1,
		id: scan.id,
		repo_name: scan.repo_name,
		status: scan.status,
		phase: scan.phase,
		started_at: scan.started_at,
		completed_at: full?.completed_at ?? null,
		revision: full?.revision ?? null,
		cost_usd: scan.cost_usd,
		finding_count: candidates.length,
		open_count: remaining,
		reviewed_count: reviewable.length - remaining,
		reviewable_count: reviewable.length,
		duplicate_count: candidates.filter((candidate) => candidate.status === "duplicate").length,
		severity_counts: severityCounts,
		coverage_percent: coverage.bytes_in_scope
			? Math.round((coverage.bytes_read / coverage.bytes_in_scope) * 100)
			: 0,
	};
}

function scanDetail(ledger: Ledger, scanId: string): ReviewDetailV1 | undefined {
	const scan = ledger.getScan(scanId);
	if (!scan) return undefined;
	const repo = ledger.getRepo(scan.repo_id);
	if (!repo) return undefined;
	const candidates = ledger.listCandidates(scanId).map(toReviewCandidate);
	return {
		version: 1,
		scan: {
			id: scan.id,
			revision: scan.revision,
			status: scan.status,
			phase: scan.phase,
			model_ref: scan.model_ref,
			started_at: scan.started_at,
			completed_at: scan.completed_at,
			cost_usd: scan.cost_usd,
		},
		repo: { name: repo.name },
		coverage: ledger.coverage(scanId),
		passCoverage: ledger.passCoverage(scanId, Math.max(1, scan.passes ?? 1)),
		threatModel: ledger.getThreatModel(scanId),
		candidates,
	};
}

function renderSnapshot(detail: NonNullable<ReturnType<typeof scanDetail>>): string {
	const snapshot = JSON.stringify(detail).replaceAll("<", "\\u003c");
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
	const declared = Number(request.headers["content-length"] ?? 0);
	if (Number.isFinite(declared) && declared > 20_000) throw new Error("request is too large");
	let body = "";
	let bytes = 0;
	for await (const chunk of request) {
		bytes += Buffer.byteLength(chunk);
		if (bytes > 20_000) throw new Error("request is too large");
		body += chunk;
	}
	const parsed: unknown = JSON.parse(body);
	if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
		throw new Error("request body must be a JSON object");
	}
	return parsed as Record<string, unknown>;
}

function securityHeaders(response: ServerResponse): void {
	response.setHeader("Cache-Control", "no-store");
	response.setHeader("X-Content-Type-Options", "nosniff");
	response.setHeader("Referrer-Policy", "no-referrer");
	response.setHeader("X-Frame-Options", "DENY");
	response.setHeader(
		"Content-Security-Policy",
		"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
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
