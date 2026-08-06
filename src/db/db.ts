/**
 * The ledger. One DB at ~/.opensec/opensec.db, one connection, one writer.
 *
 * Never hold a transaction across an LLM call (plan §6) — every write here is a
 * complete statement, and the agent tool calls into these functions one verb at
 * a time.
 */

import Database from "better-sqlite3";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import type {
	Candidate,
	Coverage,
	Lead,
	Location,
	Phase,
	Profile,
	Resolution,
	ScanFile,
	ScanRecord,
	ScanStatus,
} from "../types.js";

const SCHEMA_VERSION = 1;

const here = dirname(fileURLToPath(import.meta.url));

export function defaultDbPath(): string {
	return join(homedir(), ".opensec", "opensec.db");
}

export function scanArtifactDir(scanId: string): string {
	return join(homedir(), ".opensec", "scans", scanId);
}

export class Ledger {
	private constructor(private readonly db: Database.Database) {}

	static open(path?: string): Ledger {
		const file = path ?? defaultDbPath();
		mkdirSync(dirname(resolve(file)), { recursive: true });
		const db = new Database(file);
		db.pragma("journal_mode = WAL");
		db.pragma("foreign_keys = ON");
		const ledger = new Ledger(db);
		ledger.migrate();
		return ledger;
	}

	private migrate(): void {
		const schema = readFileSync(join(here, "schema.sql"), "utf8");
		this.db.exec(schema);
		const row = this.db
			.prepare("SELECT MAX(version) AS v FROM schema_version")
			.get() as { v: number | null };
		if (row.v === null) {
			this.db
				.prepare("INSERT INTO schema_version (version, applied_at) VALUES (?, ?)")
				.run(SCHEMA_VERSION, now());
		}
	}

	close(): void {
		this.db.close();
	}

	// ---------------------------------------------------------------- repos

	upsertRepo(path: string, name: string, remoteUrl: string | null): string {
		const id = shortHash(resolve(path));
		this.db
			.prepare(
				`INSERT INTO repos (id, path, name, remote_url, created_at) VALUES (?, ?, ?, ?, ?)
				 ON CONFLICT(path) DO UPDATE SET name = excluded.name, remote_url = excluded.remote_url`,
			)
			.run(id, resolve(path), name, remoteUrl, now());
		return id;
	}

	// ---------------------------------------------------------------- scans

	createScan(args: {
		id: string;
		repoId: string;
		revision: string | null;
		profile: Profile;
		configHash: string;
	}): void {
		this.db
			.prepare(
				`INSERT INTO scans (id, repo_id, revision, profile, status, phase, config_hash, started_at)
				 VALUES (?, ?, ?, ?, 'running', 'inventory', ?, ?)`,
			)
			.run(args.id, args.repoId, args.revision, args.profile, args.configHash, now());
	}

	setPhase(scanId: string, phase: Phase): void {
		this.db.prepare("UPDATE scans SET phase = ? WHERE id = ?").run(phase, scanId);
	}

	setThreatModel(scanId: string, text: string): void {
		this.db.prepare("UPDATE scans SET threat_model = ? WHERE id = ?").run(text, scanId);
	}

	getThreatModel(scanId: string): string | null {
		const row = this.db
			.prepare("SELECT threat_model FROM scans WHERE id = ?")
			.get(scanId) as { threat_model: string | null } | undefined;
		return row?.threat_model ?? null;
	}

	finishScan(scanId: string, status: ScanStatus): void {
		this.db
			.prepare("UPDATE scans SET status = ?, phase = 'report', completed_at = ? WHERE id = ?")
			.run(status, now(), scanId);
	}

	addUsage(scanId: string, tokensIn: number, tokensOut: number, costUsd: number): void {
		this.db
			.prepare(
				`UPDATE scans SET tokens_in = tokens_in + ?, tokens_out = tokens_out + ?,
				 cost_usd = cost_usd + ? WHERE id = ?`,
			)
			.run(tokensIn, tokensOut, costUsd, scanId);
	}

	getScan(scanId: string): ScanRecord | undefined {
		const row = this.db.prepare("SELECT * FROM scans WHERE id = ?").get(scanId) as
			| Record<string, unknown>
			| undefined;
		if (!row) return undefined;
		return {
			id: row.id as string,
			repo_id: row.repo_id as string,
			revision: row.revision as string | null,
			profile: row.profile as Profile,
			status: row.status as ScanStatus,
			phase: row.phase as Phase,
			config_hash: row.config_hash as string,
			started_at: row.started_at as string,
			completed_at: row.completed_at as string | null,
			tokens_in: row.tokens_in as number,
			tokens_out: row.tokens_out as number,
			cost_usd: row.cost_usd as number,
		};
	}

	// ---------------------------------------------------------------- files

	insertFiles(
		scanId: string,
		files: Array<{ path: string; sha: string; bytes: number; excludedReason: string | null }>,
	): void {
		const stmt = this.db.prepare(
			`INSERT OR REPLACE INTO files (scan_id, path, sha, bytes_total, excluded_reason)
			 VALUES (?, ?, ?, ?, ?)`,
		);
		const tx = this.db.transaction(() => {
			for (const f of files) stmt.run(scanId, f.path, f.sha, f.bytes, f.excludedReason);
		});
		tx();
	}

	/** The worklist query behind `work.next`. Excluded files never appear. */
	listWork(scanId: string, limit: number, cursor: number): { files: ScanFile[]; total: number } {
		const total = (
			this.db
				.prepare(
					"SELECT COUNT(*) AS n FROM files WHERE scan_id = ? AND excluded_reason IS NULL",
				)
				.get(scanId) as { n: number }
		).n;
		const rows = this.db
			.prepare(
				`SELECT path, sha, bytes_total, bytes_read, excluded_reason, first_touched_at
				 FROM files WHERE scan_id = ? AND excluded_reason IS NULL
				 ORDER BY path LIMIT ? OFFSET ?`,
			)
			.all(scanId, limit, cursor) as ScanFile[];
		return { files: rows, total };
	}

	fileInScope(scanId: string, path: string): boolean {
		const row = this.db
			.prepare(
				"SELECT 1 AS ok FROM files WHERE scan_id = ? AND path = ? AND excluded_reason IS NULL",
			)
			.get(scanId, path) as { ok: number } | undefined;
		return row !== undefined;
	}

	/**
	 * Record that a read/grep actually reached a file. Coverage is derived from
	 * this, never self-reported — an agent cannot mark work it never did.
	 */
	recordTouch(scanId: string, path: string, bytesRead: number): void {
		this.db
			.prepare(
				`UPDATE files SET bytes_read = MAX(bytes_read, ?),
				 first_touched_at = COALESCE(first_touched_at, ?)
				 WHERE scan_id = ? AND path = ?`,
			)
			.run(bytesRead, now(), scanId, path);
	}

	coverage(scanId: string): Coverage {
		const row = this.db
			.prepare(
				`SELECT COUNT(*) AS files_in_scope,
				        SUM(CASE WHEN first_touched_at IS NOT NULL THEN 1 ELSE 0 END) AS files_touched,
				        COALESCE(SUM(bytes_total), 0) AS bytes_in_scope,
				        COALESCE(SUM(MIN(bytes_read, bytes_total)), 0) AS bytes_read
				 FROM files WHERE scan_id = ? AND excluded_reason IS NULL`,
			)
			.get(scanId) as Record<string, number>;
		return {
			files_in_scope: row.files_in_scope ?? 0,
			files_touched: row.files_touched ?? 0,
			bytes_in_scope: row.bytes_in_scope ?? 0,
			bytes_read: row.bytes_read ?? 0,
		};
	}

	excludedCount(scanId: string): number {
		return (
			this.db
				.prepare(
					"SELECT COUNT(*) AS n FROM files WHERE scan_id = ? AND excluded_reason IS NOT NULL",
				)
				.get(scanId) as { n: number }
		).n;
	}

	// ----------------------------------------------------------- candidates

	nextCandidateId(scanId: string): string {
		const n = (
			this.db
				.prepare("SELECT COUNT(*) AS n FROM candidates WHERE scan_id = ?")
				.get(scanId) as { n: number }
		).n;
		return `c${n + 1}`;
	}

	createCandidate(c: {
		id: string;
		scanId: string;
		workerId: string;
		title: string;
		cweIds: string[];
		locations: Location[];
		summary: string;
		evidence: string;
	}): void {
		this.db
			.prepare(
				`INSERT INTO candidates
				 (id, scan_id, worker_id, title, cwe_ids, locations_json, summary, evidence, created_at)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			)
			.run(
				c.id,
				c.scanId,
				c.workerId,
				c.title,
				JSON.stringify(c.cweIds),
				JSON.stringify(c.locations),
				c.summary,
				c.evidence,
				now(),
			);
	}

	resolveCandidate(scanId: string, id: string, resolution: Resolution): void {
		this.db
			.prepare("UPDATE candidates SET resolution_json = ? WHERE scan_id = ? AND id = ?")
			.run(JSON.stringify(resolution), scanId, id);
		if (resolution.disposition === "duplicate" && resolution.duplicate_of) {
			this.db
				.prepare("UPDATE candidates SET merged_into = ? WHERE scan_id = ? AND id = ?")
				.run(resolution.duplicate_of, scanId, id);
		}
	}

	getCandidate(scanId: string, id: string): Candidate | undefined {
		const row = this.db
			.prepare("SELECT * FROM candidates WHERE scan_id = ? AND id = ?")
			.get(scanId, id) as Record<string, unknown> | undefined;
		return row ? rowToCandidate(row) : undefined;
	}

	listCandidates(scanId: string): Candidate[] {
		const rows = this.db
			.prepare("SELECT * FROM candidates WHERE scan_id = ? ORDER BY id")
			.all(scanId) as Array<Record<string, unknown>>;
		return rows.map(rowToCandidate);
	}

	listUnresolvedCandidates(scanId: string): Candidate[] {
		return this.listCandidates(scanId).filter((c) => !c.resolution);
	}

	// ---------------------------------------------------------------- leads

	recordLead(scanId: string, lead: Lead): void {
		this.db
			.prepare(
				"INSERT INTO leads (scan_id, worker_id, text, status, created_at) VALUES (?, ?, ?, ?, ?)",
			)
			.run(scanId, lead.worker_id, lead.text, lead.status, now());
	}

	listLeads(scanId: string): Lead[] {
		return this.db
			.prepare("SELECT worker_id, text, status FROM leads WHERE scan_id = ?")
			.all(scanId) as Lead[];
	}
}

function rowToCandidate(row: Record<string, unknown>): Candidate {
	return {
		id: row.id as string,
		scan_id: row.scan_id as string,
		worker_id: row.worker_id as string,
		title: row.title as string,
		cwe_ids: JSON.parse(row.cwe_ids as string) as string[],
		locations: JSON.parse(row.locations_json as string) as Location[],
		summary: row.summary as string,
		evidence: row.evidence as string,
		created_at: row.created_at as string,
		resolution: row.resolution_json
			? (JSON.parse(row.resolution_json as string) as Resolution)
			: undefined,
		merged_into: (row.merged_into as string | null) ?? null,
	};
}

export function now(): string {
	return new Date().toISOString();
}

export function shortHash(input: string): string {
	return createHash("sha256").update(input).digest("hex").slice(0, 12);
}
