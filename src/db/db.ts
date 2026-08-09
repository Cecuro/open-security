import Database from "better-sqlite3";
import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { identityHash, mergeLocations, mergeProse } from "../scan/identity.js";
import type {
	Candidate,
	Coverage,
	Lead,
	Location,
	Phase,
	Profile,
	Resolution,
	ScanScope,
	ScanFile,
	ScanRecord,
	ScanStatus,
	WorkerCoverage,
} from "../types.js";
import { MIGRATIONS, SCHEMA_VERSION } from "./migrations.js";

const here = dirname(fileURLToPath(import.meta.url));

export function defaultDbPath(): string {
	return join(homedir(), ".opensec", "opensec.db");
}

export function scanArtifactDir(scanId: string): string {
	return join(homedir(), ".opensec", "scans", scanId);
}

export function opensecDir(...segments: string[]): string {
	const root = join(homedir(), ".opensec");
	mkdirSync(root, { recursive: true, mode: 0o700 });
	try {
		chmodSync(root, 0o700);
	} catch {
	}
	if (segments.length === 0) return root;
	const dir = join(root, ...segments);
	mkdirSync(dir, { recursive: true, mode: 0o700 });
	return dir;
}

export class Ledger {
	private constructor(private readonly db: Database.Database) {}

	static open(path?: string): Ledger {
		const file = path ?? defaultDbPath();
		if (path === undefined) opensecDir();
		else mkdirSync(dirname(resolve(file)), { recursive: true });
		const db = new Database(file);
		db.pragma("journal_mode = WAL");
		db.pragma("foreign_keys = ON");
		const ledger = new Ledger(db);
		ledger.migrate();
		return ledger;
	}

	private migrate(): void {
		this.db.exec(readFileSync(join(here, "schema.sql"), "utf8"));

		const stamp = this.db.prepare("INSERT INTO schema_version (version, applied_at) VALUES (?, ?)");
		const current = () =>
			(this.db.prepare("SELECT MAX(version) AS v FROM schema_version").get() as {
				v: number | null;
			}).v;

		let at = current();
		if (at === null) {
			stamp.run(1, now());
			at = 1;
		}

		if (at > SCHEMA_VERSION) {
			throw new Error(
				`this database is at schema version ${at}, but this opensec understands ${SCHEMA_VERSION}. ` +
					`Upgrade opensec, or point --db at a different file.`,
			);
		}

		for (const m of MIGRATIONS) {
			if (m.version <= at) continue;
			try {
				this.db.transaction(() => {
					this.db.exec(m.sql);
					stamp.run(m.version, now());
				})();
			} catch (err) {
				throw new Error(
					`schema migration ${m.version} (${m.note}) failed: ${(err as Error).message}`,
				);
			}
		}
	}

	close(): void {
		this.db.close();
	}

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

	createScan(args: {
		id: string;
		repoId: string;
		revision: string | null;
		profile: Profile;
		configHash: string;
		modelRef?: string;
		promptHash?: string;
		probes?: number;
		scope?: ScanScope;
	}): void {
		this.db
			.prepare(
				`INSERT INTO scans (id, repo_id, revision, profile, status, phase, config_hash,
				 model_ref, prompt_hash, probes, scope_kind, scope_base, started_at)
				 VALUES (?, ?, ?, ?, 'running', 'inventory', ?, ?, ?, ?, ?, ?, ?)`,
			)
			.run(
				args.id,
				args.repoId,
				args.revision,
				args.profile,
				args.configHash,
				args.modelRef ?? null,
				args.promptHash ?? null,
				args.probes ?? null,
				args.scope?.kind ?? "repository",
				args.scope?.kind === "diff" ? args.scope.base : null,
				now(),
			);
	}

	getRepo(id: string): { id: string; path: string; name: string } | undefined {
		return this.db.prepare("SELECT id, path, name FROM repos WHERE id = ?").get(id) as
			| { id: string; path: string; name: string }
			| undefined;
	}

	listScans(limit = 20): Array<{
		id: string;
		repo_name: string;
		status: ScanStatus;
		phase: Phase;
		started_at: string;
		cost_usd: number;
	}> {
		return this.db
			.prepare(
				`SELECT s.id, r.name AS repo_name, s.status, s.phase, s.started_at, s.cost_usd
				 FROM scans s JOIN repos r ON r.id = s.repo_id
				 ORDER BY s.started_at DESC LIMIT ?`,
			)
			.all(limit) as Array<{
			id: string;
			repo_name: string;
			status: ScanStatus;
			phase: Phase;
			started_at: string;
			cost_usd: number;
		}>;
	}

	/** Put a failed or interrupted scan back into 'running' so it can be resumed. */
	reopenScan(scanId: string): void {
		this.db
			.prepare("UPDATE scans SET status = 'running', completed_at = NULL WHERE id = ?")
			.run(scanId);
	}

	setPhase(scanId: string, phase: Phase): void {
		this.db.prepare("UPDATE scans SET phase = ? WHERE id = ?").run(phase, scanId);
	}

	setThreatModel(scanId: string, text: string, source: string): void {
		this.db
			.prepare("UPDATE scans SET threat_model = ?, threat_model_source = ? WHERE id = ?")
			.run(text, source, scanId);
	}

	getThreatModel(scanId: string): string | null {
		const row = this.db
			.prepare("SELECT threat_model FROM scans WHERE id = ?")
			.get(scanId) as { threat_model: string | null } | undefined;
		return row?.threat_model ?? null;
	}

	finishScan(scanId: string, status: ScanStatus): void {
		if (status === "completed") {
			this.db
				.prepare("UPDATE scans SET status = ?, phase = 'report', completed_at = ? WHERE id = ?")
				.run(status, now(), scanId);
		} else {
			this.db
				.prepare("UPDATE scans SET status = ?, completed_at = ? WHERE id = ?")
				.run(status, now(), scanId);
		}
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
			model_ref: (row.model_ref as string | null) ?? null,
			prompt_hash: (row.prompt_hash as string | null) ?? null,
			probes: (row.probes as number | null) ?? null,
			threat_model_source: (row.threat_model_source as string | null) ?? null,
			scope_kind: (row.scope_kind as ScanRecord["scope_kind"]) ?? null,
			scope_base: (row.scope_base as string | null) ?? null,
			started_at: row.started_at as string,
			completed_at: row.completed_at as string | null,
			tokens_in: row.tokens_in as number,
			tokens_out: row.tokens_out as number,
			cost_usd: row.cost_usd as number,
		};
	}

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

	/**
	 * The worklist: in-scope files that have not been read through.
	 *
	 * There is no cursor, because a cursor is a way to page past work you did
	 * not do — which is what a probe handed 427 files did, reaching the end of
	 * the list having read a fifth of it. A file leaves this list by being read,
	 * or not at all.
	 *
	 * `bytes_read < bytes_total`, not `bytes_read = 0`: pi truncates a read at
	 * 50KB, so one whole-file read of a 190KB file sees a quarter of it. Under
	 * the weaker test that file was done, and the tail of every large file in
	 * the repository went unreviewed — which is where the findings that need
	 * following a function to its end happen to live.
	 *
	 * `bytes_read`, not `first_touched_at`: a grep marks a file touched without
	 * reading it, and one repo-wide grep would otherwise empty the worklist for
	 * free. Searched is not reviewed.
	 */
	listWork(
		scanId: string,
		limit: number,
		worklist?: readonly string[],
		readGroup?: string,
	): { files: ScanFile[]; unread: number } {
		// The partition arrives as the paths themselves rather than a column on
		// files. It is derived per run and never read back, so persisting it would
		// be a second bookkeeping path that only exists to drift.
		if (worklist && worklist.length === 0) return { files: [], unread: 0 };
		const scope = worklist ? ` AND f.path IN (${worklist.map(() => "?").join(",")})` : "";
		const paths = worklist ? [...worklist] : [];

		// Two shapes rather than one with a conditional expression spliced into it.
		// The clever version put the read-group placeholder in the SELECT list and
		// the scan id in the WHERE, and the arguments went in the other order — so
		// every probe got an empty worklist, filed nothing, and the scan reported
		// itself clean. Parameter order is not worth being clever about.
		if (readGroup === undefined) {
			const unread = (
				this.db
					.prepare(
						`SELECT COUNT(*) AS n FROM files f
						 WHERE f.scan_id = ? AND f.excluded_reason IS NULL
						 AND f.bytes_read < f.bytes_total${scope}`,
					)
					.get(scanId, ...paths) as { n: number }
			).n;
			const files = this.db
				.prepare(
					`SELECT f.path, f.sha, f.bytes_total, f.bytes_read, f.excluded_reason,
					        f.first_touched_at
					 FROM files f WHERE f.scan_id = ? AND f.excluded_reason IS NULL
					 AND f.bytes_read < f.bytes_total${scope}
					 ORDER BY f.path LIMIT ?`,
				)
				.all(scanId, ...paths, limit) as ScanFile[];
			return { files, unread };
		}

		// "Read" means read by this pass. Without that, a second pass opens on an
		// empty worklist and its silence reads as agreement with the first.
		const join = `LEFT JOIN file_reads r
			 ON r.scan_id = f.scan_id AND r.path = f.path AND r.read_group = ?`;
		const unread = (
			this.db
				.prepare(
					`SELECT COUNT(*) AS n FROM files f ${join}
					 WHERE f.scan_id = ? AND f.excluded_reason IS NULL
					 AND COALESCE(r.bytes_read, 0) < f.bytes_total${scope}`,
				)
				.get(readGroup, scanId, ...paths) as { n: number }
		).n;
		const files = this.db
			.prepare(
				`SELECT f.path, f.sha, f.bytes_total, COALESCE(r.bytes_read, 0) AS bytes_read,
				        f.excluded_reason, f.first_touched_at
				 FROM files f ${join}
				 WHERE f.scan_id = ? AND f.excluded_reason IS NULL
				 AND COALESCE(r.bytes_read, 0) < f.bytes_total${scope}
				 ORDER BY f.path LIMIT ?`,
			)
			.all(readGroup, scanId, ...paths, limit) as ScanFile[];
		return { files, unread };
	}

	/** Whether inventory ran at all for this scan, excluded files included. */
	hasFiles(scanId: string): boolean {
		return (
			this.db.prepare("SELECT 1 AS ok FROM files WHERE scan_id = ? LIMIT 1").get(scanId) !==
			undefined
		);
	}

	listInScopePaths(scanId: string): string[] {
		const rows = this.db
			.prepare(
				"SELECT path FROM files WHERE scan_id = ? AND excluded_reason IS NULL ORDER BY path",
			)
			.all(scanId) as Array<{ path: string }>;
		return rows.map((r) => r.path);
	}

	/**
	 * In scope, and — when the caller owns a slice — inside it. Ownership is what
	 * ties a finding to the probe that filed it.
	 */
	fileInScope(scanId: string, path: string, worklist?: readonly string[]): boolean {
		if (worklist && !worklist.includes(path)) return false;
		const row = this.db
			.prepare(
				"SELECT 1 AS ok FROM files WHERE scan_id = ? AND path = ? AND excluded_reason IS NULL",
			)
			.get(scanId, path) as { ok: number } | undefined;
		return row !== undefined;
	}

	/**
	 * `continued` is a read that carried an offset — the agent asking for more of
	 * a file it has already seen part of. Those add up; everything else is a
	 * high-water mark.
	 *
	 * The distinction exists because pi truncates a read at 50KB. Under plain
	 * MAX, a 190KB file reads once, records 51,200, and can never record more no
	 * matter how much of it is paged through — so coverage silently ceilings at
	 * 50KB per file and the worklist calls the file done. That is how a probe
	 * reached 100% of files while the tail of every large one went unread, which
	 * is exactly where the deep findings live.
	 *
	 * Adding only offset reads keeps the accounting honest in the direction that
	 * matters: re-reading a file from the top cannot inflate it, because that is
	 * the read with no offset.
	 */
	recordTouch(
		scanId: string,
		path: string,
		bytesRead: number,
		continued = false,
		readGroup?: string,
		workerId?: string,
	): void {
		// files.bytes_read stays the union across every pass, because coverage is a
		// claim about the scan. file_reads is what each pass has seen on its own.
		this.db
			.prepare(
				continued
					? `UPDATE files SET bytes_read = MIN(bytes_total, bytes_read + ?),
					   first_touched_at = COALESCE(first_touched_at, ?)
					   WHERE scan_id = ? AND path = ?`
					: `UPDATE files SET bytes_read = MAX(bytes_read, ?),
					   first_touched_at = COALESCE(first_touched_at, ?)
					   WHERE scan_id = ? AND path = ?`,
			)
			.run(bytesRead, now(), scanId, path);

		if (readGroup !== undefined) {
			this.db
				.prepare(
					`INSERT INTO file_reads (scan_id, read_group, path, bytes_read) VALUES (?, ?, ?, ?)
					 ON CONFLICT(scan_id, read_group, path) DO UPDATE SET
					   bytes_read = ${continued ? "file_reads.bytes_read + excluded.bytes_read" : "MAX(file_reads.bytes_read, excluded.bytes_read)"}`,
				)
				.run(scanId, readGroup, path, bytesRead);
		}
		if (workerId !== undefined) {
			this.db
				.prepare(
					`INSERT INTO worker_file_reads (scan_id, worker_id, path, bytes_read) VALUES (?, ?, ?, ?)
					 ON CONFLICT(scan_id, worker_id, path) DO UPDATE SET
					   bytes_read = ${continued ? "worker_file_reads.bytes_read + excluded.bytes_read" : "MAX(worker_file_reads.bytes_read, excluded.bytes_read)"}`,
				)
				.run(scanId, workerId, path, bytesRead);
		}
	}

	beginWorkerWork(scanId: string, workerId: string, paths: readonly string[]): void {
		const files = paths.length;
		const bytes = paths.reduce((sum, path) => {
			const row = this.db
				.prepare("SELECT bytes_total FROM files WHERE scan_id = ? AND path = ?")
				.get(scanId, path) as { bytes_total: number } | undefined;
			return sum + (row?.bytes_total ?? 0);
		}, 0);
		this.db
			.prepare(
				`INSERT OR IGNORE INTO worker_work (scan_id, worker_id, files_assigned, bytes_assigned)
				 VALUES (?, ?, ?, ?)`,
			)
			.run(scanId, workerId, files, bytes);
	}

	completeWorkerWork(
		scanId: string,
		workerId: string,
		worklist: readonly string[],
		readGroup: string | undefined,
		summary: string,
	): void {
		const { unread } = this.listWork(scanId, 1, worklist, readGroup);
		if (unread !== 0) throw new Error(`work is not complete: ${unread} file(s) still need reading`);
		const row = this.db
			.prepare("SELECT completed_at FROM worker_work WHERE scan_id = ? AND worker_id = ?")
			.get(scanId, workerId) as { completed_at: string | null } | undefined;
		if (!row) throw new Error("worker was not registered for this worklist");
		if (row.completed_at) throw new Error("work.complete was already recorded");
		this.db
			.prepare("UPDATE worker_work SET summary = ?, completed_at = ? WHERE scan_id = ? AND worker_id = ?")
			.run(summary, now(), scanId, workerId);
	}

	workerCoverage(scanId: string): WorkerCoverage[] {
		return this.db
			.prepare(
				`SELECT w.worker_id, w.files_assigned, w.bytes_assigned, w.summary, w.completed_at,
				 COUNT(r.path) AS files_touched, COALESCE(SUM(MIN(r.bytes_read, f.bytes_total)), 0) AS bytes_read
				 FROM worker_work w
				 LEFT JOIN worker_file_reads r ON r.scan_id = w.scan_id AND r.worker_id = w.worker_id
				 LEFT JOIN files f ON f.scan_id = r.scan_id AND f.path = r.path
				 WHERE w.scan_id = ? GROUP BY w.worker_id ORDER BY w.worker_id`,
			)
			.all(scanId)
			.map((row) => {
				const r = row as Record<string, string | number | null>;
				return {
					worker_id: r.worker_id as string,
					files_assigned: r.files_assigned as number,
					files_in_scope: r.files_assigned as number,
					files_touched: r.files_touched as number,
					bytes_assigned: r.bytes_assigned as number,
					bytes_in_scope: r.bytes_assigned as number,
					bytes_read: r.bytes_read as number,
					completed: r.completed_at !== null,
					...(r.summary ? { summary: r.summary as string } : {}),
				};
			});
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

	nextCandidateId(scanId: string): string {
		const n = (
			this.db
				.prepare("SELECT COUNT(*) AS n FROM candidates WHERE scan_id = ?")
				.get(scanId) as { n: number }
		).n;
		return `c${n + 1}`;
	}

	upsertCandidate(c: {
		scanId: string;
		workerId: string;
		title: string;
		cweIds: string[];
		locations: Location[];
		summary: string;
		evidence: string;
		instance?: string | null;
	}): { id: string; merged: boolean } {
		const hash = identityHash({
			cweIds: c.cweIds,
			locations: c.locations,
			instance: c.instance,
		});

		const existing = this.db
			.prepare(
				"SELECT * FROM candidates WHERE scan_id = ? AND identity_hash = ? AND merged_into IS NULL",
			)
			.get(c.scanId, hash) as Record<string, unknown> | undefined;

		if (existing) {
			const prev = rowToCandidate(existing);
			this.db
				.prepare(
					`UPDATE candidates SET cwe_ids = ?, locations_json = ?, summary = ?, evidence = ?
					 WHERE scan_id = ? AND id = ?`,
				)
				.run(
					JSON.stringify([...new Set([...prev.cwe_ids, ...c.cweIds])]),
					JSON.stringify(mergeLocations(prev.locations, c.locations)),
					mergeProse(prev.summary, c.summary),
					mergeProse(prev.evidence, c.evidence),
					c.scanId,
					prev.id,
				);
			return { id: prev.id, merged: true };
		}

		const id = this.nextCandidateId(c.scanId);
		this.db
			.prepare(
				`INSERT INTO candidates
				 (id, scan_id, worker_id, title, cwe_ids, locations_json, summary, evidence,
				  instance, identity_hash, created_at)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			)
			.run(
				id,
				c.scanId,
				c.workerId,
				c.title,
				JSON.stringify(c.cweIds),
				JSON.stringify(c.locations),
				c.summary,
				c.evidence,
				c.instance ?? null,
				hash,
				now(),
			);
		return { id, merged: false };
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
			.prepare(
				"SELECT * FROM candidates WHERE scan_id = ? ORDER BY CAST(SUBSTR(id, 2) AS INTEGER), id")
			.all(scanId) as Array<Record<string, unknown>>;
		return rows.map(rowToCandidate);
	}

	listLiveCandidates(scanId: string): Candidate[] {
		return this.listCandidates(scanId).filter((c) => !c.merged_into);
	}

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
		instance: (row.instance as string | null) ?? null,
		identity_hash: (row.identity_hash as string | null) ?? null,
	};
}

export function now(): string {
	return new Date().toISOString();
}

export function shortHash(input: string): string {
	return createHash("sha256").update(input).digest("hex").slice(0, 12);
}
