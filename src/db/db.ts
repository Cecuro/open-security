import Database from "better-sqlite3";
import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { identityHash } from "../scan/identity.js";
import { normalizeScanConfig, parseScanConfig, scanConfigHash } from "../scan/config.js";
import type {
	Candidate,
	CandidateActivity,
	CandidateActivityKind,
	CandidateStatus,
	Coverage,
	Location,
	PassCoverage,
	Phase,
	Profile,
	ScanFile,
	ScanRecord,
	ScanStatus,
	ScanConfig,
} from "../types.js";
import { MIGRATIONS, SCHEMA_VERSION } from "./migrations.js";

const here = dirname(fileURLToPath(import.meta.url));

export interface CandidateActivityWrite {
	scanId: string;
	candidateId: string;
	workerId: string;
	kind: CandidateActivityKind;
	body: string;
	status: CandidateStatus;
	data?: CandidateActivity["data"];
	duplicateOf?: string | null;
}

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
		const existing = this.db
			.prepare("SELECT 1 AS ok FROM sqlite_master WHERE type = 'table' AND name = 'scans'")
			.get() !== undefined;
		if (existing) {
			this.db.exec(
				"CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)",
			);
		} else {
			this.db.exec(readFileSync(join(here, "schema.sql"), "utf8"));
		}

		const stamp = this.db.prepare("INSERT INTO schema_version (version, applied_at) VALUES (?, ?)");
		const current = () =>
			(this.db.prepare("SELECT MAX(version) AS v FROM schema_version").get() as {
				v: number | null;
			}).v;

		let at = current();
		if (at === null) {
			// A new ledger is created directly at the current schema. An old ledger
			// that predates version stamps still starts from the v1 baseline.
			at = existing ? 1 : SCHEMA_VERSION;
			stamp.run(at, now());
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
					if (m.version === 16) this.migrateNormalizedConfig();
					else this.db.exec(m.sql);
					stamp.run(m.version, now());
				})();
			} catch (err) {
				throw new Error(
					`schema migration ${m.version} (${m.note}) failed: ${(err as Error).message}`,
				);
			}
		}
	}

	private migrateNormalizedConfig(): void {
		const columns = new Set(
			(this.db.prepare("PRAGMA table_info(scans)").all() as Array<{ name: string }>).map((row) => row.name),
		);
		if (!columns.has("passes")) {
			if (columns.has("probes")) this.db.exec("ALTER TABLE scans RENAME COLUMN probes TO passes");
			else this.db.exec("ALTER TABLE scans ADD COLUMN passes INTEGER");
		}
		if (!columns.has("config_json")) {
			this.db.exec("ALTER TABLE scans ADD COLUMN config_json TEXT NOT NULL DEFAULT '{}'");
		}
		this.db.exec("UPDATE scans SET phase = 'assessment' WHERE phase = 'attack_path'");
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
		config: ScanConfig;
	}): void {
		const config = normalizeScanConfig(args.config);
		const configJson = JSON.stringify(config);
		this.db
			.prepare(
				`INSERT INTO scans (id, repo_id, revision, profile, status, phase, config_hash,
				 config_json, model_ref, prompt_hash, passes, scope_kind, scope_base, started_at)
				 VALUES (?, ?, ?, ?, 'running', 'inventory', ?, ?, ?, ?, ?, ?, ?, ?)`,
			)
			.run(
				args.id,
				args.repoId,
				args.revision,
				config.profile,
				scanConfigHash(config),
				configJson,
				config.modelRef,
				config.promptHash,
				config.passes,
				config.scope.kind,
				config.scope.kind === "diff" ? config.scope.base : null,
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

	listEvents(
		scanId: string,
		limit = 200,
	): Array<{ at: string; type: string; worker_id: string | null; detail_json: string | null }> {
		return this.db
			.prepare(
				`SELECT at, type, worker_id, detail_json FROM scan_events
				 WHERE scan_id = ? ORDER BY id DESC LIMIT ?`,
			)
			.all(scanId, limit) as Array<{
				at: string;
				type: string;
				worker_id: string | null;
				detail_json: string | null;
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
		this.recordEvent(scanId, "phase", { phase });
	}

	/** Small, structured events for live progress and post-run diagnosis. */
	recordEvent(
		scanId: string,
		type: string,
		detail?: Record<string, unknown>,
		workerId?: string,
	): void {
		this.db
			.prepare(
				"INSERT INTO scan_events (scan_id, at, type, worker_id, detail_json) VALUES (?, ?, ?, ?, ?)",
			)
			.run(scanId, now(), type, workerId ?? null, detail ? JSON.stringify(detail) : null);
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

	addUsage(
		scanId: string,
		usage: {
			tokensIn: number;
			tokensOut: number;
			costUsd: number;
			inputTokens: number;
			cacheReadTokens: number;
			cacheWriteTokens: number;
			cacheCostUsd: number;
			cacheSavingsUsd: number;
		},
	): void {
		this.db
			.prepare(
				`UPDATE scans SET input_tokens = input_tokens + ?,
				 cache_read_tokens = cache_read_tokens + ?, cache_write_tokens = cache_write_tokens + ?,
				 tokens_in = tokens_in + ?, tokens_out = tokens_out + ?, cost_usd = cost_usd + ?,
				 cache_cost_usd = cache_cost_usd + ?, cache_savings_usd = cache_savings_usd + ?
				 WHERE id = ?`,
			)
			.run(
				usage.inputTokens,
				usage.cacheReadTokens,
				usage.cacheWriteTokens,
				usage.tokensIn,
				usage.tokensOut,
				usage.costUsd,
				usage.cacheCostUsd,
				usage.cacheSavingsUsd,
				scanId,
			);
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
			config: parseScanConfig(row.config_json),
			model_ref: (row.model_ref as string | null) ?? null,
			prompt_hash: (row.prompt_hash as string | null) ?? null,
			passes: (row.passes as number | null) ?? null,
			threat_model_source: (row.threat_model_source as string | null) ?? null,
			scope_kind: (row.scope_kind as ScanRecord["scope_kind"]) ?? null,
			scope_base: (row.scope_base as string | null) ?? null,
			started_at: row.started_at as string,
			completed_at: row.completed_at as string | null,
			input_tokens: row.input_tokens as number,
			cache_read_tokens: row.cache_read_tokens as number,
			cache_write_tokens: row.cache_write_tokens as number,
			tokens_in: row.tokens_in as number,
			tokens_out: row.tokens_out as number,
			cost_usd: row.cost_usd as number,
			cache_cost_usd: row.cache_cost_usd as number,
			cache_savings_usd: row.cache_savings_usd as number,
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
		readGroup?: string,
	): { files: ScanFile[]; unread: number } {
		if (readGroup === undefined) {
			const progress = `LEFT JOIN (
				SELECT path, MAX(bytes_read) AS bytes_read, MIN(first_touched_at) AS first_touched_at
				FROM file_reads WHERE scan_id = ? GROUP BY path
			) r ON r.path = f.path`;
			const unread = (
				this.db
					.prepare(
						`SELECT COUNT(*) AS n FROM files f ${progress}
						 WHERE f.scan_id = ? AND f.excluded_reason IS NULL
						 AND COALESCE(r.bytes_read, 0) < f.bytes_total`,
					)
					.get(scanId, scanId) as { n: number }
			).n;
			const files = this.db
				.prepare(
					`SELECT f.path, f.sha, f.bytes_total, COALESCE(r.bytes_read, 0) AS bytes_read,
					        f.excluded_reason, r.first_touched_at
					 FROM files f ${progress}
					 WHERE f.scan_id = ? AND f.excluded_reason IS NULL
					 AND COALESCE(r.bytes_read, 0) < f.bytes_total
					 ORDER BY f.path LIMIT ?`,
				)
				.all(scanId, scanId, limit) as ScanFile[];
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
					 AND COALESCE(r.bytes_read, 0) < f.bytes_total`,
				)
				.get(readGroup, scanId) as { n: number }
		).n;
		const files = this.db
			.prepare(
				`SELECT f.path, f.sha, f.bytes_total, COALESCE(r.bytes_read, 0) AS bytes_read,
				        f.excluded_reason, r.first_touched_at
				 FROM files f ${join}
				 WHERE f.scan_id = ? AND f.excluded_reason IS NULL
				 AND COALESCE(r.bytes_read, 0) < f.bytes_total
				 ORDER BY f.path LIMIT ?`,
			)
			.all(readGroup, scanId, limit) as ScanFile[];
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

	/** Whether a path belongs to the inventory scope used for coverage. */
	fileInScope(scanId: string, path: string): boolean {
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
		if (!this.fileInScope(scanId, path)) return;
		// Direct ledger callers default to the first pass. Agent instrumentation
		// only calls this for discovery contexts, where readGroup is explicit.
		const group = readGroup ?? "pass-1";
		this.db
			.prepare(
				`INSERT INTO file_reads
				 (scan_id, read_group, path, bytes_read, first_touched_at, last_worker_id)
				 VALUES (?, ?, ?, ?, ?, ?)
				 ON CONFLICT(scan_id, read_group, path) DO UPDATE SET
				   bytes_read = ${continued ? "MIN((SELECT bytes_total FROM files WHERE scan_id = excluded.scan_id AND path = excluded.path), file_reads.bytes_read + excluded.bytes_read)" : "MAX(file_reads.bytes_read, excluded.bytes_read)"},
				   first_touched_at = COALESCE(file_reads.first_touched_at, excluded.first_touched_at),
				   last_worker_id = excluded.last_worker_id`,
			)
			.run(scanId, group, path, bytesRead, now(), workerId ?? null);
	}

	completeWorkerWork(
		scanId: string,
		readGroup: string | undefined,
	): void {
		const { unread } = this.listWork(scanId, 1, readGroup);
		if (unread !== 0) throw new Error(`work is not complete: ${unread} file(s) still need reading`);
	}

	workerCompleted(scanId: string, workerId: string, readGroup: string): boolean {
		return Boolean(
			this.db
				.prepare(
					`SELECT 1 FROM scan_events
					 WHERE scan_id = ? AND worker_id = ? AND type = 'work_complete'
					 AND json_extract(detail_json, '$.read_group') = ? LIMIT 1`,
				)
				.get(scanId, workerId, readGroup),
		);
	}

	passCoverage(scanId: string, passes: number): PassCoverage[] {
		return Array.from({ length: passes }, (_, index) => {
			const pass = index + 1;
			const group = `pass-${pass}`;
			const row = this.db
				.prepare(
					`SELECT COUNT(*) AS files_in_scope,
					 SUM(CASE WHEN r.first_touched_at IS NOT NULL THEN 1 ELSE 0 END) AS files_touched,
					 COALESCE(SUM(f.bytes_total), 0) AS bytes_in_scope,
					 COALESCE(SUM(MIN(COALESCE(r.bytes_read, 0), f.bytes_total)), 0) AS bytes_read
					 FROM files f LEFT JOIN file_reads r
					 ON r.scan_id = f.scan_id AND r.path = f.path AND r.read_group = ?
					 WHERE f.scan_id = ? AND f.excluded_reason IS NULL`,
				)
				.get(group, scanId) as Record<string, number>;
			const coverage = coverageRow(row);
			const work = this.db
				.prepare(
					`SELECT
					 COUNT(DISTINCT CASE WHEN type = 'work_started' THEN worker_id END) AS started,
					 COUNT(DISTINCT CASE WHEN type = 'work_complete' THEN worker_id END) AS completed
					 FROM scan_events
					 WHERE scan_id = ? AND json_extract(detail_json, '$.read_group') = ?`,
				)
				.get(scanId, group) as { started: number; completed: number };
			return {
				pass,
				...coverage,
				completed:
					coverage.bytes_read >= coverage.bytes_in_scope &&
					work.started > 0 &&
					work.completed >= work.started,
			};
		});
	}

	coverage(scanId: string): Coverage {
		const row = this.db
			.prepare(
				`SELECT COUNT(*) AS files_in_scope,
				 SUM(CASE WHEN r.first_touched_at IS NOT NULL THEN 1 ELSE 0 END) AS files_touched,
				 COALESCE(SUM(f.bytes_total), 0) AS bytes_in_scope,
				 COALESCE(SUM(MIN(COALESCE(r.bytes_read, 0), f.bytes_total)), 0) AS bytes_read
				 FROM files f LEFT JOIN (
					SELECT path, MAX(bytes_read) AS bytes_read, MIN(first_touched_at) AS first_touched_at
					FROM file_reads
					WHERE scan_id = ? AND read_group LIKE 'pass-%' GROUP BY path
				 ) r ON r.path = f.path
				 WHERE f.scan_id = ? AND f.excluded_reason IS NULL`,
			)
			.get(scanId, scanId) as Record<string, number>;
		return coverageRow(row);
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
		description: string;
		instance?: string | null;
	}): { id: string; merged: boolean; duplicateOf?: string } {
		const hash = identityHash({
			cweIds: c.cweIds,
			locations: c.locations,
			instance: c.instance,
		});

		const existing = this.db
			.prepare(
				"SELECT * FROM candidates WHERE scan_id = ? AND identity_hash = ? AND duplicate_of IS NULL",
			)
			.get(c.scanId, hash) as Record<string, unknown> | undefined;

		if (existing) {
			const prev = rowToCandidate(existing, this.listCandidateActivities(c.scanId, existing.id as string));
			const id = this.nextCandidateId(c.scanId);
			this.db.transaction(() => {
				this.db
					.prepare(
						`INSERT INTO candidates
						 (id, scan_id, worker_id, title, cwe_ids, locations_json, description,
						  status, duplicate_of, instance, identity_hash, created_at)
						 VALUES (?, ?, ?, ?, ?, ?, ?, 'duplicate', ?, ?, ?, ?)`,
					)
					.run(
						id,
						c.scanId,
						c.workerId,
						c.title,
						JSON.stringify(c.cweIds),
						JSON.stringify(c.locations),
						c.description,
						prev.id,
						c.instance ?? null,
						hash,
						now(),
					);
				this.db
					.prepare(
						`INSERT INTO candidate_activity
						 (scan_id, candidate_id, worker_id, kind, body, data_json, created_at)
						 VALUES (?, ?, ?, 'duplicate', ?, ?, ?)`,
					)
					.run(
						c.scanId,
						id,
						c.workerId,
						`exact identity match with ${prev.id}`,
						JSON.stringify({ disposition: "duplicate", duplicate_of: prev.id }),
						now(),
					);
			})();
			return { id, merged: true, duplicateOf: prev.id };
		}

		const id = this.nextCandidateId(c.scanId);
		this.db
			.prepare(
				`INSERT INTO candidates
				 (id, scan_id, worker_id, title, cwe_ids, locations_json, description,
				  status, instance, identity_hash, created_at)
				 VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)`,
			)
			.run(
				id,
				c.scanId,
				c.workerId,
				c.title,
				JSON.stringify(c.cweIds),
				JSON.stringify(c.locations),
				c.description,
				c.instance ?? null,
				hash,
				now(),
			);
		return { id, merged: false };
	}

	addCandidateActivity(args: CandidateActivityWrite): void {
		this.addCandidateActivities([args]);
	}

	addCandidateActivities(items: readonly CandidateActivityWrite[]): void {
		if (items.length === 0) return;
		const insert = this.db.prepare(
			`INSERT INTO candidate_activity
			 (scan_id, candidate_id, worker_id, kind, body, data_json, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		);
		const update = this.db.prepare(
			"UPDATE candidates SET status = ?, duplicate_of = ? WHERE scan_id = ? AND id = ?",
		);
		const updateUnlessReviewed = this.db.prepare(
			`UPDATE candidates SET status = ?, duplicate_of = ?
			 WHERE scan_id = ? AND id = ?
			 AND NOT EXISTS (
				 SELECT 1 FROM candidate_activity
				 WHERE scan_id = ? AND candidate_id = ? AND kind = 'review'
			 )`,
		);
		this.db.transaction(() => {
			for (const args of items) {
				insert.run(
					args.scanId,
					args.candidateId,
					args.workerId,
					args.kind,
					args.body,
					args.data ? JSON.stringify(args.data) : null,
					now(),
				);
				if (args.kind === "review") {
					update.run(args.status, args.duplicateOf ?? null, args.scanId, args.candidateId);
				} else if (args.kind !== "comment") {
					updateUnlessReviewed.run(
						args.status,
						args.duplicateOf ?? null,
						args.scanId,
						args.candidateId,
						args.scanId,
						args.candidateId,
					);
				}
			}
		})();
	}

	getCandidate(scanId: string, id: string): Candidate | undefined {
		const row = this.db
			.prepare("SELECT * FROM candidates WHERE scan_id = ? AND id = ?")
			.get(scanId, id) as Record<string, unknown> | undefined;
		return row ? rowToCandidate(row, this.listCandidateActivities(scanId, id)) : undefined;
	}

	listCandidates(scanId: string): Candidate[] {
		const rows = this.db
			.prepare(
				"SELECT * FROM candidates WHERE scan_id = ? ORDER BY CAST(SUBSTR(id, 2) AS INTEGER), id")
			.all(scanId) as Array<Record<string, unknown>>;
		const activities = this.listAllCandidateActivities(scanId);
		return rows.map((row) => rowToCandidate(row, activities.get(row.id as string) ?? []));
	}

	listLiveCandidates(scanId: string): Candidate[] {
		return this.listCandidates(scanId).filter((c) => !c.duplicate_of);
	}

	reviewCandidate(args: {
		scanId: string;
		candidateId: string;
		status?: CandidateStatus;
		comment?: string;
	}): Candidate {
		const scan = this.getScan(args.scanId);
		if (!scan) throw new Error(`no scan '${args.scanId}'`);
		if (scan.status !== "completed") throw new Error("findings can only be reviewed after a scan completes");
		const candidate = this.getCandidate(args.scanId, args.candidateId);
		if (!candidate) throw new Error(`no finding '${args.candidateId}' in scan '${args.scanId}'`);

		const status = args.status ?? candidate.status;
		const comment = args.comment?.trim();
		if (args.status === undefined && !comment) throw new Error("a review needs a state or comment");
		if (args.status === "duplicate") {
			throw new Error("merge duplicates during the scan; the reviewer cannot choose a target yet");
		}

		const disposition = status === "open" ? undefined : status;
		const activities: CandidateActivityWrite[] = [];
		if (args.status !== undefined) {
			const changed = args.status !== candidate.status;
			activities.push({
				scanId: args.scanId,
				candidateId: args.candidateId,
				workerId: "reviewer",
				kind: "review",
				body: changed
					? `State changed from ${candidate.status} to ${status}.`
					: `Reviewed as ${status}.`,
				status,
				data: disposition ? { disposition } : undefined,
				duplicateOf: status === "duplicate" ? candidate.duplicate_of : null,
			});
		}
		if (comment) {
			activities.push({
				scanId: args.scanId,
				candidateId: args.candidateId,
				workerId: "reviewer",
				kind: "comment",
				body: comment,
				status,
				data: disposition ? { disposition } : undefined,
				duplicateOf: status === "duplicate" ? candidate.duplicate_of : null,
			});
		}
		this.addCandidateActivities(activities);

		return this.getCandidate(args.scanId, args.candidateId) as Candidate;
	}

	hasDuplicateChildren(scanId: string, id: string): boolean {
		return Boolean(
			this.db
				.prepare("SELECT 1 FROM candidates WHERE scan_id = ? AND duplicate_of = ? LIMIT 1")
				.get(scanId, id),
		);
	}

	private listCandidateActivities(scanId: string, candidateId: string): CandidateActivity[] {
		const rows = this.db
			.prepare(
				`SELECT id, worker_id, kind, body, data_json, created_at
				 FROM candidate_activity WHERE scan_id = ? AND candidate_id = ? ORDER BY id`,
			)
			.all(scanId, candidateId) as Array<Record<string, unknown>>;
		return rows.map(rowToActivity);
	}

	private listAllCandidateActivities(scanId: string): Map<string, CandidateActivity[]> {
		const grouped = new Map<string, CandidateActivity[]>();
		const rows = this.db
			.prepare(
				`SELECT id, candidate_id, worker_id, kind, body, data_json, created_at
				 FROM candidate_activity WHERE scan_id = ? ORDER BY id`,
			)
			.all(scanId) as Array<Record<string, unknown>>;
		for (const row of rows) {
			const id = row.candidate_id as string;
			const list = grouped.get(id) ?? [];
			list.push(rowToActivity(row));
			grouped.set(id, list);
		}
		return grouped;
	}
}

function rowToCandidate(row: Record<string, unknown>, activities: CandidateActivity[]): Candidate {
	return {
		id: row.id as string,
		scan_id: row.scan_id as string,
		worker_id: row.worker_id as string,
		title: row.title as string,
		cwe_ids: JSON.parse(row.cwe_ids as string) as string[],
		locations: JSON.parse(row.locations_json as string) as Location[],
		description: (row.description as string | null) ?? "",
		status: ((row.status as CandidateStatus | null) ?? "open"),
		created_at: row.created_at as string,
		activities,
		duplicate_of: (row.duplicate_of as string | null) ?? null,
		instance: (row.instance as string | null) ?? null,
		identity_hash: (row.identity_hash as string | null) ?? null,
	};
}

function rowToActivity(row: Record<string, unknown>): CandidateActivity {
	return {
		id: row.id as number,
		worker_id: row.worker_id as string,
		kind: row.kind as CandidateActivityKind,
		body: row.body as string,
		at: row.created_at as string,
		data: row.data_json
			? JSON.parse(row.data_json as string) as CandidateActivity["data"]
			: undefined,
	};
}

function coverageRow(row: Record<string, number>): Coverage {
	return {
		files_in_scope: row.files_in_scope ?? 0,
		files_touched: row.files_touched ?? 0,
		bytes_in_scope: row.bytes_in_scope ?? 0,
		bytes_read: row.bytes_read ?? 0,
	};
}

export function now(): string {
	return new Date().toISOString();
}

export function shortHash(input: string): string {
	return createHash("sha256").update(input).digest("hex").slice(0, 12);
}
