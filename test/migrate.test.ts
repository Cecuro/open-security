/**
 * Migrations. The reason this file exists: `CREATE TABLE IF NOT EXISTS` is a
 * no-op against a table that already exists, so before there was a migration
 * list, adding a column simply did not happen for anyone who had already run a
 * scan — every write to it failed at runtime, not at open.
 */

import Database from "better-sqlite3";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { Ledger } from "../src/db/db.js";
import { MIGRATIONS, SCHEMA_VERSION } from "../src/db/migrations.js";

/**
 * Deliberately the frozen fixture, NOT src/db/schema.sql. Reading the live
 * schema here is what made this suite blind to the partition_id bug: the test
 * database got the column from the schema file, so nothing failed, while every
 * real version-1 database on disk lacked it and crashed on open.
 */
const SCHEMA_V1 = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "schema-v1.sql");

/** A database as opensec v1 left it, and nothing since. */
function makeV1(file: string): void {
	const db = new Database(file);
	db.exec(readFileSync(SCHEMA_V1, "utf8"));
	db.prepare("INSERT INTO schema_version (version, applied_at) VALUES (1, ?)").run("then");
	db.prepare("INSERT INTO repos (id, path, name, created_at) VALUES ('r', '/tmp/r', 'r', 'then')").run();
	db.prepare(
		`INSERT INTO scans (id, repo_id, profile, status, phase, config_hash, started_at)
		 VALUES ('old', 'r', 'static', 'completed', 'report', 'h', 'then')`,
	).run();
	db.prepare(
		`INSERT INTO candidates (id, scan_id, worker_id, title, cwe_ids, locations_json, summary, evidence, created_at)
		 VALUES ('c1', 'old', 'probe-1', 'an old finding', '[]', '[]', 's', 'e', 'then')`,
	).run();
	db.prepare(
		`INSERT INTO candidates
		 (id, scan_id, worker_id, title, cwe_ids, locations_json, summary, evidence, resolution_json, created_at)
		 VALUES ('c2', 'old', 'probe-1', 'a resolved finding', '[]', '[]', 's2', 'e2', ?, 'then')`,
	).run(
		JSON.stringify({
			disposition: "confirmed",
			rationale: "rated",
			validation: { disposition: "confirmed", rationale: "validated", at: "validate-time" },
			attack_path: {
				reachability: { entry_point: "x.ts:1", path: ["x.ts:1"], controls: [] },
				rationale: "assessed",
				at: "assess-time",
			},
			inputs: {
				impact: "low",
				vector: "localhost",
				auth_required: "user",
				network_reachable: false,
				cross_tenant: false,
				code_execution_proven: false,
				traced_path_no_control: false,
				method: "code_reading",
			},
			computed: {
				severity: "low",
				likelihood: "low",
				confidence: 0.3,
				reportable: true,
				rationale: ["rated"],
			},
		}),
	);
	db.prepare(
		`INSERT INTO files
		 (scan_id, path, sha, bytes_total, bytes_read, excluded_reason, first_touched_at)
		 VALUES ('old', 'x.ts', 'sha', 10, 10, NULL, 'read-time')`,
	).run();
	db.close();
}

function tmpFile(name: string): string {
	return join(mkdtempSync(join(tmpdir(), "opensec-mig-")), name);
}

function makeVersion(file: string, version: number): void {
	makeV1(file);
	const db = new Database(file);
	for (const migration of MIGRATIONS.filter((item) => item.version <= version)) {
		db.exec(migration.sql);
		db.prepare("INSERT INTO schema_version (version, applied_at) VALUES (?, 'then')").run(
			migration.version,
		);
	}
	db.close();
}

describe("schema migrations", () => {
	it("upgrades a version-1 database in place, keeping its rows", () => {
		const file = tmpFile("v1.db");
		makeV1(file);

		const ledger = Ledger.open(file);
		// The old scan and its finding are still there.
		expect(ledger.getScan("old")?.status).toBe("completed");
		const candidate = ledger.getCandidate("old", "c1");
		expect(candidate?.title).toBe("an old finding");
		expect(candidate?.description).toBe("s\n\ne");
		expect(candidate?.status).toBe("open");
		const resolved = ledger.getCandidate("old", "c2");
		expect(resolved?.activities.map((activity) => activity.kind)).toEqual([
			"validation",
			"assessment",
		]);
		expect(resolved?.activities[0]?.body).toBe("validated");
		expect(resolved?.activities[1]?.body).toBe("assessed");
		expect(ledger.coverage("old")).toEqual({
			files_in_scope: 1,
			files_touched: 1,
			bytes_in_scope: 10,
			bytes_read: 10,
		});
		ledger.close();

		const db = new Database(file);
		const version = (db.prepare("SELECT MAX(version) AS v FROM schema_version").get() as {
			v: number;
		}).v;
		expect(version).toBe(SCHEMA_VERSION);

		// The current compact schema is present after the historical migrations.
		const cols = (table: string) =>
			(db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>).map(
				(c) => c.name,
			);
		expect(cols("candidates")).toContain("instance");
		expect(cols("candidates")).toContain("identity_hash");
		expect(cols("candidates")).toEqual(
			expect.arrayContaining(["description", "status", "duplicate_of"]),
		);
		expect(cols("candidates")).not.toEqual(
			expect.arrayContaining(["summary", "evidence", "resolution_json", "merged_into"]),
		);
		expect(cols("scans")).toContain("threat_model_source");
		expect(cols("scans")).toContain("scope_kind");
		expect(cols("scans")).toContain("scope_base");
		expect(cols("scans")).toEqual(
			expect.arrayContaining([
				"input_tokens",
				"cache_read_tokens",
				"cache_write_tokens",
				"cache_cost_usd",
				"cache_savings_usd",
			]),
		);
		// partition_id was added by migration 2 and taken away again by migration
		// 5, once probes stopped owning slices. A database that predates both has
		// to arrive at the same place as one that lived through them, which is the
		// only reason the add is still in the list at all.
		expect(cols("files")).not.toContain("partition_id");
		expect(cols("files")).not.toContain("bytes_read");
		expect(cols("files")).not.toContain("first_touched_at");
		expect(cols("file_reads")).toEqual(
			expect.arrayContaining(["bytes_read", "first_touched_at", "last_worker_id"]),
		);
		const tables = (db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as Array<{ name: string }>).map((row) => row.name);
		expect(tables).not.toContain("worker_work");
		expect(tables).not.toContain("worker_file_reads");
		expect(tables).not.toContain("leads");
		expect(tables).toContain("candidate_activity");
		const indexes = (
			db.prepare("SELECT name FROM sqlite_master WHERE type = 'index'").all() as Array<{
				name: string;
			}>
		).map((r) => r.name);
		expect(indexes).not.toContain("files_partition");
		db.close();
	});

	it("a migrated database and a fresh one end up structurally identical", () => {
		const upgraded = tmpFile("upgraded.db");
		makeV1(upgraded);
		Ledger.open(upgraded).close();
		const fresh = tmpFile("new.db");
		Ledger.open(fresh).close();

		const shapeOf = (file: string) => {
			const db = new Database(file);
			const rows = db
				.prepare("SELECT type, name, sql FROM sqlite_master ORDER BY type, name")
				.all() as Array<{ sql: string | null }>;
			db.close();
			// ALTER TABLE leaves the added column at the end of the CREATE statement
			// while a fresh table would declare it inline, so compare the set of
			// (table, column) pairs rather than the SQL text.
			return rows.map((r) => (r.sql ?? "").replace(/\s+/g, " ").trim()).join("\n");
		};

		const a = new Database(upgraded);
		const b = new Database(fresh);
		const columns = (db: Database.Database) =>
			(db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all() as Array<{
				name: string;
			}>)
				.flatMap((t) =>
					(db.prepare(`PRAGMA table_info(${t.name})`).all() as Array<{ name: string }>).map(
						(c) => `${t.name}.${c.name}`,
					),
				)
				.sort();
		expect(columns(a)).toEqual(columns(b));
		a.close();
		b.close();
		// Indexes too — a missing one is a silent full scan, not an error.
		expect(shapeOf(upgraded).split("\n").length).toBe(shapeOf(fresh).split("\n").length);
	});

	it("is idempotent — reopening applies nothing and changes nothing", () => {
		const file = tmpFile("twice.db");
		makeV1(file);
		Ledger.open(file).close();
		Ledger.open(file).close();

		const db = new Database(file);
		const rows = db.prepare("SELECT version FROM schema_version ORDER BY version").all() as Array<{
			version: number;
		}>;
		expect(rows.map((r) => r.version)).toEqual([1, ...MIGRATIONS.map((m) => m.version)]);
		db.close();
	});

	it("a fresh database ends at the same version as an upgraded one", () => {
		const fresh = tmpFile("fresh.db");
		Ledger.open(fresh).close();
		const db = new Database(fresh);
		expect(
			(db.prepare("SELECT MAX(version) AS v FROM schema_version").get() as { v: number }).v,
		).toBe(SCHEMA_VERSION);
		db.close();
	});

	it("keeps per-pass reads authoritative and preserves grep-only touches", () => {
		const file = tmpFile("v12-coverage.db");
		makeVersion(file, 12);
		const old = new Database(file);
		old.prepare(
			"UPDATE files SET bytes_total = 100, bytes_read = 100, first_touched_at = 'read-time' WHERE path = 'x.ts'",
		).run();
		old.prepare(
			`INSERT INTO file_reads (scan_id, read_group, path, bytes_read)
			 VALUES ('old', 'pass-1', 'x.ts', 10), ('old', 'pass-2', 'x.ts', 100)`,
		).run();
		old.prepare(
			`INSERT INTO files
			 (scan_id, path, sha, bytes_total, bytes_read, excluded_reason, first_touched_at)
			 VALUES ('old', 'grep-only.ts', 'sha2', 10, 0, NULL, 'grep-time')`,
		).run();
		old.close();

		const ledger = Ledger.open(file);
		const passes = ledger.passCoverage("old", 2);
		expect(passes[0]).toMatchObject({ files_touched: 2, bytes_read: 10, completed: false });
		expect(passes[1]).toMatchObject({ files_touched: 1, bytes_read: 100, completed: false });
		expect(ledger.coverage("old")).toMatchObject({ files_touched: 2, bytes_read: 100 });
		ledger.close();
	});

	it("refuses a database written by a newer opensec rather than misreading it", () => {
		const file = tmpFile("future.db");
		Ledger.open(file).close();
		const db = new Database(file);
		db.prepare("INSERT INTO schema_version (version, applied_at) VALUES (?, ?)").run(
			SCHEMA_VERSION + 5,
			"later",
		);
		db.close();

		expect(() => Ledger.open(file)).toThrow(/Upgrade opensec/);
	});
});

describe("file_reads is held to the same integrity as every other scan table", () => {
	it("refuses a row for a scan that does not exist", () => {
		// Every other table keyed on scan_id declares REFERENCES scans(id), and
		// the connection turns foreign_keys on. This one was written without it,
		// which would have let a pass's read history outlive the scan it belongs
		// to and only show up as a worklist that never drains.
		const file = tmpFile("fk.db");
		Ledger.open(file).close();
		const db = new Database(file);
		db.pragma("foreign_keys = ON");
		expect(db.prepare("PRAGMA foreign_key_list(file_reads)").all()).toHaveLength(1);
		expect(() =>
			db
				.prepare("INSERT INTO file_reads (scan_id, read_group, path, bytes_read) VALUES (?,?,?,?)")
				.run("no-such-scan", "pass-1", "a.rs", 1),
		).toThrow(/FOREIGN KEY/);
		db.close();
	});
});
