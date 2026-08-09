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
	db.close();
}

function tmpFile(name: string): string {
	return join(mkdtempSync(join(tmpdir(), "opensec-mig-")), name);
}

describe("schema migrations", () => {
	it("upgrades a version-1 database in place, keeping its rows", () => {
		const file = tmpFile("v1.db");
		makeV1(file);

		const ledger = Ledger.open(file);
		// The old scan and its finding are still there.
		expect(ledger.getScan("old")?.status).toBe("completed");
		expect(ledger.getCandidate("old", "c1")?.title).toBe("an old finding");
		ledger.close();

		const db = new Database(file);
		const version = (db.prepare("SELECT MAX(version) AS v FROM schema_version").get() as {
			v: number;
		}).v;
		expect(version).toBe(SCHEMA_VERSION);

		// The columns every migration claimed to add are actually present.
		const cols = (table: string) =>
			(db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>).map(
				(c) => c.name,
			);
		expect(cols("candidates")).toContain("instance");
		expect(cols("candidates")).toContain("identity_hash");
		expect(cols("scans")).toContain("threat_model_source");
		expect(cols("scans")).toContain("scope_kind");
		expect(cols("scans")).toContain("scope_base");
		// partition_id was added by migration 2 and taken away again by migration
		// 5, once probes stopped owning slices. A database that predates both has
		// to arrive at the same place as one that lived through them, which is the
		// only reason the add is still in the list at all.
		expect(cols("files")).not.toContain("partition_id");
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
