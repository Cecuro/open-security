import Database from "better-sqlite3";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { Ledger } from "../src/db/db.js";
import { MIGRATIONS, SCHEMA_VERSION } from "../src/db/migrations.js";

function tmpFile(name: string): string {
	return join(mkdtempSync(join(tmpdir(), "opensec-schema-")), name);
}

describe("schema migrations", () => {
	it("creates a new ledger at the public baseline", () => {
		const file = tmpFile("new.db");
		Ledger.open(file).close();

		const db = new Database(file);
		const version = db.prepare("SELECT MAX(version) AS v FROM schema_version").get() as {
			v: number;
		};
		expect(version.v).toBe(SCHEMA_VERSION);
		expect(MIGRATIONS).toEqual([]);
		expect(
			(db.prepare("PRAGMA table_info(candidates)").all() as Array<{ name: string }>).map(
				(column) => column.name,
			),
		).toEqual(
			expect.arrayContaining(["description", "status", "duplicate_of", "identity_hash"]),
		);
		const tables = (
			db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as Array<{
				name: string;
			}>
		).map((row) => row.name);
		expect(tables).toEqual(
			expect.arrayContaining([
				"repos",
				"scans",
				"files",
				"file_reads",
				"candidates",
				"candidate_activity",
				"scan_events",
			]),
		);
		db.close();
	});

	it("can reopen a public ledger without changing its version", () => {
		const file = tmpFile("twice.db");
		Ledger.open(file).close();
		Ledger.open(file).close();

		const db = new Database(file);
		const versions = db.prepare("SELECT version FROM schema_version").all() as Array<{
			version: number;
		}>;
		expect(versions).toEqual([{ version: SCHEMA_VERSION }]);
		db.close();
	});

	it("keeps file reads tied to a real scan", () => {
		const file = tmpFile("foreign-key.db");
		Ledger.open(file).close();
		const db = new Database(file);
		db.pragma("foreign_keys = ON");
		expect(db.prepare("PRAGMA foreign_key_list(file_reads)").all()).toHaveLength(1);
		expect(() =>
			db
				.prepare(
					"INSERT INTO file_reads (scan_id, read_group, path, bytes_read) VALUES (?, ?, ?, ?)",
				)
				.run("missing", "pass-1", "a.ts", 1),
		).toThrow(/FOREIGN KEY/);
		db.close();
	});

	it("rejects private pre-release ledgers instead of opening the wrong shape", () => {
		const file = tmpFile("old.db");
		const db = new Database(file);
		db.exec(`
			CREATE TABLE scans (id TEXT PRIMARY KEY);
			CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
			INSERT INTO schema_version VALUES (16, 'then');
		`);
		db.close();

		expect(() => Ledger.open(file)).toThrow(/pre-release schema version 16/);
	});

	it("rejects ledgers created by a newer release", () => {
		const file = tmpFile("future.db");
		const db = new Database(file);
		db.exec(`
			CREATE TABLE scans (id TEXT PRIMARY KEY);
			CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
			INSERT INTO schema_version VALUES (${SCHEMA_VERSION + 1}, 'then');
		`);
		db.close();

		expect(() => Ledger.open(file)).toThrow(/Upgrade opensec/);
	});
});
