/**
 * Schema migrations.
 *
 * `schema.sql` is frozen at version 1 and is never edited again. Every later
 * change is an entry here, applied in order. That means a fresh database takes
 * exactly the same path as an upgraded one — the migrations run on every single
 * `Ledger.open()` of a new file, so a broken ALTER is caught by the first test
 * that opens a ledger rather than by the first user with a database from last
 * week.
 *
 * SQLite's ALTER TABLE is not transactional across statements in all builds, so
 * each migration is applied inside one transaction together with its version
 * row: a half-applied migration rolls back rather than leaving a database that
 * claims a version it doesn't have.
 */

export interface Migration {
	version: number;
	/** Why, in one line. Printed if the migration fails. */
	note: string;
	sql: string;
}

export const MIGRATIONS: Migration[] = [
	{
		version: 2,
		// This one is retroactive. partition_id was added by editing schema.sql
		// during the parallel-probes work, which meant no database created before
		// that ever got the column — opening one crashed on the index. It is a
		// migration now, and schema.sql is back to the shape those databases have.
		note: "files.partition_id — which probe is accountable for a file",
		sql: `
			ALTER TABLE files ADD COLUMN partition_id INTEGER;
			CREATE INDEX IF NOT EXISTS files_partition ON files(scan_id, partition_id);
		`,
	},
	{
		version: 3,
		note: "candidate identity, so two probes filing the same flaw collapse to one row",
		sql: `
			ALTER TABLE candidates ADD COLUMN instance TEXT;
			ALTER TABLE candidates ADD COLUMN identity_hash TEXT;
			CREATE INDEX IF NOT EXISTS candidates_identity
			  ON candidates(scan_id, identity_hash);
		`,
	},
	{
		version: 4,
		note: "where a scan's threat model came from, so a reused one is visible in the record",
		sql: `
			ALTER TABLE scans ADD COLUMN threat_model_source TEXT;
		`,
	},
];

/** The version this build of opensec writes and expects. */
export const SCHEMA_VERSION = MIGRATIONS.reduce((v, m) => Math.max(v, m.version), 1);
