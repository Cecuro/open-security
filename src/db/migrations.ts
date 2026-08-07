export interface Migration {
	version: number;
	note: string;
	sql: string;
}

export const MIGRATIONS: Migration[] = [
	{
		version: 2,
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
	{
		version: 5,
		note: "drop files.partition_id — probes own the whole repository, not a slice of it",
		sql: `
			DROP INDEX IF EXISTS files_partition;
			ALTER TABLE files DROP COLUMN partition_id;
		`,
	},
];

export const SCHEMA_VERSION = MIGRATIONS.reduce((v, m) => Math.max(v, m.version), 1);
