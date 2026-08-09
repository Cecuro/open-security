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
	{
		version: 6,
		note: "store model, prompt hash and probe count on the scan, so a report can be re-rendered from the ledger alone",
		sql: `
			ALTER TABLE scans ADD COLUMN model_ref TEXT;
			ALTER TABLE scans ADD COLUMN prompt_hash TEXT;
			ALTER TABLE scans ADD COLUMN probes INTEGER;
		`,
	},
	{
		version: 7,
		note: "file_reads — what each pass has read, so a second pass is not handed an empty worklist",
		sql: `
			CREATE TABLE IF NOT EXISTS file_reads (
			  scan_id    TEXT NOT NULL REFERENCES scans(id),
			  read_group TEXT NOT NULL,
			  path       TEXT NOT NULL,
			  bytes_read INTEGER NOT NULL DEFAULT 0,
			  PRIMARY KEY (scan_id, read_group, path)
			);
		`,
	},
	{
		version: 8,
		note: "per-worker read coverage and completion",
		sql: `
			CREATE TABLE worker_work (
			  scan_id TEXT NOT NULL REFERENCES scans(id),
			  worker_id TEXT NOT NULL,
			  files_assigned INTEGER NOT NULL,
			  bytes_assigned INTEGER NOT NULL,
			  summary TEXT,
			  completed_at TEXT,
			  PRIMARY KEY (scan_id, worker_id)
			);
			CREATE TABLE worker_file_reads (
			  scan_id TEXT NOT NULL REFERENCES scans(id),
			  worker_id TEXT NOT NULL,
			  path TEXT NOT NULL,
			  bytes_read INTEGER NOT NULL DEFAULT 0,
			  PRIMARY KEY (scan_id, worker_id, path)
			);
		`,
	},
	{
		version: 9,
		note: "scan scope, so diff and working-tree reports remain reproducible",
		sql: `
			ALTER TABLE scans ADD COLUMN scope_kind TEXT;
			ALTER TABLE scans ADD COLUMN scope_base TEXT;
		`,
	},
	{
		version: 10,
		note: "cache usage and economics, so reports can show prompt-cache effectiveness",
		sql: `
			ALTER TABLE scans ADD COLUMN input_tokens INTEGER NOT NULL DEFAULT 0;
			ALTER TABLE scans ADD COLUMN cache_read_tokens INTEGER NOT NULL DEFAULT 0;
			ALTER TABLE scans ADD COLUMN cache_write_tokens INTEGER NOT NULL DEFAULT 0;
			ALTER TABLE scans ADD COLUMN cache_cost_usd REAL NOT NULL DEFAULT 0;
			ALTER TABLE scans ADD COLUMN cache_savings_usd REAL NOT NULL DEFAULT 0;
		`,
	},
	{
		version: 11,
		note: "scan_events — durable lifecycle, model-usage and tool-error observability",
		sql: `
			CREATE TABLE scan_events (
				id          INTEGER PRIMARY KEY AUTOINCREMENT,
				scan_id     TEXT NOT NULL REFERENCES scans(id),
				at          TEXT NOT NULL,
				type        TEXT NOT NULL,
				worker_id   TEXT,
				detail_json TEXT
			);
			CREATE INDEX scan_events_scan_at ON scan_events(scan_id, at);
		`,
	},
];

export const SCHEMA_VERSION = MIGRATIONS.reduce((v, m) => Math.max(v, m.version), 1);
