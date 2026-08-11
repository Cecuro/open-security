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
	{
		version: 12,
		note: "simple candidate state and append-only activity",
		sql: `
			ALTER TABLE candidates ADD COLUMN description TEXT;
			ALTER TABLE candidates ADD COLUMN status TEXT NOT NULL DEFAULT 'open';
			ALTER TABLE candidates ADD COLUMN duplicate_of TEXT;
			UPDATE candidates
			SET description = CASE
				WHEN evidence = '' THEN summary
				WHEN summary = '' THEN evidence
				ELSE summary || char(10) || char(10) || evidence
			END,
			status = COALESCE(json_extract(resolution_json, '$.disposition'), 'open'),
			duplicate_of = merged_into;

			CREATE TABLE candidate_activity (
				id           INTEGER PRIMARY KEY AUTOINCREMENT,
				scan_id      TEXT NOT NULL,
				candidate_id TEXT NOT NULL,
				worker_id    TEXT NOT NULL,
				kind         TEXT NOT NULL,
				body         TEXT NOT NULL,
				data_json    TEXT,
				created_at   TEXT NOT NULL,
				FOREIGN KEY (scan_id, candidate_id) REFERENCES candidates(scan_id, id)
			);
			CREATE INDEX candidate_activity_candidate
				ON candidate_activity(scan_id, candidate_id, id);

			INSERT INTO candidate_activity
				(scan_id, candidate_id, worker_id, kind, body, data_json, created_at)
			SELECT scan_id, id, worker_id, 'validation',
				COALESCE(
					json_extract(resolution_json, '$.validation.rationale'),
					json_extract(resolution_json, '$.rationale'),
					''
				),
				json_object(
					'disposition', COALESCE(
						json_extract(resolution_json, '$.validation.disposition'),
						json_extract(resolution_json, '$.disposition')
					)
				),
				COALESCE(json_extract(resolution_json, '$.validation.at'), created_at)
			FROM candidates
			WHERE resolution_json IS NOT NULL
				AND json_extract(resolution_json, '$.disposition') != 'duplicate'
				AND (
					json_type(resolution_json, '$.validation') IS NOT NULL
					OR (
						json_type(resolution_json, '$.attack_path') IS NULL
						AND json_type(resolution_json, '$.computed') IS NULL
					)
				);

			INSERT INTO candidate_activity
				(scan_id, candidate_id, worker_id, kind, body, data_json, created_at)
			SELECT scan_id, id, worker_id, 'assessment',
				COALESCE(
					json_extract(resolution_json, '$.attack_path.rationale'),
					json_extract(resolution_json, '$.rationale'),
					''
				),
				json_object(
					'disposition', json_extract(resolution_json, '$.disposition'),
					'reachability', json_extract(resolution_json, '$.attack_path.reachability'),
					'inputs', json_extract(resolution_json, '$.inputs'),
					'computed', json_extract(resolution_json, '$.computed')
				),
				COALESCE(json_extract(resolution_json, '$.attack_path.at'), created_at)
			FROM candidates
			WHERE resolution_json IS NOT NULL
				AND json_extract(resolution_json, '$.disposition') != 'duplicate'
				AND (
					json_type(resolution_json, '$.attack_path') IS NOT NULL
					OR json_type(resolution_json, '$.computed') IS NOT NULL
				);

			INSERT INTO candidate_activity
				(scan_id, candidate_id, worker_id, kind, body, data_json, created_at)
			SELECT scan_id, id, worker_id, 'duplicate',
				COALESCE(json_extract(resolution_json, '$.rationale'), ''),
				json_object(
					'disposition', 'duplicate',
					'duplicate_of', COALESCE(
						json_extract(resolution_json, '$.duplicate_of'),
						merged_into
					)
				),
				created_at
			FROM candidates
			WHERE resolution_json IS NOT NULL
				AND json_extract(resolution_json, '$.disposition') = 'duplicate';
		`,
	},
	{
		version: 13,
		note: "coverage is inventory plus per-pass reads; workers are scheduling only",
		sql: `
			ALTER TABLE file_reads ADD COLUMN first_touched_at TEXT;
			ALTER TABLE file_reads ADD COLUMN last_worker_id TEXT;
			UPDATE file_reads
			SET first_touched_at = COALESCE(
				(SELECT files.first_touched_at FROM files
				 WHERE files.scan_id = file_reads.scan_id AND files.path = file_reads.path),
				CASE WHEN bytes_read > 0 THEN CURRENT_TIMESTAMP END
			)
			WHERE first_touched_at IS NULL AND (
				bytes_read > 0 OR EXISTS (
					SELECT 1 FROM files
					WHERE files.scan_id = file_reads.scan_id
						AND files.path = file_reads.path
						AND files.first_touched_at IS NOT NULL
				)
			);
			INSERT INTO file_reads
				(scan_id, read_group, path, bytes_read, first_touched_at, last_worker_id)
			SELECT scan_id, 'pass-1', path, bytes_read,
				COALESCE(first_touched_at, CASE WHEN bytes_read > 0 THEN CURRENT_TIMESTAMP END), NULL
			FROM files
			WHERE (bytes_read > 0 OR first_touched_at IS NOT NULL)
				AND NOT EXISTS (
					SELECT 1 FROM file_reads
					WHERE file_reads.scan_id = files.scan_id
						AND file_reads.path = files.path
						AND file_reads.read_group LIKE 'pass-%'
				);
			DROP TABLE worker_file_reads;
			DROP TABLE worker_work;
		`,
	},
	{
		version: 14,
		note: "remove legacy candidate columns and leads",
		sql: `
			DROP INDEX IF EXISTS candidates_identity;
			DROP INDEX IF EXISTS candidate_activity_candidate;
			ALTER TABLE candidates RENAME TO candidates_legacy;
			ALTER TABLE candidate_activity RENAME TO candidate_activity_legacy;

			CREATE TABLE candidates (
				id             TEXT NOT NULL,
				scan_id        TEXT NOT NULL REFERENCES scans(id),
				worker_id      TEXT NOT NULL,
				title          TEXT NOT NULL,
				cwe_ids        TEXT NOT NULL,
				locations_json TEXT NOT NULL,
				description    TEXT NOT NULL,
				status         TEXT NOT NULL,
				duplicate_of   TEXT,
				instance       TEXT,
				identity_hash  TEXT,
				created_at     TEXT NOT NULL,
				PRIMARY KEY (scan_id, id)
			);
			CREATE INDEX candidates_identity ON candidates(scan_id, identity_hash);
			INSERT INTO candidates
				(id, scan_id, worker_id, title, cwe_ids, locations_json, description,
				 status, duplicate_of, instance, identity_hash, created_at)
			SELECT id, scan_id, worker_id, title, cwe_ids, locations_json,
				COALESCE(description, ''), status, duplicate_of, instance, identity_hash, created_at
			FROM candidates_legacy;

			CREATE TABLE candidate_activity (
				id           INTEGER PRIMARY KEY AUTOINCREMENT,
				scan_id      TEXT NOT NULL,
				candidate_id TEXT NOT NULL,
				worker_id    TEXT NOT NULL,
				kind         TEXT NOT NULL,
				body         TEXT NOT NULL,
				data_json    TEXT,
				created_at   TEXT NOT NULL,
				FOREIGN KEY (scan_id, candidate_id) REFERENCES candidates(scan_id, id)
			);
			CREATE INDEX candidate_activity_candidate
				ON candidate_activity(scan_id, candidate_id, id);
			INSERT INTO candidate_activity
				(id, scan_id, candidate_id, worker_id, kind, body, data_json, created_at)
			SELECT id, scan_id, candidate_id, worker_id, kind, body, data_json, created_at
			FROM candidate_activity_legacy;

			DROP TABLE candidate_activity_legacy;
			DROP TABLE candidates_legacy;
			DROP TABLE leads;
		`,
	},
	{
		version: 15,
		note: "files are inventory only; reads live in file_reads",
		sql: `
			CREATE TABLE files_new (
				scan_id         TEXT NOT NULL REFERENCES scans(id),
				path            TEXT NOT NULL,
				sha             TEXT NOT NULL,
				bytes_total     INTEGER NOT NULL,
				excluded_reason TEXT,
				PRIMARY KEY (scan_id, path)
			);
			INSERT INTO files_new (scan_id, path, sha, bytes_total, excluded_reason)
			SELECT scan_id, path, sha, bytes_total, excluded_reason FROM files;
			DROP TABLE files;
			ALTER TABLE files_new RENAME TO files;
			CREATE INDEX files_scan_scope ON files(scan_id, excluded_reason);
		`,
	},
	{
		version: 16,
		note: "normalized scan configuration and consistent pass/assessment names",
		sql: `
			ALTER TABLE scans RENAME COLUMN probes TO passes;
			ALTER TABLE scans ADD COLUMN config_json TEXT NOT NULL DEFAULT '{}';
			UPDATE scans SET phase = 'assessment' WHERE phase = 'attack_path';
		`,
	},
];

export const SCHEMA_VERSION = MIGRATIONS.reduce((v, m) => Math.max(v, m.version), 1);
