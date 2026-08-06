-- opensec schema, M0.
--
-- One process, one connection, single writer by construction (plan §6). No
-- claim races, no leases. schema_version exists from M0 rather than being
-- retrofitted later.

CREATE TABLE IF NOT EXISTS schema_version (
  version    INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS repos (
  id         TEXT PRIMARY KEY,
  path       TEXT NOT NULL UNIQUE,
  name       TEXT NOT NULL,
  remote_url TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
  id           TEXT PRIMARY KEY,
  repo_id      TEXT NOT NULL REFERENCES repos(id),
  revision     TEXT,
  profile      TEXT NOT NULL,
  status       TEXT NOT NULL,
  phase        TEXT NOT NULL,
  config_hash  TEXT NOT NULL,
  threat_model TEXT,
  started_at   TEXT NOT NULL,
  completed_at TEXT,
  tokens_in    INTEGER NOT NULL DEFAULT 0,
  tokens_out   INTEGER NOT NULL DEFAULT 0,
  cost_usd     REAL    NOT NULL DEFAULT 0
);

-- `files` IS the worklist: work.next is a query over it, and bytes_read is what
-- makes coverage measurable. There is no files.done verb — a file counts as
-- touched only when a read/grep actually reached it.
CREATE TABLE IF NOT EXISTS files (
  scan_id          TEXT NOT NULL REFERENCES scans(id),
  path             TEXT NOT NULL,
  sha              TEXT NOT NULL,
  bytes_total      INTEGER NOT NULL,
  bytes_read       INTEGER NOT NULL DEFAULT 0,
  excluded_reason  TEXT,
  first_touched_at TEXT,
  -- Which probe is ACCOUNTABLE for this file. Not which probe may read it:
  -- reads are repo-wide, because real bugs cross files (plan §4).
  partition_id     INTEGER,
  PRIMARY KEY (scan_id, path)
);

CREATE INDEX IF NOT EXISTS files_scan_scope ON files(scan_id, excluded_reason);
CREATE INDEX IF NOT EXISTS files_partition ON files(scan_id, partition_id);

CREATE TABLE IF NOT EXISTS candidates (
  id              TEXT NOT NULL,
  scan_id         TEXT NOT NULL REFERENCES scans(id),
  worker_id       TEXT NOT NULL,
  title           TEXT NOT NULL,
  cwe_ids         TEXT NOT NULL,      -- JSON array; [] when there is no clear class
  locations_json  TEXT NOT NULL,      -- JSON array of {path,start_line,end_line,symbol}
  summary         TEXT NOT NULL,
  evidence        TEXT NOT NULL,
  resolution_json TEXT,               -- NULL until investigate resolves it
  merged_into     TEXT,               -- set by dedup; source rows are never deleted
  created_at      TEXT NOT NULL,
  PRIMARY KEY (scan_id, id)
);

-- Hypotheses that died. "Every candidate dispositioned" is trivially satisfied
-- by never creating candidates, so the leads a probe abandoned are recorded too.
CREATE TABLE IF NOT EXISTS leads (
  scan_id    TEXT NOT NULL REFERENCES scans(id),
  worker_id  TEXT NOT NULL,
  text       TEXT NOT NULL,
  status     TEXT NOT NULL,
  created_at TEXT NOT NULL
);
