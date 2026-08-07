-- FROZEN. CREATE TABLE IF NOT EXISTS is a no-op against a table that already
-- exists, so a column added here never appears for anyone who has run a scan.
-- Every change goes in migrations.ts.

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

CREATE TABLE IF NOT EXISTS files (
  scan_id          TEXT NOT NULL REFERENCES scans(id),
  path             TEXT NOT NULL,
  sha              TEXT NOT NULL,
  bytes_total      INTEGER NOT NULL,
  bytes_read       INTEGER NOT NULL DEFAULT 0,
  excluded_reason  TEXT,
  first_touched_at TEXT,
  PRIMARY KEY (scan_id, path)
);

CREATE INDEX IF NOT EXISTS files_scan_scope ON files(scan_id, excluded_reason);

CREATE TABLE IF NOT EXISTS candidates (
  id              TEXT NOT NULL,
  scan_id         TEXT NOT NULL REFERENCES scans(id),
  worker_id       TEXT NOT NULL,
  title           TEXT NOT NULL,
  cwe_ids         TEXT NOT NULL,
  locations_json  TEXT NOT NULL,
  summary         TEXT NOT NULL,
  evidence        TEXT NOT NULL,
  resolution_json TEXT,
  merged_into     TEXT,
  created_at      TEXT NOT NULL,
  PRIMARY KEY (scan_id, id)
);

CREATE TABLE IF NOT EXISTS leads (
  scan_id    TEXT NOT NULL REFERENCES scans(id),
  worker_id  TEXT NOT NULL,
  text       TEXT NOT NULL,
  status     TEXT NOT NULL,
  created_at TEXT NOT NULL
);
