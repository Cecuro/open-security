-- The current schema for a new ledger. Existing ledgers reach this shape through
-- migrations.ts; changes to an existing schema still require a migration.

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
  id                  TEXT PRIMARY KEY,
  repo_id             TEXT NOT NULL REFERENCES repos(id),
  revision            TEXT,
  profile             TEXT NOT NULL,
  status              TEXT NOT NULL,
  phase               TEXT NOT NULL,
  config_hash         TEXT NOT NULL,
  threat_model        TEXT,
  threat_model_source TEXT,
  model_ref           TEXT,
  prompt_hash         TEXT,
  probes              INTEGER,
  scope_kind          TEXT,
  scope_base          TEXT,
  started_at          TEXT NOT NULL,
  completed_at        TEXT,
  input_tokens        INTEGER NOT NULL DEFAULT 0,
  cache_read_tokens   INTEGER NOT NULL DEFAULT 0,
  cache_write_tokens  INTEGER NOT NULL DEFAULT 0,
  tokens_in           INTEGER NOT NULL DEFAULT 0,
  tokens_out          INTEGER NOT NULL DEFAULT 0,
  cost_usd            REAL NOT NULL DEFAULT 0,
  cache_cost_usd      REAL NOT NULL DEFAULT 0,
  cache_savings_usd   REAL NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS files (
  scan_id         TEXT NOT NULL REFERENCES scans(id),
  path            TEXT NOT NULL,
  sha             TEXT NOT NULL,
  bytes_total     INTEGER NOT NULL,
  excluded_reason TEXT,
  PRIMARY KEY (scan_id, path)
);
CREATE INDEX IF NOT EXISTS files_scan_scope ON files(scan_id, excluded_reason);

CREATE TABLE IF NOT EXISTS file_reads (
  scan_id          TEXT NOT NULL REFERENCES scans(id),
  read_group       TEXT NOT NULL,
  path             TEXT NOT NULL,
  bytes_read       INTEGER NOT NULL DEFAULT 0,
  first_touched_at TEXT,
  last_worker_id   TEXT,
  PRIMARY KEY (scan_id, read_group, path)
);

CREATE TABLE IF NOT EXISTS candidates (
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
CREATE INDEX IF NOT EXISTS candidates_identity ON candidates(scan_id, identity_hash);

CREATE TABLE IF NOT EXISTS candidate_activity (
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
CREATE INDEX IF NOT EXISTS candidate_activity_candidate
  ON candidate_activity(scan_id, candidate_id, id);

CREATE TABLE IF NOT EXISTS scan_events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id     TEXT NOT NULL REFERENCES scans(id),
  at          TEXT NOT NULL,
  type        TEXT NOT NULL,
  worker_id   TEXT,
  detail_json TEXT
);
CREATE INDEX IF NOT EXISTS scan_events_scan_at ON scan_events(scan_id, at);
