export interface Migration {
	version: number;
	note: string;
	sql: string;
}

/**
 * Version 17 is the first public schema. The private pre-release migration
 * chain was collapsed before v0.1.0 so new installs start from schema.sql.
 * Keep this number monotonic: an old ledger must fail clearly instead of being
 * mistaken for the public baseline.
 */
export const SCHEMA_VERSION = 17;

/** Add all schema changes after v0.1.0 here. */
export const MIGRATIONS: Migration[] = [];
