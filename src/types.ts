/** Core types. Shared by the SDK, the CLI, the agent tool and the renderer. */

/** Where the scan's bash runs. M0 is static-only; `container` arrives with M2. */
export type Profile = "static" | "container";

export type ScanStatus = "running" | "completed" | "failed";

/**
 * `reduce` runs before `validate` so duplicates are never validated twice, and
 * `attack_path` runs after it over survivors only. Validation and reachability
 * are separate agents on purpose: a reader who has already talked themselves
 * into "this is real" is a poor judge of how far it actually reaches, and most
 * false positives die in the first pass without anyone paying for the second.
 */
export type Phase =
	| "inventory"
	| "threat_model"
	| "discovery"
	| "reduce"
	| "validate"
	| "attack_path"
	| "report";

/**
 * What investigation concluded about a candidate.
 *
 * `needs_follow_up` is the degradation target: anything unparseable or
 * unverifiable lands here rather than disappearing (plan §4).
 */
export type Disposition =
	| "confirmed"
	| "not_applicable"
	| "suppressed"
	| "duplicate"
	| "needs_follow_up";

export type Impact = "none" | "low" | "medium" | "high";

/** How an attacker reaches the flaw. Drives likelihood (plan §6.3). */
export type Vector = "remote" | "local_network" | "localhost" | "none" | "unknown";

export type AuthRequired = "none" | "user" | "admin";

/** How the conclusion was reached. Binds confidence numerically (plan §6.6). */
export type Method =
	| "reproduced_poc"
	| "asan"
	| "debugger"
	| "code_reading"
	| "counterevidence";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Likelihood = "high" | "medium" | "low";

/**
 * What a location IS to the finding. Identity is computed over paths and roles,
 * so "the sink is in a.ts and the missing check is in b.ts" is a different
 * finding from "the sink is in b.ts and the missing check is in a.ts", even
 * though the file set is the same.
 */
export type LocationRole = "entrypoint" | "source" | "root_control" | "sink" | "evidence";

/** A file:line span. Line numbers are validated against the real file on write. */
export interface Location {
	path: string;
	start_line: number;
	end_line: number;
	/** Enclosing function/class if the agent knows it. */
	symbol?: string;
	/** Defaults to `evidence` when the agent doesn't say. */
	role?: LocationRole;
}

/**
 * The reachability trace, recorded by the attack-path pass. This is what makes
 * `traced_path_no_control` checkable rather than a boolean the model asserts:
 * claiming a path with no control while listing controls is a contradiction the
 * tool can see.
 */
export interface Reachability {
	/** Where an attacker starts. `path:line` plus what they control there. */
	entry_point: string;
	/** Each hop from entry point to sink, in order. */
	path: string[];
	/** Every check, filter or encoder found ON that path. Empty is a claim. */
	controls: string[];
}

/**
 * Auditable suppression reasons. There is deliberately no `ignore` value in
 * either severity enum — suppression is booleans with evidence (plan §6.2).
 */
export interface Suppression {
	self_only?: boolean;
	requires_preexisting_privilege?: boolean;
	privilege_delta_is_the_bug?: boolean;
	precondition_unreachable?: boolean;
	/** Free text justifying whichever booleans are set. */
	evidence?: string;
	/** Where the suppression came from. Repo claims are never grounds on their own (plan §5). */
	source?: "policy_flag" | "code_evidence" | "repo_claim";
}

/** The observable inputs severity is computed from. */
export interface SeverityInputs {
	impact: Impact;
	vector: Vector;
	auth_required: AuthRequired;
	network_reachable: boolean;
	cross_tenant: boolean;
	code_execution_proven: boolean;
	/** A traced source→sink path with no intervening control. Second route to critical. */
	traced_path_no_control: boolean;
	method: Method;
	suppression?: Suppression;
}

export interface SeverityResult {
	severity: Severity;
	likelihood: Likelihood;
	confidence: number;
	reportable: boolean;
	/** Set when severity is asserted without execution, e.g. `critical (unproven)`. */
	proof_gap?: "no_execution" | "build_requires_network";
	/** Human-readable trace of how this was computed. Rendered in the report. */
	rationale: string[];
}

export interface Candidate {
	id: string;
	scan_id: string;
	worker_id: string;
	title: string;
	cwe_ids: string[];
	locations: Location[];
	summary: string;
	evidence: string;
	created_at: string;
	resolution?: Resolution;
	merged_into?: string | null;
	/**
	 * What distinguishes this from a sibling finding of the same class in the
	 * same place — e.g. which secret, which parameter. Part of identity.
	 */
	instance?: string | null;
	/** sha256 of the identity tuple. Equal hashes are one finding, by definition. */
	identity_hash?: string | null;
}

/** The first pass: is this real? No severity, no reachability. */
export interface Validation {
	disposition: Disposition;
	rationale: string;
	at: string;
}

/** The second pass, over survivors only: how far does it actually reach? */
export interface AttackPath {
	reachability: Reachability;
	rationale: string;
	at: string;
}

/**
 * Accumulated across both passes. `disposition` is the live state — validate
 * writes it, assess may downgrade it when the suppression gate fires — while
 * `validation` and `attack_path` keep each pass's own record, so a suppressed
 * finding still shows what the first reader concluded.
 */
export interface Resolution {
	disposition: Disposition;
	rationale: string;
	validation?: Validation;
	attack_path?: AttackPath;
	inputs?: SeverityInputs;
	computed?: SeverityResult;
	/** Set when disposition is `duplicate`. */
	duplicate_of?: string;
}

export interface Lead {
	worker_id: string;
	text: string;
	status: "open" | "dead_end" | "became_candidate";
}

export interface ScanFile {
	path: string;
	sha: string;
	bytes_total: number;
	bytes_read: number;
	excluded_reason: string | null;
	first_touched_at: string | null;
}

export interface ScanRecord {
	id: string;
	repo_id: string;
	revision: string | null;
	profile: Profile;
	status: ScanStatus;
	phase: Phase;
	config_hash: string;
	started_at: string;
	completed_at: string | null;
	tokens_in: number;
	tokens_out: number;
	cost_usd: number;
}

/** Coverage as three numbers, because none alone is honest (plan §6). */
export interface Coverage {
	files_in_scope: number;
	files_touched: number;
	bytes_in_scope: number;
	bytes_read: number;
}
