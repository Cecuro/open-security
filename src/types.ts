export type Profile = "local" | "container";

export type ScanScope =
	| { kind: "repository" }
	| { kind: "diff"; base: string }
	| { kind: "scope_file"; path: string }
	| { kind: "working_tree" };

export type ScanStatus = "running" | "completed" | "partial" | "failed";

export type Phase =
	| "inventory"
	| "threat_model"
	| "discovery"
	| "reduce"
	| "validate"
	| "assessment"
	| "report";

/** The complete, defaulted configuration that governs one scan. */
export interface ScanConfig {
	modelRef: string;
	profile: Profile;
	scope: ScanScope;
	promptHash: string;
	passes: number;
	concurrency: number;
	maxTurns: number;
	maxFiles: number | null;
	exclude: string[];
	maxCostUsd: number | null;
	refreshThreatModel: boolean;
}

export type Disposition =
	| "confirmed"
	| "not_applicable"
	| "suppressed"
	| "duplicate"
	| "needs_follow_up";

export type CandidateStatus = "open" | Disposition;

export type Impact = "none" | "low" | "medium" | "high";

export type Vector = "remote" | "local_network" | "localhost" | "none" | "unknown";

export type AuthRequired = "none" | "user" | "admin";

export type Method =
	| "reproduced_poc"
	| "asan"
	| "debugger"
	| "code_reading"
	| "counterevidence";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Likelihood = "high" | "medium" | "low";

export type LocationRole = "entrypoint" | "source" | "root_control" | "sink" | "evidence";

export interface Location {
	path: string;
	start_line: number;
	end_line: number;
	symbol?: string;
	role?: LocationRole;
}

export interface Reachability {
	entry_point: string;
	path: string[];
	controls: string[];
}

export interface Suppression {
	self_only?: boolean;
	requires_preexisting_privilege?: boolean;
	privilege_delta_is_the_bug?: boolean;
	precondition_unreachable?: boolean;
	evidence?: string;
	source?: "code_evidence" | "repo_claim";
}

export interface SeverityInputs {
	impact: Impact;
	vector: Vector;
	auth_required: AuthRequired;
	network_reachable: boolean;
	cross_tenant: boolean;
	code_execution_proven: boolean;
	traced_path_no_control: boolean;
	method: Method;
	suppression?: Suppression;
}

export interface SeverityResult {
	severity: Severity;
	likelihood: Likelihood;
	confidence: number;
	reportable: boolean;
	proof_gap?: "no_execution" | "build_requires_network";
	rationale: string[];
}

export interface Candidate {
	id: string;
	scan_id: string;
	worker_id: string;
	title: string;
	cwe_ids: string[];
	locations: Location[];
	description: string;
	status: CandidateStatus;
	created_at: string;
	activities: CandidateActivity[];
	duplicate_of?: string | null;
	instance?: string | null;
	identity_hash?: string | null;
}

export type CandidateActivityKind =
	| "validation"
	| "assessment"
	| "duplicate"
	| "comment"
	| "review";

export interface CandidateActivity {
	id: number;
	worker_id: string;
	kind: CandidateActivityKind;
	body: string;
	at: string;
	data?: {
		disposition?: Disposition;
		duplicate_of?: string;
		reachability?: Reachability;
		inputs?: SeverityInputs;
		computed?: SeverityResult;
	};
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
	/** Null only for scans created before normalized configuration was stored. */
	config: ScanConfig | null;
	model_ref: string | null;
	prompt_hash: string | null;
	passes: number | null;
	threat_model_source: string | null;
	scope_kind?: ScanScope["kind"] | null;
	scope_base?: string | null;
	started_at: string;
	completed_at: string | null;
	/** Uncached prompt tokens. `tokens_in` remains the total prompt-token count. */
	input_tokens: number;
	cache_read_tokens: number;
	cache_write_tokens: number;
	tokens_in: number;
	tokens_out: number;
	cost_usd: number;
	cache_cost_usd: number;
	cache_savings_usd: number;
}

export interface Coverage {
	files_in_scope: number;
	files_touched: number;
	bytes_in_scope: number;
	bytes_read: number;
}

export interface PassCoverage extends Coverage {
	pass: number;
	completed: boolean;
}

export function latestActivity(
	candidate: Candidate,
	kind: CandidateActivityKind,
): CandidateActivity | undefined {
	return candidate.activities.findLast((activity) => activity.kind === kind);
}

export function candidateComputed(candidate: Candidate): SeverityResult | undefined {
	return latestActivity(candidate, "assessment")?.data?.computed ?? undefined;
}

export function candidateInputs(candidate: Candidate): SeverityInputs | undefined {
	return latestActivity(candidate, "assessment")?.data?.inputs ?? undefined;
}

export function candidateStatus(candidate: Candidate): CandidateStatus {
	return candidate.status;
}

export function candidateDuplicateOf(candidate: Candidate): string | null {
	return candidate.duplicate_of ?? null;
}

export function candidateDescription(candidate: Candidate): string {
	return candidate.description;
}
