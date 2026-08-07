export type Profile = "static" | "container";

export type ScanStatus = "running" | "completed" | "failed";

export type Phase =
	| "inventory"
	| "threat_model"
	| "discovery"
	| "reduce"
	| "validate"
	| "attack_path"
	| "report";

export type Disposition =
	| "confirmed"
	| "not_applicable"
	| "suppressed"
	| "duplicate"
	| "needs_follow_up";

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
	summary: string;
	evidence: string;
	created_at: string;
	resolution?: Resolution;
	merged_into?: string | null;
	instance?: string | null;
	identity_hash?: string | null;
}

export interface Validation {
	disposition: Disposition;
	rationale: string;
	at: string;
}

export interface AttackPath {
	reachability: Reachability;
	rationale: string;
	at: string;
}

export interface Resolution {
	disposition: Disposition;
	rationale: string;
	validation?: Validation;
	attack_path?: AttackPath;
	inputs?: SeverityInputs;
	computed?: SeverityResult;
	duplicate_of?: string;
}

export interface Lead {
	worker_id: string;
	text: string;
	status: "open" | "dead_end";
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

export interface Coverage {
	files_in_scope: number;
	files_touched: number;
	bytes_in_scope: number;
	bytes_read: number;
}
