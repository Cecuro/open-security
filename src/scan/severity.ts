import type {
	AuthRequired,
	Impact,
	Likelihood,
	Method,
	Severity,
	SeverityInputs,
	SeverityResult,
	Suppression,
	Vector,
} from "../types.js";

const LIKELIHOOD: Record<Vector, Record<AuthRequired, Likelihood>> = {
	remote: { none: "high", user: "medium", admin: "low" },
	local_network: { none: "medium", user: "low", admin: "low" },
	localhost: { none: "low", user: "low", admin: "low" },
	none: { none: "low", user: "low", admin: "low" },
	unknown: { none: "low", user: "low", admin: "low" },
};

const MATRIX: Record<Impact, Record<Likelihood, Severity>> = {
	high: { high: "high", medium: "high", low: "medium" },
	medium: { high: "high", medium: "medium", low: "low" },
	low: { high: "medium", medium: "low", low: "low" },
	none: { high: "low", medium: "low", low: "info" },
};

const EXECUTION_METHODS = new Set<Method>(["reproduced_poc", "asan", "debugger"]);

export const CONFIDENCE_BY_METHOD: Record<Method, number> = {
	reproduced_poc: 1.0,
	asan: 0.9,
	debugger: 0.8,
	code_reading: 0.3,
	counterevidence: 0.0,
};

export function suppressionClaim(s: Suppression | undefined): string | null {
	if (!s) return null;
	if (s.self_only) return "self_only";
	if (s.precondition_unreachable) return "precondition_unreachable";
	if (s.requires_preexisting_privilege && !s.privilege_delta_is_the_bug) {
		return "requires_preexisting_privilege";
	}
	return null;
}

// code_evidence only. There is no mechanism for an operator to declare policy,
// so accepting a "policy_flag" source would let an agent assert a declaration
// nobody made. Add the value back when a real --accept-risk flag exists.
const GROUNDS = new Set(["code_evidence"]);

export function reportabilityGate(s: Suppression | undefined): string | null {
	const claim = suppressionClaim(s);
	if (!claim || !s) return null;
	if (!GROUNDS.has(s.source ?? "")) return null;
	if (!s.evidence || s.evidence.trim().length === 0) return null;
	return claim;
}

export function computeSeverity(inputs: SeverityInputs): SeverityResult {
	const rationale: string[] = [];

	const executionProven = inputs.code_execution_proven;
	const confidence = CONFIDENCE_BY_METHOD[inputs.method];

	const blocked = reportabilityGate(inputs.suppression);

	const claim = suppressionClaim(inputs.suppression);
	if (claim && !blocked) {
		const s = inputs.suppression;
		const why =
			s?.source === "repo_claim"
				? "it rests on an in-repo claim, which is evidence about what the authors believe, not policy"
				: !s?.source
					? "no source was given, so there is nothing to audit"
					: !s?.evidence?.trim()
						? "no evidence was given for it"
						: `'${s.source}' is not grounds for suppression`;
		rationale.push(`suppression '${claim}' refused: ${why}. This stays in the report.`);
	}

	if (blocked) {
		rationale.push(`suppressed before the matrix: ${blocked}`);
		if (inputs.suppression?.evidence) {
			rationale.push(`suppression evidence: ${inputs.suppression.evidence}`);
		}
		rationale.push(`grounds: ${inputs.suppression?.source}`);
		return {
			severity: "info",
			likelihood: "low",
			confidence,
			reportable: false,
			rationale,
		};
	}

	const likelihood = LIKELIHOOD[inputs.vector][inputs.auth_required];
	rationale.push(
		`likelihood ${likelihood} from vector=${inputs.vector}, auth_required=${inputs.auth_required}`,
	);

	let severity = MATRIX[inputs.impact][likelihood];
	rationale.push(`matrix: impact=${inputs.impact} × likelihood=${likelihood} → ${severity}`);

	let proof_gap: SeverityResult["proof_gap"];
	const unauthReachable = inputs.network_reachable && inputs.auth_required === "none";
	if (severity === "high" && unauthReachable) {
		if (executionProven) {
			severity = "critical";
			rationale.push("critical: unauthenticated, network-reachable, execution proven");
		} else if (inputs.cross_tenant || inputs.traced_path_no_control) {
			severity = "critical";
			proof_gap = "no_execution";
			rationale.push(
				`critical (unproven): unauthenticated, network-reachable, ${
					inputs.cross_tenant ? "cross-tenant" : "traced path with no intervening control"
				}, but nothing was executed`,
			);
		}
	}

	if (severity === "critical" && !proof_gap && !EXECUTION_METHODS.has(inputs.method)) {
		proof_gap = "no_execution";
		rationale.push(
			`execution was claimed but method is '${inputs.method}', which does not demonstrate it`,
		);
	}

	return { severity, likelihood, confidence, reportable: true, proof_gap, rationale };
}

export function formatSeverity(r: SeverityResult): string {
	return r.proof_gap === "no_execution" ? `${r.severity} (unproven)` : r.severity;
}

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export function severityRank(s: Severity): number {
	return SEVERITY_ORDER.indexOf(s);
}

export function renderMatrix(): string {
	const rows = (Object.keys(MATRIX) as Impact[]).map((impact) => {
		const cells = (["high", "medium", "low"] as Likelihood[]).map(
			(l) => MATRIX[impact][l],
		);
		return `| ${impact.padEnd(6)} | ${cells.map((c) => c.padEnd(8)).join(" | ")} |`;
	});
	return [
		"| impact | L=high   | L=medium | L=low    |",
		"|--------|----------|----------|----------|",
		...rows,
		"",
		"Critical is a promotion, not a cell: unauthenticated + network-reachable +",
		"(execution proven | cross-tenant | traced path with no intervening control).",
	].join("\n");
}
