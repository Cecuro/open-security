/**
 * Severity is computed, never accepted from the model (plan §6).
 *
 * This module is the single source of truth: the matrix below is one data table,
 * evaluated here and rendered by `opensec help severity` and the report appendix,
 * so the published policy cannot drift from the one being applied.
 *
 * The order matters. Reportability is a gate BEFORE the matrix, because the
 * matrix is not a delete key — low impact downgrades, it never discards.
 */

import type {
	AuthRequired,
	Impact,
	Likelihood,
	Method,
	Profile,
	Severity,
	SeverityInputs,
	SeverityResult,
	Suppression,
	Vector,
} from "../types.js";

/** Likelihood from how the flaw is reached and what auth it needs (plan §6.3). */
const LIKELIHOOD: Record<Vector, Record<AuthRequired, Likelihood>> = {
	remote: { none: "high", user: "medium", admin: "low" },
	local_network: { none: "medium", user: "low", admin: "low" },
	localhost: { none: "low", user: "low", admin: "low" },
	none: { none: "low", user: "low", admin: "low" },
	// An unknown vector must not buy a high likelihood.
	unknown: { none: "low", user: "low", admin: "low" },
};

/** impact × likelihood → base severity. No cell is a suppression. */
const MATRIX: Record<Impact, Record<Likelihood, Severity>> = {
	high: { high: "high", medium: "high", low: "medium" },
	medium: { high: "high", medium: "medium", low: "low" },
	low: { high: "medium", medium: "low", low: "low" },
	none: { high: "low", medium: "low", low: "info" },
};

/** Methods that actually demonstrate execution, as opposed to reasoning about it. */
const EXECUTION_METHODS = new Set<Method>(["reproduced_poc", "asan", "debugger"]);

/** Confidence is bound to method numerically, so a static trace cannot report 0.9. */
export const CONFIDENCE_BY_METHOD: Record<Method, number> = {
	reproduced_poc: 1.0,
	asan: 0.9,
	debugger: 0.8,
	code_reading: 0.3,
	counterevidence: 0.0,
};

/**
 * The hard suppression gate. Returns a reason when the candidate is not
 * reportable at all — not a downgrade, a removal from the report.
 *
 * `privilege_delta_is_the_bug` is the escape hatch: needing a privilege is only
 * disqualifying when the privilege isn't itself what's being escalated.
 */
export function reportabilityGate(s: Suppression | undefined): string | null {
	if (!s) return null;
	if (s.self_only) return "self_only";
	if (s.precondition_unreachable) return "precondition_unreachable";
	if (s.requires_preexisting_privilege && !s.privilege_delta_is_the_bug) {
		return "requires_preexisting_privilege";
	}
	return null;
}

export function computeSeverity(
	inputs: SeverityInputs,
	profile: Profile = "static",
): SeverityResult {
	const rationale: string[] = [];

	// `code_execution_proven` is only meaningful under the container profile —
	// nothing executes under static, so the model cannot have proven it.
	let executionProven = inputs.code_execution_proven;
	if (executionProven && profile !== "container") {
		executionProven = false;
		rationale.push(
			"code_execution_proven ignored: nothing executes under the static profile",
		);
	}

	let confidence = CONFIDENCE_BY_METHOD[inputs.method];
	if (
		EXECUTION_METHODS.has(inputs.method) && profile !== "container"
	) {
		// Same reasoning: an execution-derived method is not available statically.
		confidence = CONFIDENCE_BY_METHOD.code_reading;
		rationale.push(
			`method '${inputs.method}' downgraded to code_reading confidence under the static profile`,
		);
	}

	const blocked = reportabilityGate(inputs.suppression);
	if (blocked) {
		rationale.push(`suppressed before the matrix: ${blocked}`);
		if (inputs.suppression?.evidence) {
			rationale.push(`suppression evidence: ${inputs.suppression.evidence}`);
		}
		if (inputs.suppression?.source === "repo_claim") {
			rationale.push(
				"suppression rests on an in-repo claim, which is evidence, not policy",
			);
		}
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

	// Critical is a promotion from observable inputs, not a matrix cell.
	let proof_gap: SeverityResult["proof_gap"];
	const unauthReachable = inputs.network_reachable && inputs.auth_required === "none";
	if (severity === "high" && unauthReachable) {
		if (executionProven) {
			severity = "critical";
			rationale.push("critical: unauthenticated, network-reachable, execution proven");
		} else if (inputs.cross_tenant || inputs.traced_path_no_control) {
			// Second route: a static scan can still reach critical, but it carries
			// the gap. The ceiling is on confidence, not on severity.
			severity = "critical";
			proof_gap = "no_execution";
			rationale.push(
				`critical (unproven): unauthenticated, network-reachable, ${
					inputs.cross_tenant ? "cross-tenant" : "traced path with no intervening control"
				}, but nothing was executed`,
			);
		}
	}

	// A `critical` with no proof gap is the strongest claim this tool makes, so
	// it must rest on an execution-derived method — not on a model setting
	// `code_execution_proven: true` while reporting `method: "code_reading"`.
	if (severity === "critical" && !proof_gap && !EXECUTION_METHODS.has(inputs.method)) {
		proof_gap = "no_execution";
		rationale.push(
			`execution was claimed but method is '${inputs.method}', which does not demonstrate it`,
		);
	}

	return { severity, likelihood, confidence, reportable: true, proof_gap, rationale };
}

/** How a severity prints. `critical (unproven)` is a distinct claim from `critical`. */
export function formatSeverity(r: SeverityResult): string {
	return r.proof_gap === "no_execution" ? `${r.severity} (unproven)` : r.severity;
}

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export function severityRank(s: Severity): number {
	return SEVERITY_ORDER.indexOf(s);
}

/** Rendered by `opensec help severity` and embedded in the report appendix. */
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
