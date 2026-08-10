import { describe, expect, it } from "vitest";

import { computeSeverity, reportabilityGate } from "../src/scan/severity.js";
import type { SeverityInputs } from "../src/types.js";

const base: SeverityInputs = {
	impact: "high",
	vector: "remote",
	auth_required: "none",
	network_reachable: true,
	cross_tenant: false,
	code_execution_proven: false,
	traced_path_no_control: false,
	method: "code_reading",
};

/** A suppression that is entitled to suppress: boolean, evidence, and grounds. */
const grounded = (over: Record<string, unknown> = {}) => ({
	evidence: "the handler rejects any subject other than the caller at auth.ts:40",
	source: "code_evidence" as const,
	...over,
});

describe("the reportability gate runs before the matrix", () => {
	it("drops self-only findings entirely, rather than landing them at low", () => {
		const r = computeSeverity({ ...base, suppression: grounded({ self_only: true }) });
		expect(r.reportable).toBe(false);
		expect(r.rationale.join(" ")).toContain("self_only");
	});

	it("keeps a privilege-requiring finding when the privilege delta IS the bug", () => {
		expect(
			reportabilityGate(
				grounded({ requires_preexisting_privilege: true, privilege_delta_is_the_bug: true }),
			),
		).toBeNull();
		expect(reportabilityGate(grounded({ requires_preexisting_privilege: true }))).toBe(
			"requires_preexisting_privilege",
		);
	});

	it("downgrades low impact but never discards it", () => {
		const r = computeSeverity({ ...base, impact: "low" });
		expect(r.reportable).toBe(true);
		expect(r.severity).toBe("medium");
	});
});

/**
 * Found by opensec scanning opensec. The booleans were checked in code while
 * `source` was enforced only by the prompt, which made removal-from-the-report
 * — the strongest claim this tool makes — the one thing a repository could talk
 * an agent into.
 */
describe("a suppression boolean is not enough on its own", () => {
	const suppressed = (s: Record<string, unknown>) =>
		computeSeverity({ ...base, suppression: s });

	it("refuses a suppression that rests on the repository's own claim", () => {
		const r = suppressed({
			self_only: true,
			evidence: "SECURITY.md says CLI input is trusted",
			source: "repo_claim",
		});
		expect(r.reportable).toBe(true);
		expect(r.rationale.join(" ")).toContain("not policy");
	});

	it("refuses one with NO source, which is the easier attack than repo_claim", () => {
		// Blocking only repo_claim would be defeated by omitting the field.
		const r = suppressed({ self_only: true, evidence: "trust me" });
		expect(r.reportable).toBe(true);
		expect(r.rationale.join(" ")).toContain("nothing to audit");
	});

	it("refuses one with grounds but no evidence", () => {
		const r = suppressed({ self_only: true, source: "code_evidence" });
		expect(r.reportable).toBe(true);
		expect(r.rationale.join(" ")).toContain("no evidence");
	});

	it("refuses 'policy_flag' — no mechanism exists for an operator to declare policy", () => {
		// The value used to be grounds, but nothing verified an operator ever
		// declared anything, so a repo could talk an agent into asserting it.
		const r = suppressed({ self_only: true, evidence: "operator said so", source: "policy_flag" });
		expect(r.reportable).toBe(true);
		expect(r.rationale.join(" ")).toContain("not grounds");
	});

	it("says so in the report rather than suppressing quietly either way", () => {
		const r = suppressed({ precondition_unreachable: true, source: "repo_claim", evidence: "x" });
		expect(r.rationale.join(" ")).toContain("precondition_unreachable");
		expect(r.rationale.join(" ")).toContain("stays in the report");
		// And it is still rated normally, not parked at info.
		expect(r.severity).toBe("high");
	});
});

describe("the matrix", () => {
	it("keys likelihood off vector and auth together", () => {
		expect(computeSeverity(base).likelihood).toBe("high");
		expect(computeSeverity({ ...base, auth_required: "admin" }).likelihood).toBe("low");
		expect(computeSeverity({ ...base, vector: "localhost" }).likelihood).toBe("low");
	});

	it("refuses to let an unknown vector buy a high likelihood", () => {
		expect(computeSeverity({ ...base, vector: "unknown" }).likelihood).toBe("low");
	});
});

describe("critical is a promotion from observable inputs", () => {
	it("does not reach critical on impact and likelihood alone", () => {
		expect(computeSeverity({ ...base, network_reachable: false }).severity).toBe("high");
	});

	it("reaches critical from a traced path, but marks the proof gap", () => {
		const r = computeSeverity({ ...base, traced_path_no_control: true });
		expect(r.severity).toBe("critical");
		expect(r.proof_gap).toBe("no_execution");
	});

	it("reaches critical cleanly when execution was proven in a container", () => {
		const r = computeSeverity({ ...base, code_execution_proven: true, method: "reproduced_poc" });
		expect(r.severity).toBe("critical");
		expect(r.proof_gap).toBeUndefined();
		expect(r.confidence).toBe(1.0);
	});
});

describe("confidence is bound to method", () => {
	it("assigns code reading its lower confidence", () => {
		const r = computeSeverity({ ...base, method: "code_reading" });
		expect(r.confidence).toBe(0.3);
	});
});
