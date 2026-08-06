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

describe("the reportability gate runs before the matrix", () => {
	it("drops self-only findings entirely, rather than landing them at low", () => {
		const r = computeSeverity({ ...base, suppression: { self_only: true } });
		expect(r.reportable).toBe(false);
		expect(r.rationale.join(" ")).toContain("self_only");
	});

	it("keeps a privilege-requiring finding when the privilege delta IS the bug", () => {
		expect(
			reportabilityGate({
				requires_preexisting_privilege: true,
				privilege_delta_is_the_bug: true,
			}),
		).toBeNull();
		expect(reportabilityGate({ requires_preexisting_privilege: true })).toBe(
			"requires_preexisting_privilege",
		);
	});

	it("downgrades low impact but never discards it", () => {
		const r = computeSeverity({ ...base, impact: "low" });
		expect(r.reportable).toBe(true);
		expect(r.severity).toBe("medium");
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

	it("reaches critical statically via a traced path, but marks the proof gap", () => {
		const r = computeSeverity({ ...base, traced_path_no_control: true });
		expect(r.severity).toBe("critical");
		expect(r.proof_gap).toBe("no_execution");
	});

	it("reaches critical cleanly when execution was proven in a container", () => {
		const r = computeSeverity(
			{ ...base, code_execution_proven: true, method: "reproduced_poc" },
			"container",
		);
		expect(r.severity).toBe("critical");
		expect(r.proof_gap).toBeUndefined();
		expect(r.confidence).toBe(1.0);
	});
});

describe("confidence is bound to method", () => {
	it("caps a static review at code-reading confidence", () => {
		const r = computeSeverity({ ...base, method: "code_reading" });
		expect(r.confidence).toBe(0.3);
	});

	it("ignores an execution claim that the static profile cannot support", () => {
		const r = computeSeverity(
			{ ...base, code_execution_proven: true, method: "reproduced_poc" },
			"static",
		);
		expect(r.confidence).toBe(0.3);
		expect(r.rationale.join(" ")).toContain("static profile");
		// And the execution claim buys no severity either: without a traced path or
		// a tenant crossing there is no second route, so it stops at high.
		expect(r.severity).toBe("high");
	});
});
