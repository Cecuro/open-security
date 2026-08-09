import { describe, expect, it } from "vitest";

import { policyExitCode } from "../src/scan/policy.js";
import type { Candidate, Coverage } from "../src/types.js";

const coverage: Coverage = {
	files_in_scope: 1,
	files_touched: 1,
	bytes_in_scope: 10,
	bytes_read: 10,
};

const finding: Candidate = {
	id: "c1",
	scan_id: "s1",
	worker_id: "probe-1",
	title: "A real finding",
	cwe_ids: [],
	locations: [],
	summary: "summary",
	evidence: "evidence",
	created_at: "now",
	resolution: {
		disposition: "confirmed",
		rationale: "confirmed",
		computed: {
			severity: "high",
			likelihood: "high",
			confidence: 0.3,
			reportable: true,
			rationale: [],
		},
	},
};

describe("CI severity policy", () => {
	it("is report-only until a threshold is requested", () => {
		expect(policyExitCode({ candidates: [finding], coverage })).toBe(0);
	});

	it("fails only findings at or above the configured threshold", () => {
		expect(policyExitCode({ candidates: [finding], coverage }, "critical")).toBe(0);
		expect(policyExitCode({ candidates: [finding], coverage }, "high")).toBe(1);
	});

	it("never passes incomplete coverage under a CI policy", () => {
		expect(
			policyExitCode(
				{ candidates: [], coverage: { ...coverage, bytes_read: 9 } },
				"high",
			),
		).toBe(2);
	});
});
