import { describe, expect, it } from "vitest";

import { renderExport } from "../src/scan/export.js";

const input = {
	scan: {
		id: "scan-1",
		repo_id: "repo-1",
		revision: "abc",
		profile: "static" as const,
		status: "completed" as const,
		phase: "report" as const,
		config_hash: "config",
		model_ref: "test/model",
		prompt_hash: "prompt",
		probes: 1,
		threat_model_source: null,
		started_at: "2026-08-09T00:00:00.000Z",
		completed_at: "2026-08-09T00:01:00.000Z",
		tokens_in: 0,
		tokens_out: 0,
		cost_usd: 0,
	},
	coverage: { files_in_scope: 1, files_touched: 1, bytes_in_scope: 20, bytes_read: 20 },
	candidates: [
		{
			id: "c1",
			scan_id: "scan-1",
			worker_id: "probe-1",
			title: "SQL injection",
			cwe_ids: ["CWE-89"],
			locations: [{ path: "src/query.ts", start_line: 12, end_line: 13 }],
			summary: "Attacker-controlled input reaches a query.",
			evidence: 'query("select " + input)',
			created_at: "now",
			resolution: {
				disposition: "confirmed" as const,
				rationale: "traced",
				computed: {
					severity: "high" as const,
					likelihood: "high" as const,
					confidence: 0.3,
					reportable: true,
					rationale: [],
				},
			},
		},
		{
			id: "c2",
			scan_id: "scan-1",
			worker_id: "probe-2",
			title: "Merged copy",
			cwe_ids: ["CWE-89"],
			locations: [{ path: "src/query.ts", start_line: 12, end_line: 13 }],
			summary: "duplicate",
			evidence: "duplicate",
			created_at: "now",
			merged_into: "c1",
			resolution: { disposition: "confirmed" as const, rationale: "merged" },
		},
	],
};

describe("scan exports", () => {
	it("keeps the full ledger projection in JSON", () => {
		const json = JSON.parse(renderExport(input, "json"));
		expect(json.scan.id).toBe("scan-1");
		expect(json.candidates).toHaveLength(2);
	});

	it("exports reportable findings as CSV with quoted fields", () => {
		const csv = renderExport(input, "csv");
		expect(csv).toContain("id,severity,confidence");
		expect(csv).toContain("c1,high,0.3,CWE-89,SQL injection,src/query.ts,12,13");
		expect(csv).not.toContain("Merged copy");
	});

	it("writes standard SARIF locations and severity levels", () => {
		const sarif = JSON.parse(renderExport(input, "sarif"));
		expect(sarif.version).toBe("2.1.0");
		expect(sarif.runs[0].tool.driver.name).toBe("opensec");
		expect(sarif.runs[0].results).toHaveLength(1);
		expect(sarif.runs[0].results[0]).toMatchObject({
			ruleId: "CWE-89",
			level: "error",
			locations: [{ physicalLocation: { artifactLocation: { uri: "src/query.ts" } } }],
		});
	});
});
