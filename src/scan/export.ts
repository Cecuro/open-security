import type { Candidate, Coverage, ScanRecord, Severity } from "../types.js";

export type ExportFormat = "csv" | "json" | "sarif";

export interface ExportInput {
	scan: ScanRecord;
	coverage: Coverage;
	candidates: Candidate[];
}

export function renderExport(input: ExportInput, format: ExportFormat): string {
	switch (format) {
		case "json":
			return `${JSON.stringify(input, null, 2)}\n`;
		case "csv":
			return renderCsv(input);
		case "sarif":
			return `${JSON.stringify(renderSarif(input), null, 2)}\n`;
	}
}

function reportable(input: ExportInput): Candidate[] {
	return input.candidates.filter(
		(candidate) =>
			candidate.merged_into == null &&
			candidate.resolution?.disposition === "confirmed" &&
			candidate.resolution.computed?.reportable !== false,
	);
}

function renderCsv(input: ExportInput): string {
	const header = [
		"id",
		"severity",
		"confidence",
		"cwe",
		"title",
		"path",
		"start_line",
		"end_line",
		"summary",
		"evidence",
	];
	const rows = reportable(input).map((candidate) => {
		const location = candidate.locations[0];
		const computed = candidate.resolution?.computed;
		return [
			candidate.id,
			computed?.severity ?? "info",
			computed?.confidence.toFixed(1) ?? "",
			candidate.cwe_ids.join(";"),
			candidate.title,
			location?.path ?? "",
			location?.start_line ?? "",
			location?.end_line ?? "",
			candidate.summary,
			candidate.evidence,
		];
	});
	return [header, ...rows].map((row) => row.map(csv).join(",")).join("\n") + "\n";
}

function renderSarif(input: ExportInput) {
	const findings = reportable(input);
	const rules = new Map<string, { id: string; name: string; shortDescription: { text: string } }>();
	const results = findings.map((candidate) => {
		const computed = candidate.resolution?.computed;
		const ruleId = candidate.cwe_ids[0] ?? "opensec-security-finding";
		if (!rules.has(ruleId)) {
			rules.set(ruleId, {
				id: ruleId,
				name: ruleId,
				shortDescription: { text: candidate.title },
			});
		}
		return {
			ruleId,
			level: sarifLevel(computed?.severity ?? "info"),
			message: { text: candidate.summary },
			locations: candidate.locations.map((location) => ({
				physicalLocation: {
					artifactLocation: { uri: location.path },
					region: { startLine: location.start_line, endLine: location.end_line },
				},
			})),
			properties: {
				findingId: candidate.id,
				confidence: computed?.confidence ?? null,
				likelihood: computed?.likelihood ?? null,
				proofGap: computed?.proof_gap ?? null,
				scanId: input.scan.id,
			},
		};
	});
	return {
		version: "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		runs: [
			{
				tool: {
					driver: {
						name: "opensec",
						informationUri: "https://github.com/Cecuro/open-security",
						rules: [...rules.values()],
					},
				},
				results,
			},
		],
	};
}

function csv(value: unknown): string {
	const text = String(value ?? "");
	return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function sarifLevel(severity: Severity): "error" | "warning" | "note" {
	if (severity === "critical" || severity === "high") return "error";
	if (severity === "medium") return "warning";
	return "note";
}
