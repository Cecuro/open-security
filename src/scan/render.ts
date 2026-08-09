import type { Candidate, Coverage, ScanRecord, WorkerCoverage } from "../types.js";
import { formatSeverity, renderMatrix, severityRank } from "./severity.js";

export interface ReportInput {
	scan: ScanRecord;
	repoName: string;
	repoPath: string;
	candidates: Candidate[];
	coverage: Coverage;
	probeCoverage?: WorkerCoverage[];
	leads: Array<{ worker_id: string; text: string; status: string }>;
	/** File extensions in scope, without the dot. */
	extensions: string[];
	excludedFiles: number;
	modelRef: string;
	promptHash: string;
	ownership?: string;
	/** Independent passes that ran. Undefined when the caller does not track it. */
	passes?: number;
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
	out.push(`| repository | ${codeSpan(r.repoPath)} |`);
	out.push(`| revision | ${r.scan.revision ? codeSpan(r.scan.revision) : "_not a git repo_"} |`);
	if (r.scan.scope_kind === "diff") out.push(`| scope | diff from ${codeSpan(r.scan.scope_base ?? "(unknown)")} to \`HEAD\` |`);
	if (r.scan.scope_kind === "working_tree") out.push("| scope | staged, unstaged, and untracked files against `HEAD` |");
	out.push(`| profile | **${r.scan.profile}**${r.scan.profile === "static" ? " — nothing was executed" : ""} |`);
	out.push(`| model | ${codeSpan(r.modelRef)} |`);
	out.push(`| prompts | ${codeSpan(r.promptHash)} |`);
	if (r.threatModel) out.push(`| threat model | ${esc(r.threatModel)} |`);
	out.push(`| started | ${r.scan.started_at} |`);
	const inputTokens = r.scan.input_tokens ?? 0;
	const cacheReadTokens = r.scan.cache_read_tokens ?? 0;
	const cacheWriteTokens = r.scan.cache_write_tokens ?? 0;
	const cacheCostUsd = r.scan.cache_cost_usd ?? 0;
	const cacheSavingsUsd = r.scan.cache_savings_usd ?? 0;
	const cachePromptTokens = inputTokens + cacheReadTokens + cacheWriteTokens;
	if (cachePromptTokens > 0 || r.scan.tokens_in === 0) {
		out.push(
			`| tokens | ${inputTokens.toLocaleString()} input / ` +
				`${cacheReadTokens.toLocaleString()} cache read / ` +
				`${cacheWriteTokens.toLocaleString()} cache write / ` +
				`${r.scan.tokens_out.toLocaleString()} out |`,
		);
		out.push(`| cache hit rate | ${percent(cacheReadTokens, inputTokens + cacheReadTokens)} |`);
		out.push(`| cache cost | ${usd(cacheCostUsd)} |`);
		out.push(`| cache savings | ${usd(cacheSavingsUsd)} |`);
	} else {
		// Scans written before cache accounting only have the aggregate total.
		out.push(`| tokens | ${r.scan.tokens_in.toLocaleString()} prompt / ${r.scan.tokens_out.toLocaleString()} out |`);
		out.push("| cache | _not recorded by this version of opensec_ |");
	}
	out.push(`| cost | ${r.scan.cost_usd > 0 ? `$${r.scan.cost_usd.toFixed(4)}` : "_not priced_"} |`);
	out.push("");

	const pctFiles = pct(r.coverage.files_touched, r.coverage.files_in_scope);
	const pctBytes = pct(r.coverage.bytes_read, r.coverage.bytes_in_scope);
	out.push("## Coverage", "");
	out.push(`- **${r.coverage.files_touched} / ${r.coverage.files_in_scope} files touched** (${pctFiles})`);
	out.push(`- **${fmtBytes(r.coverage.bytes_read)} / ${fmtBytes(r.coverage.bytes_in_scope)} read** (${pctBytes}) — the number to trust`);
	out.push(`- ${r.excludedFiles} files excluded from scope with a recorded reason`);
	if (r.ownership) out.push(`- ownership: ${esc(r.ownership)}`);
	out.push("");
	out.push(
		"> Coverage is derived from the read and grep calls that actually happened, not",
		"> from anything the agents claimed. It is a **laziness detector, not proof of",
		"> review**: a file that was read is not thereby a file that was understood.",
		"",
	);
	if (r.probeCoverage && r.probeCoverage.length > 0) {
		const complete = r.probeCoverage.filter((p) => p.completed).length;
		out.push("## Probe coverage", "");
		out.push(`${complete} / ${r.probeCoverage.length} probe(s) completed their worklist.`, "");
		out.push("| probe | files read | bytes read | status |", "|---|---|---|---|");
		for (const p of r.probeCoverage) {
			out.push(
				`| ${codeSpan(p.worker_id)} | ${p.files_touched} / ${p.files_assigned} | ` +
				`${pct(p.bytes_read, p.bytes_assigned)} | ${p.completed ? "complete" : "incomplete"} |`,
			);
		}
		for (const p of r.probeCoverage) if (p.summary) out.push(`- ${codeSpan(p.worker_id)}: ${esc(p.summary)}`);
		out.push("");
	}
	// Coverage says what was read. It says nothing about what was noticed, and
	// what gets noticed varies a lot: repeated scans of the same code at the same
	// revision, reading all of it, return overlapping but different findings —
	// including runs that miss what an earlier one found. A report that presents
	// one pass as the answer is overstating itself, so it says so.
	if (r.passes !== undefined && r.passes < 2) {
		out.push(
			"> This was **one pass**. Reading everything is not noticing everything: a",
			"> second pass over the same code, at the same revision, finds an overlapping",
			"> but different set — in both directions, including findings this one made.",
			"> Treat this as one sample, not the finding list. Raise `--probes` for more.",
			"",
		);
	}
	if (r.extensions.length > 0) {
		out.push(`Extensions in scope: ${r.extensions.map((e) => codeSpan(`.${e}`)).join(", ")}.`, "");
	}

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
				`| ${c.id} | ${comp ? formatSeverity(comp) : "?"} | ${comp?.confidence.toFixed(1) ?? "?"} | ${escInline(c.title)} | ${loc ? codeSpan(`${loc.path}:${loc.start_line}`) : "?"} |`,
			);
		}
		out.push("");
		for (const c of confirmed) out.push(...renderFinding(c, mergedInto(r.candidates, c.id)));
	}

	if (followUp.length > 0) {
		out.push("## Needs follow-up", "");
		out.push(
			"These could not be settled either way. They degrade this scan's claim rather",
			"than disappearing from it.",
			"",
		);
		for (const c of followUp) {
			out.push(
				`- **${c.id}** ${escInline(c.title)} — ${firstLoc(c)}${
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

/**
 * How many separate filings collapsed into this one.
 *
 * Only interesting above 1, and only really above 1 once more than one pass is
 * running. It is deliberately not an input to anything: see the note this puts
 * in the report.
 */
function mergedInto(candidates: Candidate[], id: string): number {
	return candidates.filter((c) => c.merged_into === id).length;
}

function renderFinding(c: Candidate, mergedCount = 0): string[] {
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
	if (mergedCount > 0) {
		// Said plainly because the temptation is to read it as corroboration. Two
		// agents agreeing is a property of the search — they read the same code
		// under the same instructions — and severity and confidence are computed
		// from the evidence either way. A finding filed once is not weaker for it.
		out.push(
			`> Filed ${mergedCount + 1} times independently and merged. That is a fact about ` +
				`the search, not evidence about the finding.`,
			"",
		);
	}

	out.push("**Locations**", "");
	for (const l of c.locations) {
		out.push(`- ${codeSpan(`${l.path}:${l.start_line}-${l.end_line}`)}${l.symbol ? ` — ${codeSpan(l.symbol)}` : ""}`);
	}
	out.push("");

	out.push("**What an attacker gets**", "", esc(c.summary), "");
	out.push("**Evidence**", "", quote(c.evidence), "");

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
	return l ? codeSpan(`${l.path}:${l.start_line}`) : "?";
}

// Markdown backslash escapes do not apply inside a code span — `routes/\[id\].ts`
// renders those backslashes literally. Only two characters matter here: a
// backtick would end the span, and a pipe splits the table cell even inside one.
function codeSpan(s: string): string {
	return `\`${String(s).replace(/[\r\n]+/g, " ").replaceAll("`", "'").replaceAll("|", "\\|")}\``;
}

function esc(s: string): string {
	return String(s)
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;")
		.replaceAll("|", "\\|")
		.replaceAll("[", "\\[")
		.replaceAll("]", "\\]")
		.replaceAll("!", "\\!");
}

function percent(n: number, total: number): string {
	if (total === 0) return "_not reported by provider_";
	return `${((n / total) * 100).toFixed(1)}%`;
}

function usd(value: number): string {
	return value > 0 ? `$${value.toFixed(4)}` : "$0.0000";
}

function escInline(s: string): string {
	return esc(String(s).replace(/[\r\n]+/g, " ")).trim();
}

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
