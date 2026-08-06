/**
 * The four LLM phases. The spine is fixed and lives in code; the agents only
 * ever write through the `opensec` tool.
 */

import type { AgentRunner } from "../agents/session.js";
import type { RunContext } from "../agents/tool.js";
import type { Ledger } from "../db/db.js";
import type { Candidate } from "../types.js";
import type { Prompts } from "./prompts.js";
import { wrapUntrusted } from "./prompts.js";

export interface PhaseDeps {
	runner: AgentRunner;
	ledger: Ledger;
	prompts: Prompts;
	scanId: string;
	repoRoot: string;
	repoName: string;
	profile: RunContext["profile"];
	nonce: string;
	onEvent?: (msg: string) => void;
}

function ctxFor(deps: PhaseDeps, workerId: string): RunContext {
	return {
		scanId: deps.scanId,
		workerId,
		repoRoot: deps.repoRoot,
		profile: deps.profile,
		ledger: deps.ledger,
		nonce: deps.nonce,
	};
}

function bill(deps: PhaseDeps, r: { tokensIn: number; tokensOut: number; costUsd: number }): void {
	deps.ledger.addUsage(deps.scanId, r.tokensIn, r.tokensOut, r.costUsd);
}

// ------------------------------------------------------------ threat model

export async function runThreatModel(deps: PhaseDeps, modelRef?: string): Promise<string> {
	const ctx = ctxFor(deps, "threat-model");
	const { files, total } = deps.ledger.listWork(deps.scanId, 200, 0);
	const listing = files.map((f) => f.path).join("\n");

	const result = await deps.runner.run({
		ctx,
		modelRef,
		systemPrompt: deps.prompts.get("threat-model.md"),
		prompt: [
			`Repository: ${deps.repoName}`,
			`Files in scope: ${total}`,
			"",
			`Here are the first ${files.length} paths. Call opensec({ verb: "work.next", cursor: N })`,
			"to page through the rest, and read whatever you need.",
			"",
			wrapUntrusted(deps.nonce, "file-listing", listing),
			"",
			"Write the threat model now.",
		].join("\n"),
	});

	bill(deps, result);
	deps.ledger.setThreatModel(deps.scanId, result.text);
	return result.text;
}

// --------------------------------------------------------------- discovery

export async function runDiscovery(
	deps: PhaseDeps,
	threatModel: string,
	modelRef?: string,
): Promise<void> {
	const ctx = ctxFor(deps, "probe-1");

	const result = await deps.runner.run({
		ctx,
		modelRef,
		systemPrompt: deps.prompts.get("probe.md"),
		prompt: [
			"A threat model for this repository was written first. It was derived from",
			"the code under review, so treat it as orientation, not as fact:",
			"",
			wrapUntrusted(deps.nonce, "threat-model", threatModel),
			"",
			'Begin by calling opensec({ verb: "work.next" }) to get your worklist.',
			"Page through it until remaining is 0, then report.",
		].join("\n"),
	});

	bill(deps, result);
}

// ------------------------------------------------------------- investigate

export async function runInvestigate(
	deps: PhaseDeps,
	candidate: Candidate,
	modelRef?: string,
): Promise<void> {
	const ctx = ctxFor(deps, `investigate-${candidate.id}`);

	const locations = candidate.locations
		.map((l) => `${l.path}:${l.start_line}-${l.end_line}${l.symbol ? ` (${l.symbol})` : ""}`)
		.join("\n");

	const result = await deps.runner.run({
		ctx,
		modelRef,
		allowBash: deps.profile === "container",
		systemPrompt: [
			deps.prompts.get("investigate.md"),
			"",
			deps.prompts.get("refs/counterevidence.md"),
		].join("\n"),
		prompt: [
			`Candidate ${candidate.id}, filed by ${candidate.worker_id}.`,
			"",
			wrapUntrusted(
				deps.nonce,
				`candidate-${candidate.id}`,
				[
					`Title: ${candidate.title}`,
					`CWE: ${candidate.cwe_ids.length ? candidate.cwe_ids.join(", ") : "(none assigned)"}`,
					"Locations:",
					locations,
					"",
					"Summary:",
					candidate.summary,
					"",
					"Evidence as filed:",
					candidate.evidence,
				].join("\n"),
			),
			"",
			deps.profile === "container"
				? "You have bash in a sandbox. Try to actually trigger it."
				: "You have no shell — this is a static review. Nothing you conclude may " +
					"claim execution, and `code_execution_proven` must be false.",
			"",
			`Investigate, then call opensec({ verb: "candidate.resolve", id: "${candidate.id}", ... }) once.`,
		].join("\n"),
	});

	bill(deps, result);

	// Degradation is directional: an agent that returned without resolving
	// leaves the row unresolved, which downgrades the scan's claim rather than
	// quietly dropping the candidate (plan §4).
	const after = deps.ledger.getCandidate(deps.scanId, candidate.id);
	if (after && !after.resolution) {
		deps.ledger.resolveCandidate(deps.scanId, candidate.id, {
			disposition: "needs_follow_up",
			rationale: "the investigate agent finished without recording a verdict",
		});
		deps.onEvent?.(`  ${candidate.id}: no verdict recorded → needs_follow_up`);
	}
}

// ------------------------------------------------------------------ dedup

/**
 * Dedup is an agent pass, run only when there is more than one row to compare.
 * It may change a finding's state to `duplicate`; it never deletes. Source rows
 * are preserved, because over-merging destroys instances silently while
 * under-merging only costs budget (plan §4).
 */
export async function runDedup(deps: PhaseDeps, modelRef?: string): Promise<number> {
	const reportable = deps.ledger
		.listCandidates(deps.scanId)
		.filter((c) => c.resolution?.disposition === "confirmed" && !c.merged_into);

	if (reportable.length < 2) return 0;

	const ctx = ctxFor(deps, "dedup");
	const rows = reportable
		.map((c) =>
			[
				`id: ${c.id}`,
				`title: ${c.title}`,
				`cwe: ${c.cwe_ids.join(", ") || "(none)"}`,
				`locations: ${c.locations
					.map((l) => `${l.path}:${l.start_line}-${l.end_line}${l.symbol ? ` ${l.symbol}` : ""}`)
					.join("; ")}`,
				`summary: ${c.summary}`,
			].join("\n"),
		)
		.join("\n\n---\n\n");

	const result = await deps.runner.run({
		ctx,
		modelRef,
		systemPrompt: deps.prompts.get("dedup.md"),
		prompt: [
			`${reportable.length} confirmed findings from this scan:`,
			"",
			wrapUntrusted(deps.nonce, "findings", rows),
			"",
			"Resolve any duplicates now. If there are none, say so and resolve nothing.",
		].join("\n"),
	});

	bill(deps, result);

	return deps.ledger
		.listCandidates(deps.scanId)
		.filter((c) => c.merged_into).length;
}
