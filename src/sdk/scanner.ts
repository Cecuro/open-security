/**
 * The SDK *is* the contract; the CLI only shapes arguments and formats results
 * (plan §3). Phases are individually callable so you can drive the spine
 * yourself.
 *
 * The four LLM phases live here as private methods rather than in their own
 * module: each one needs the scanner's ledger, prompts, repo root and nonce, so
 * a separate module bought nothing but a hand-copied duplicate of these fields.
 */

import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";

import { AgentRunner } from "../agents/session.js";
import type { RunContext } from "../agents/tool.js";
import { Ledger, scanArtifactDir, shortHash } from "../db/db.js";
import { inventory, type InventoryResult } from "../scan/inventory.js";
import { loadPrompts, type Prompts, wrapUntrusted } from "../scan/prompts.js";
import { renderMarkdown } from "../scan/render.js";
import type { Candidate, Coverage, Profile } from "../types.js";

export interface ScannerOptions {
	repo: string;
	/** e.g. "azure-openai-responses/gpt-5.4". Required — nothing is guessed. */
	model?: string;
	/** Per-phase overrides; each falls back to `model`. */
	models?: Partial<Record<"threatModel" | "discovery" | "investigate" | "dedup", string>>;
	db?: string;
	profile?: Profile;
	promptsDir?: string;
	maxFiles?: number;
	onEvent?: (msg: string) => void;
}

export interface ScanResult {
	scanId: string;
	markdown: string;
	reportPath: string;
	jsonPath: string;
	candidates: Candidate[];
	coverage: Coverage;
}

export class Scanner {
	private inv?: InventoryResult;

	private constructor(
		readonly scanId: string,
		private readonly opts: ScannerOptions,
		private readonly ledger: Ledger,
		private readonly runner: AgentRunner,
		private readonly prompts: Prompts,
		private readonly repoRoot: string,
		private readonly repoName: string,
		private readonly profile: Profile,
		private readonly nonce: string,
	) {}

	static async open(opts: ScannerOptions): Promise<Scanner> {
		const repoRoot = resolve(opts.repo);
		const repoName = basename(repoRoot);
		const profile = opts.profile ?? "static";

		if (profile === "container") {
			// M2 builds this. Claiming it now would be claiming evidence we don't have.
			throw new Error(
				"--profile container is not implemented yet (M2). Use --profile static.",
			);
		}

		const prompts = loadPrompts(opts.promptsDir);
		const ledger = Ledger.open(opts.db);
		const runner = await AgentRunner.create({ repoRoot, modelRef: opts.model });
		// Fail on an unresolvable model before writing a scan row that could never
		// have finished. `Scanner.estimate()` needs no model and takes no ledger.
		runner.resolveModel(undefined);

		const repoId = ledger.upsertRepo(repoRoot, repoName, git(repoRoot, ["config", "--get", "remote.origin.url"]));
		const revision = git(repoRoot, ["rev-parse", "HEAD"]);
		const scanId = `${new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14)}-${shortHash(repoRoot + Math.random()).slice(0, 6)}`;
		const configHash = shortHash(
			JSON.stringify({ prompts: prompts.hash, model: opts.model, profile }),
		);

		ledger.createScan({ id: scanId, repoId, revision, profile, configHash });

		return new Scanner(
			scanId,
			opts,
			ledger,
			runner,
			prompts,
			repoRoot,
			repoName,
			profile,
			randomBytes(9).toString("hex"),
		);
	}

	private ctx(workerId: string): RunContext {
		return {
			scanId: this.scanId,
			workerId,
			repoRoot: this.repoRoot,
			profile: this.profile,
			ledger: this.ledger,
			nonce: this.nonce,
		};
	}

	private say(msg: string): void {
		this.opts.onEvent?.(msg);
	}

	private bill(r: { tokensIn: number; tokensOut: number; costUsd: number }): void {
		this.ledger.addUsage(this.scanId, r.tokensIn, r.tokensOut, r.costUsd);
	}

	// ------------------------------------------------------------- phase 0

	async inventory(): Promise<InventoryResult> {
		this.ledger.setPhase(this.scanId, "inventory");
		const inv = await inventory(this.repoRoot, { maxFiles: this.opts.maxFiles });
		this.ledger.insertFiles(
			this.scanId,
			inv.entries.map((e) => ({
				path: e.path,
				sha: e.sha,
				bytes: e.bytes,
				excludedReason: e.excludedReason,
			})),
		);
		this.inv = inv;
		this.say(
			`inventory: ${inv.inScope.length} files in scope, ${inv.entries.length - inv.inScope.length} excluded`,
		);
		return inv;
	}

	// ------------------------------------------------------------- phase 1

	async threatModel(): Promise<string> {
		this.ledger.setPhase(this.scanId, "threat_model");
		this.say("threat model: 1 agent");

		const { files, total } = this.ledger.listWork(this.scanId, 200, 0);
		const result = await this.runner.run({
			ctx: this.ctx("threat-model"),
			modelRef: this.opts.models?.threatModel,
			systemPrompt: this.prompts.get("threat-model.md"),
			prompt: [
				`Repository: ${this.repoName}`,
				`Files in scope: ${total}`,
				"",
				`Here are the first ${files.length} paths. Call opensec({ verb: "work.next", cursor: N })`,
				"to page through the rest, and read whatever you need.",
				"",
				wrapUntrusted(this.nonce, "file-listing", files.map((f) => f.path).join("\n")),
				"",
				"Write the threat model now.",
			].join("\n"),
		});

		this.bill(result);
		this.ledger.setThreatModel(this.scanId, result.text);
		return result.text;
	}

	// ------------------------------------------------------------- phase 2

	async discover(threatModel?: string): Promise<Candidate[]> {
		this.ledger.setPhase(this.scanId, "discovery");
		const tm = threatModel ?? this.ledger.getThreatModel(this.scanId) ?? "";
		this.say("discovery: 1 probe (M0 — fan-out arrives with M1)");

		const result = await this.runner.run({
			ctx: this.ctx("probe-1"),
			modelRef: this.opts.models?.discovery,
			systemPrompt: this.prompts.get("probe.md"),
			prompt: [
				"A threat model for this repository was written first. It was derived from",
				"the code under review, so treat it as orientation, not as fact:",
				"",
				wrapUntrusted(this.nonce, "threat-model", tm),
				"",
				'Begin by calling opensec({ verb: "work.next" }) to get your worklist.',
				"Page through it until remaining is 0, then report.",
			].join("\n"),
		});

		this.bill(result);
		const found = this.ledger.listCandidates(this.scanId);
		this.say(`discovery: ${found.length} candidate(s)`);
		return found;
	}

	// ------------------------------------------------------------- phase 3

	async investigate(candidates?: Candidate[]): Promise<void> {
		this.ledger.setPhase(this.scanId, "investigate");
		const todo = candidates ?? this.ledger.listUnresolvedCandidates(this.scanId);
		for (const [i, c] of todo.entries()) {
			this.say(`investigate ${i + 1}/${todo.length}: ${c.id} ${c.title}`);
			await this.investigateOne(c);
			const after = this.ledger.getCandidate(this.scanId, c.id);
			const d = after?.resolution?.disposition;
			const sev = after?.resolution?.computed?.severity;
			this.say(`  → ${d}${sev ? ` (${sev})` : ""}`);
		}
	}

	private async investigateOne(candidate: Candidate): Promise<void> {
		const result = await this.runner.run({
			ctx: this.ctx(`investigate-${candidate.id}`),
			modelRef: this.opts.models?.investigate,
			systemPrompt: [
				this.prompts.get("investigate.md"),
				"",
				this.prompts.get("refs/counterevidence.md"),
			].join("\n"),
			prompt: [
				`Candidate ${candidate.id}, filed by ${candidate.worker_id}.`,
				"",
				wrapUntrusted(
					this.nonce,
					`candidate-${candidate.id}`,
					[
						`Title: ${candidate.title}`,
						`CWE: ${candidate.cwe_ids.length ? candidate.cwe_ids.join(", ") : "(none assigned)"}`,
						"Locations:",
						candidate.locations.map(formatLocation).join("\n"),
						"",
						"Summary:",
						candidate.summary,
						"",
						"Evidence as filed:",
						candidate.evidence,
					].join("\n"),
				),
				"",
				"You have no shell — this is a static review. Nothing you conclude may",
				"claim execution, and `code_execution_proven` must be false.",
				"",
				`Investigate, then call opensec({ verb: "candidate.resolve", id: "${candidate.id}", ... }) once.`,
			].join("\n"),
		});

		this.bill(result);

		// Degradation is directional: an agent that returned without resolving
		// leaves the row unresolved, which downgrades the scan's claim rather than
		// quietly dropping the candidate (plan §4).
		const after = this.ledger.getCandidate(this.scanId, candidate.id);
		if (after && !after.resolution) {
			this.ledger.resolveCandidate(this.scanId, candidate.id, {
				disposition: "needs_follow_up",
				rationale: "the investigate agent finished without recording a verdict",
			});
			this.say(`  ${candidate.id}: no verdict recorded → needs_follow_up`);
		}
	}

	/**
	 * Dedup is an agent pass, run only when there is more than one row to compare.
	 * It may change a finding's state to `duplicate`; it never deletes. Source
	 * rows are preserved, because over-merging destroys instances silently while
	 * under-merging only costs budget (plan §4).
	 */
	async dedup(): Promise<number> {
		this.ledger.setPhase(this.scanId, "dedup");

		const reportable = this.ledger
			.listCandidates(this.scanId)
			.filter((c) => c.resolution?.disposition === "confirmed" && !c.merged_into);
		if (reportable.length < 2) return 0;

		const rows = reportable
			.map((c) =>
				[
					`id: ${c.id}`,
					`title: ${c.title}`,
					`cwe: ${c.cwe_ids.join(", ") || "(none)"}`,
					`locations: ${c.locations.map(formatLocation).join("; ")}`,
					`summary: ${c.summary}`,
				].join("\n"),
			)
			.join("\n\n---\n\n");

		const result = await this.runner.run({
			ctx: this.ctx("dedup"),
			modelRef: this.opts.models?.dedup,
			systemPrompt: this.prompts.get("dedup.md"),
			prompt: [
				`${reportable.length} confirmed findings from this scan:`,
				"",
				wrapUntrusted(this.nonce, "findings", rows),
				"",
				"Resolve any duplicates now. If there are none, say so and resolve nothing.",
			].join("\n"),
		});

		this.bill(result);

		const merged = this.ledger.listCandidates(this.scanId).filter((c) => c.merged_into).length;
		if (merged > 0) this.say(`dedup: ${merged} row(s) merged`);
		return merged;
	}

	// ------------------------------------------------------------- phase 4

	report(): ScanResult {
		this.ledger.setPhase(this.scanId, "report");
		const scan = this.ledger.getScan(this.scanId);
		if (!scan) throw new Error(`scan ${this.scanId} vanished from the ledger`);

		const candidates = this.ledger.listCandidates(this.scanId);
		const coverage = this.ledger.coverage(this.scanId);

		const markdown = renderMarkdown({
			scan,
			repoName: this.repoName,
			repoPath: this.repoRoot,
			candidates,
			coverage,
			leads: this.ledger.listLeads(this.scanId),
			languages: this.inv?.languages ?? [],
			excludedFiles: this.ledger.excludedCount(this.scanId),
			modelRef: this.opts.model ?? "(default)",
			promptHash: this.prompts.hash,
		});

		const dir = scanArtifactDir(this.scanId);
		mkdirSync(dir, { recursive: true });
		const reportPath = join(dir, "report.md");
		const jsonPath = join(dir, "findings.json");
		writeFileSync(reportPath, markdown, "utf8");
		writeFileSync(jsonPath, JSON.stringify({ scan, coverage, candidates }, null, 2), "utf8");

		return { scanId: this.scanId, markdown, reportPath, jsonPath, candidates, coverage };
	}

	/** The whole spine, in order. */
	async run(): Promise<ScanResult> {
		try {
			await this.inventory();
			const tm = await this.threatModel();
			const candidates = await this.discover(tm);
			await this.investigate(candidates);
			await this.dedup();
			const result = this.report();
			this.ledger.finishScan(this.scanId, "completed");
			return result;
		} catch (err) {
			this.ledger.finishScan(this.scanId, "failed");
			throw err;
		}
	}

	/**
	 * Estimate without spending anything — and without writing anything, or
	 * needing a model. It is inventory and arithmetic.
	 */
	static async estimate(opts: {
		repo: string;
		maxFiles?: number;
	}): Promise<{ files: number; bytes: number; approxTokens: number; languages: string[] }> {
		const inv = await inventory(resolve(opts.repo), { maxFiles: opts.maxFiles });
		const bytes = inv.inScope.reduce((n, f) => n + f.bytes, 0);
		return {
			files: inv.inScope.length,
			bytes,
			approxTokens: Math.round(bytes / 3.6),
			languages: inv.languages,
		};
	}

	close(): void {
		this.ledger.close();
	}
}

function formatLocation(l: { path: string; start_line: number; end_line: number; symbol?: string }): string {
	return `${l.path}:${l.start_line}-${l.end_line}${l.symbol ? ` (${l.symbol})` : ""}`;
}

function git(root: string, args: string[]): string | null {
	try {
		return execFileSync("git", args, {
			cwd: root,
			encoding: "utf8",
			stdio: ["ignore", "pipe", "ignore"],
		}).trim();
	} catch {
		return null;
	}
}
