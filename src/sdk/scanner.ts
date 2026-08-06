/**
 * The SDK *is* the contract; the CLI and MCP only shape arguments and format
 * results (plan §3). Phases are individually callable so you can drive the
 * spine yourself.
 */

import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { randomBytes } from "node:crypto";

import { AgentRunner } from "../agents/session.js";
import { Ledger, scanArtifactDir, shortHash } from "../db/db.js";
import { inventory, type InventoryResult } from "../scan/inventory.js";
import {
	runDedup,
	runDiscovery,
	runInvestigate,
	runThreatModel,
	type PhaseDeps,
} from "../scan/phases.js";
import { loadPrompts, type Prompts } from "../scan/prompts.js";
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
		private readonly opts: Required<Pick<ScannerOptions, "repo">> & ScannerOptions,
		private readonly ledger: Ledger,
		private readonly runner: AgentRunner,
		private readonly prompts: Prompts,
		private readonly repoRoot: string,
		private readonly repoName: string,
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

		const repoId = ledger.upsertRepo(repoRoot, repoName, gitRemote(repoRoot));
		const revision = gitRevision(repoRoot);
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
			randomBytes(9).toString("hex"),
		);
	}

	private deps(): PhaseDeps {
		return {
			runner: this.runner,
			ledger: this.ledger,
			prompts: this.prompts,
			scanId: this.scanId,
			repoRoot: this.repoRoot,
			repoName: this.repoName,
			profile: this.opts.profile ?? "static",
			nonce: this.nonce,
			onEvent: this.opts.onEvent,
		};
	}

	private say(msg: string): void {
		this.opts.onEvent?.(msg);
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
		return runThreatModel(this.deps(), this.opts.models?.threatModel);
	}

	// ------------------------------------------------------------- phase 2

	async discover(threatModel?: string): Promise<Candidate[]> {
		this.ledger.setPhase(this.scanId, "discovery");
		const tm = threatModel ?? this.ledger.getThreatModel(this.scanId) ?? "";
		this.say("discovery: 1 probe (M0 — fan-out arrives with M1)");
		await runDiscovery(this.deps(), tm, this.opts.models?.discovery);
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
			await runInvestigate(this.deps(), c, this.opts.models?.investigate);
			const after = this.ledger.getCandidate(this.scanId, c.id);
			const d = after?.resolution?.disposition;
			const sev = after?.resolution?.computed?.severity;
			this.say(`  → ${d}${sev ? ` (${sev})` : ""}`);
		}
	}

	async dedup(): Promise<number> {
		this.ledger.setPhase(this.scanId, "dedup");
		const merged = await runDedup(this.deps(), this.opts.models?.dedup);
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
		writeFileSync(
			jsonPath,
			JSON.stringify({ scan, coverage, candidates }, null, 2),
			"utf8",
		);

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

function gitRevision(root: string): string | null {
	try {
		return execFileSync("git", ["rev-parse", "HEAD"], {
			cwd: root,
			encoding: "utf8",
			stdio: ["ignore", "pipe", "ignore"],
		}).trim();
	} catch {
		return null;
	}
}

function gitRemote(root: string): string | null {
	try {
		return execFileSync("git", ["config", "--get", "remote.origin.url"], {
			cwd: root,
			encoding: "utf8",
			stdio: ["ignore", "pipe", "ignore"],
		}).trim();
	} catch {
		return null;
	}
}
