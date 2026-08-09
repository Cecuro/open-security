import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join, resolve } from "node:path";

import { AgentRunner, type AgentRunResult, pricingOf, type RunArgs } from "../agents/session.js";
import type { SubagentDeps } from "../agents/subagent.js";
import {
	ASSESS_VERBS,
	PROBE_VERBS,
	REDUCE_VERBS,
	type RunContext,
	THREAT_MODEL_VERBS,
	VALIDATE_VERBS,
} from "../agents/tool.js";
import { Ledger, opensecDir, scanArtifactDir, shortHash } from "../db/db.js";
import { loadEnv } from "../env.js";
import { collisionGroups } from "../scan/identity.js";
import { ext, inventory, type InventoryResult } from "../scan/inventory.js";
import { mapConcurrent } from "../scan/concurrency.js";
import { describeDistribution, partition, type Partition } from "../scan/partition.js";
import { loadPrompts, type Prompts, wrapUntrusted } from "../scan/prompts.js";
import { renderMarkdown } from "../scan/render.js";
import { scopedPaths } from "../scan/target.js";
import { redactSecrets, stripControlChars } from "../text.js";
import type { Candidate, Coverage, Phase, Profile, ScanScope } from "../types.js";

export interface ScannerOptions {
	repo: string;
	model?: string;
	db?: string;
	profile?: Profile;
	promptsDir?: string;
	maxFiles?: number;
	/** Repo-relative globs the user does not want reviewed. */
	exclude?: readonly string[];
	maxCostUsd?: number | null;
	partitionMaxFiles?: number;
	/**
	 * How many independent passes run over the repository. Each pass reviews
	 * every file, by a fresh set of agents that never see the other passes'
	 * findings — so this buys independent looks, and costs roughly n times the
	 * reading. Defaults to one.
	 */
	probes?: number;
	concurrency?: number;
	maxTurns?: number;
	refreshThreatModel?: boolean;
	/** Limit candidate anchors to a Git diff or the current working tree. */
	scope?: ScanScope;
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

/**
 * Phases in execution order. A resumed scan re-enters at the phase it stopped
 * in; everything strictly before it is already in the ledger and is not redone.
 */
export const PHASE_ORDER: Phase[] = [
	"inventory",
	"threat_model",
	"discovery",
	"reduce",
	"validate",
	"attack_path",
	"report",
];

export function phaseBefore(a: Phase, b: Phase): boolean {
	return PHASE_ORDER.indexOf(a) < PHASE_ORDER.indexOf(b);
}

export class Scanner {
	private inv?: InventoryResult;
	private partitions?: Partition[];
	private constructor(
		readonly scanId: string,
		private readonly opts: ScannerOptions,
		private readonly ledger: Ledger,
		private readonly runner: AgentRunner,
		private readonly prompts: Prompts,
		private readonly repoRoot: string,
		private readonly repoName: string,
		private readonly repoId: string,
		private readonly revision: string | null,
		private readonly profile: Profile,
		private readonly scope: ScanScope,
		private readonly nonce: string,
		private readonly startPhase: Phase = "inventory",
	) {}

	static async open(opts: ScannerOptions): Promise<Scanner> {
		const repoRoot = resolve(opts.repo);
		const repoName = basename(repoRoot);
		const profile = opts.profile ?? "static";
		const scope = opts.scope ?? { kind: "repository" };

		if (profile === "container") {
			throw new Error(
				"--profile container is not implemented yet (M2). Use --profile static.",
			);
		}

		// SDK callers get the same credential resolution as the CLI. Idempotent,
		// and anything already in the environment wins.
		loadEnv();

		const prompts = loadPrompts(opts.promptsDir);
		const ledger = Ledger.open(opts.db);
		const runner = await AgentRunner.create({ repoRoot, modelRef: opts.model });
		const model = Scanner.resolveEnforceable(runner, opts.maxCostUsd);

		const repoId = ledger.upsertRepo(repoRoot, repoName, git(repoRoot, ["config", "--get", "remote.origin.url"]));
		const revision = git(repoRoot, ["rev-parse", "HEAD"]);
		const scanId = `${new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14)}-${shortHash(repoRoot + Math.random()).slice(0, 6)}`;
		const configHash = shortHash(
			JSON.stringify({ prompts: prompts.hash, model: opts.model, profile, scope }),
		);

		ledger.createScan({
			id: scanId,
			repoId,
			revision,
			profile,
			configHash,
			modelRef: `${model.provider}/${model.id}`,
			promptHash: prompts.hash,
			probes: Math.max(1, opts.probes ?? 1),
			scope,
		});

		return new Scanner(
			scanId,
			opts,
			ledger,
			runner,
			prompts,
			repoRoot,
			repoName,
			repoId,
			revision,
			profile,
			scope,
			randomBytes(9).toString("hex"),
		);
	}

	/**
	 * Pick a failed or interrupted scan back up at the phase it stopped in.
	 * Phases already in the ledger are not redone; validate and attack-path
	 * skip individual candidates that already carry a verdict. Spend so far
	 * still counts against --max-cost, so a scan that died on budget needs a
	 * higher ceiling to get anywhere.
	 */
	static async resume(
		scanId: string,
		opts: Omit<ScannerOptions, "repo" | "profile"> = {},
	): Promise<Scanner> {
		loadEnv();
		const ledger = Ledger.open(opts.db);
		try {
			const scan = ledger.getScan(scanId);
			if (!scan) {
				throw new Error(
					`no scan '${scanId}' in this ledger. 'opensec report' lists the scans it knows.`,
				);
			}
			if (scan.status === "completed") {
				throw new Error(
					`scan ${scanId} already completed. 'opensec report ${scanId}' re-renders it.`,
				);
			}
			const repo = ledger.getRepo(scan.repo_id);
			if (!repo) throw new Error(`scan ${scanId} references a repo that is not in the ledger`);
			if (!existsSync(repo.path)) {
				throw new Error(`the repository this scan reviewed is gone: ${repo.path}`);
			}

			const prompts = loadPrompts(opts.promptsDir);
			const runner = await AgentRunner.create({ repoRoot: repo.path, modelRef: opts.model });
			Scanner.resolveEnforceable(runner, opts.maxCostUsd);

			const head = git(repo.path, ["rev-parse", "HEAD"]);
			if (scan.revision && head && head !== scan.revision) {
				opts.onEvent?.(
					`resume: the repo moved from ${scan.revision.slice(0, 8)} to ${head.slice(0, 8)} ` +
						`since this scan started — recorded line numbers may be stale`,
				);
			}

			ledger.reopenScan(scanId);
			opts.onEvent?.(`resuming ${scanId} at phase '${scan.phase}'`);

			const scope: ScanScope =
				scan.scope_kind === "diff" && scan.scope_base
					? { kind: "diff", base: scan.scope_base }
					: scan.scope_kind === "working_tree"
						? { kind: "working_tree" }
						: { kind: "repository" };

			return new Scanner(
				scanId,
				{ ...opts, repo: repo.path },
				ledger,
				runner,
				prompts,
				repo.path,
				repo.name,
				scan.repo_id,
				scan.revision,
				scan.profile,
				scope,
				randomBytes(9).toString("hex"),
				scan.phase,
			);
		} catch (err) {
			ledger.close();
			throw err;
		}
	}

	// Resolve the model up front so a bad ref fails here, not mid-scan after
	// money is spent. An unpriced model reports cost 0, so under a --max-cost
	// ceiling it would spend without ever counting.
	private static resolveEnforceable(runner: AgentRunner, maxCostUsd: number | null | undefined) {
		const model = runner.resolveModel(undefined).model;
		if (typeof maxCostUsd === "number" && !pricingOf(model)) {
			throw new Error(
				`--max-cost was given but '${model.provider}/${model.id}' has no pricing ` +
					`entry, so spend cannot be measured. Use --max-cost none to run without ` +
					`a ceiling, or add a price for this model.`,
			);
		}
		return model;
	}

	private ctx(workerId: string): RunContext {
		return {
			scanId: this.scanId,
			workerId,
			repoRoot: this.repoRoot,
			profile: this.profile,
			ledger: this.ledger,
			nonce: this.nonce,
			overflowDir: this.overflowDir(workerId),
		};
	}

	private overflowDir(workerId: string): string {
		return join(scanArtifactDir(this.scanId), "overflow", workerId.replaceAll("/", "_"));
	}

	private get concurrency(): number {
		return Math.max(1, this.opts.concurrency ?? 4);
	}

	/**
	 * Independent passes over the whole repository. One by default: each extra
	 * pass re-reviews every file with fresh agents, so it multiplies cost rather
	 * than dividing it, and what it buys is a second opinion.
	 */
	private get passes(): number {
		return Math.max(1, this.opts.probes ?? 1);
	}

	private say(msg: string): void {
		this.opts.onEvent?.(msg);
	}

	private bill(
		r: Pick<AgentRunResult, "tokensIn" | "tokensOut" | "costUsd"> &
			Partial<
				Pick<
					AgentRunResult,
					"inputTokens" | "cacheReadTokens" | "cacheWriteTokens" | "cacheCostUsd" | "cacheSavingsUsd"
				>
			>,
	): void {
		const cacheReadTokens = r.cacheReadTokens ?? 0;
		const cacheWriteTokens = r.cacheWriteTokens ?? 0;
		this.ledger.addUsage(this.scanId, {
			tokensIn: r.tokensIn,
			tokensOut: r.tokensOut,
			costUsd: r.costUsd,
			inputTokens: r.inputTokens ?? Math.max(0, r.tokensIn - cacheReadTokens - cacheWriteTokens),
			cacheReadTokens,
			cacheWriteTokens,
			cacheCostUsd: r.cacheCostUsd ?? 0,
			cacheSavingsUsd: r.cacheSavingsUsd ?? 0,
		});
	}

	private budgetAvailable(): boolean {
		const max = this.opts.maxCostUsd;
		return typeof max !== "number" || (this.ledger.getScan(this.scanId)?.cost_usd ?? 0) < max;
	}

	private async runAgent(args: RunArgs): Promise<AgentRunResult> {
		const result = await this.runner.run({
			...args,
			maxTurns: args.maxTurns ?? this.opts.maxTurns,
			onUsage: (usage) => {
				this.bill(usage);
				return this.budgetAvailable();
			},
		});
		if (result.stoppedAtTurnLimit) {
			this.say(
				`  ${args.ctx.workerId} hit the turn limit and was stopped — its work so far is ` +
					`recorded, but it did not finish. Raise --max-turns if this is real work.`,
			);
		}
		return result;
	}

	private subagentDeps(): SubagentDeps {
		return {
			prompts: this.prompts,
			run: (a) =>
				this.runner.run({
					...a,
					maxTurns: this.opts.maxTurns,
					onUsage: (usage) => {
						this.bill(usage);
						return this.budgetAvailable();
					},
				}),
			checkBudget: () => this.checkBudget(),
			tracePath: (w) => this.tracePath(w),
			onEvent: (m) => this.say(m),
		};
	}

	private tracePath(workerId: string): string {
		return join(scanArtifactDir(this.scanId), "traces", `${workerId}.jsonl`);
	}

	private checkBudget(): void {
		const max = this.opts.maxCostUsd;
		if (typeof max !== "number") return;
		const scan = this.ledger.getScan(this.scanId);
		const spent = scan?.cost_usd ?? 0;
		if (spent >= max) {
			throw new Error(
				`budget exhausted: spent $${spent.toFixed(4)} of $${max} at phase ` +
					`'${scan?.phase}'. Findings recorded so far are ` +
					`in the ledger; raise --max-cost to continue.`,
			);
		}
	}

	async inventory(): Promise<InventoryResult> {
		this.ledger.setPhase(this.scanId, "inventory");
		const include = await scopedPaths(this.repoRoot, this.scope);
		const inv = await inventory(this.repoRoot, {
			maxFiles: this.opts.maxFiles,
			exclude: this.opts.exclude,
			include,
		});
		this.ledger.insertFiles(
			this.scanId,
			inv.entries.map((e) => ({
				path: e.path,
				sha: e.sha,
				bytes: e.bytes,
				excludedReason: e.excludedReason,
			})),
		);
		this.partitions = partition(
			inv.inScope.map((f) => ({ path: f.path, bytes: f.bytes })),
			{ maxFiles: this.opts.partitionMaxFiles, maxPartitions: this.concurrency * 2 },
		);

		this.inv = inv;
		this.say(
			`inventory: ${inv.inScope.length} files in scope, ${inv.entries.length - inv.inScope.length} excluded` +
				(this.scope.kind === "diff" ? ` (diff from ${this.scope.base})` : this.scope.kind === "working_tree" ? " (working tree)" : ""),
		);
		for (const glob of inv.unusedExcludes) {
			// `--exclude peridot-dashboard` matches nothing, because entries are
			// files: it needed `peridot-dashboard/**`. Saying so beats scanning what
			// they meant to leave out and billing them for it.
			this.say(`  --exclude '${glob}' matched no file — check the pattern`);
		}
		return inv;
	}

	threatModelPath(): string {
		return join(homedir(), ".opensec", "repos", this.repoId, "threat-model.md");
	}

	async threatModel(): Promise<string> {
		this.ledger.setPhase(this.scanId, "threat_model");
		const path = this.threatModelPath();

		if (existsSync(path) && !this.opts.refreshThreatModel) {
			const stored = readFileSync(path, "utf8");
			const wroteAt = /^<!-- opensec threat model .*revision (\S+)/m.exec(stored)?.[1];
			this.ledger.setThreatModel(this.scanId, stored, `reused:${path}`);
			this.say(`threat model: reusing ${path} (edit it, or --refresh-threat-model to rewrite)`);
			if (wroteAt && wroteAt !== "none" && this.revision && wroteAt !== this.revision) {
				this.say(
					`  it was written at ${wroteAt.slice(0, 8)}, the repo is at ${this.revision.slice(0, 8)}`,
				);
			}
			// A threat model can also go stale sideways. It is stored per repository,
			// but scope is per run, so --exclude can leave one whose highest-risk
			// areas are all files this scan will not review — pointing every probe
			// at code it cannot file against. Say so rather than orient them wrongly.
			// Only when there is an inventory to compare against. Phases are
			// individually callable, and `new Set(undefined)` is empty — which would
			// report every file the model cites as out of scope, confidently and
			// wrongly, to anyone calling threatModel() on its own.
			const drift = this.inv
				? citedOutOfScope(stored, new Set(this.inv.inScope.map((f) => f.path)))
				: { cited: 0, outOfScope: 0 };
			if (drift.outOfScope > 0) {
				// Stated, not thresholded. A share is the wrong summary anyway — this
				// model spent its top two highest-risk areas on excluded files while
				// only 8 of 29 citations were out of scope, so any cutoff that keeps
				// quiet about a dependency mention also keeps quiet about that.
				this.say(
					`  ${drift.outOfScope} of the ${drift.cited} files it points at are outside ` +
						`this scan's scope`,
				);
			}
			return stored;
		}

		this.checkBudget();
		this.say("threat model: 1 agent");

		// The inventory, not the worklist: the threat model wants the shape of the
		// repository, and work.next now hands out unread files in batches, which
		// is a different question.
		const inScope = this.inv?.inScope ?? [];
		const files = inScope.slice(0, 200);
		const total = inScope.length;
		const result = await this.runAgent({
			ctx: { ...this.ctx("threat-model"), verbs: THREAT_MODEL_VERBS },
			onEvent: (m) => this.say(m),
			tracePath: this.tracePath("threat-model"),
			subagents: this.subagentDeps(),
			systemPrompt: this.prompts.get("threat-model.md"),
			prompt: [
				`Repository: ${this.repoName}`,
				`Files in scope: ${total}`,
				"",
				`Here are the first ${files.length} paths of ${total}. Read whatever you need.`,
				"",
				wrapUntrusted(this.nonce, "file-listing", files.map((f) => f.path).join("\n")),
				"",
				"Write the threat model now.",
			].join("\n"),
		});

		// Redacted on write only. This file is the user's to edit, so redacting it
		// again on read would silently eat their edits. The nonce is stripped for
		// the same reason it is stripped from tool inputs: this text goes back into
		// other agents' prompts inside wrapUntrusted fences that use the same
		// nonce, and the agent that wrote it saw that nonce in its own prompt.
		const text = stripControlChars(
			redactSecrets(result.text.replaceAll(this.nonce, "[nonce-stripped]")),
		);

		const header =
			`<!-- opensec threat model · repo ${this.repoName} · revision ${this.revision ?? "none"} ` +
			`· written ${new Date().toISOString()} -->\n` +
			`<!-- This file is yours to edit. The next scan of this repository reads it as\n` +
			`     written; opensec only rewrites it when you pass --refresh-threat-model. -->\n\n`;
		opensecDir("repos", this.repoId);
		writeFileSync(path, header + text, { encoding: "utf8", mode: 0o600 });
		chmodSync(path, 0o600);

		this.ledger.setThreatModel(this.scanId, text, `generated:${path}`);
		this.say(`threat model: written to ${path} — edit it and the next scan will use yours`);
		return text;
	}

	async discover(threatModel?: string): Promise<Candidate[]> {
		this.ledger.setPhase(this.scanId, "discovery");
		const tm = threatModel ?? this.ledger.getThreatModel(this.scanId) ?? "";
		this.checkBudget();

		if (!this.ledger.hasFiles(this.scanId)) {
			// Without this, a discover() with no inventory scans zero files and
			// reports a clean completed scan.
			throw new Error("discover() before inventory(): nothing is in scope yet. run() orders the phases.");
		}

		const parts = this.partitions ?? [];
		const passes = this.passes;
		this.say(
			`discovery: ${describeDistribution(parts)}` +
				(passes > 1 ? ` × ${passes} independent pass(es)` : "") +
				`, ${this.concurrency} at a time`,
		);

		// One agent per partition. The partition is the unit that fits in a
		// context; that is the whole reason it exists.
		const plan = parts.flatMap((part) =>
			Array.from({ length: passes }, (_, pass) => ({
				workerId: passes > 1 ? `probe-${part.id + 1}-p${pass + 1}` : `probe-${part.id + 1}`,
				paths: part.paths,
				readGroup: `pass-${pass + 1}`,
			})),
		);

		await mapConcurrent(plan, this.concurrency, async ({ workerId, paths, readGroup }) => {
			this.checkBudget();
			this.ledger.beginWorkerWork(this.scanId, workerId, paths);
			await this.runAgent({
				ctx: { ...this.ctx(workerId), verbs: PROBE_VERBS, worklist: paths, readGroup },
				onEvent: (m) => this.say(m),
				tracePath: this.tracePath(workerId),
				subagents: this.subagentDeps(),
				systemPrompt: this.prompts.get("probe.md"),
				prompt: [
					`You are ${workerId}. ${describeCompany(parts.length, passes)}`,
					"",
					"A threat model for this repository was written first. It was derived from",
					"the code under review, so treat it as orientation, not as fact:",
					"",
					wrapUntrusted(this.nonce, "threat-model", tm),
					"",
					'Begin by calling opensec({ verb: "work.next" }) to get your worklist.',
					"Page through it until remaining is 0. That covers the list; it is not",
					"where you stop. Keep going until a pass turns up nothing you had not",
					"already recorded, then report.",
				].join("\n"),
			});
			const progress = this.ledger.workerCoverage(this.scanId).find((p) => p.worker_id === workerId);
			this.say(
				`  ${workerId} ${progress?.completed ? "completed" : "stopped incomplete"} ` +
				`(${progress?.files_touched ?? 0}/${progress?.files_assigned ?? paths.length} files touched)`,
			);
		});

		const found = this.ledger.listCandidates(this.scanId);
		this.say(`discovery: ${found.length} candidate(s)`);
		return found;
	}

	async reduce(): Promise<number> {
		this.ledger.setPhase(this.scanId, "reduce");

		const live = this.ledger.listLiveCandidates(this.scanId).filter((c) => !c.resolution);
		const groups = collisionGroups(live);
		if (groups.length === 0) {
			if (live.length > 1) this.say(`reduce: ${live.length} candidate(s), no collisions`);
			return 0;
		}

		const inGroups = groups.reduce((n, g) => n + g.length, 0);
		this.say(
			`reduce: ${inGroups} of ${live.length} candidate(s) collide, in ${groups.length} group(s)`,
		);

		await mapConcurrent(groups, this.concurrency, async (group, i) => {
			this.checkBudget();
			const workerId = `reduce-${i + 1}`;
			await this.runAgent({
				ctx: {
					...this.ctx(workerId),
					verbs: REDUCE_VERBS,
					resolvableIds: group.map((c) => c.id),
					dispositions: ["duplicate"],
				},
				onEvent: (m) => this.say(m),
				tracePath: this.tracePath(workerId),
				systemPrompt: this.prompts.get("reduce.md"),
				prompt: [
					`${group.length} candidates in the same class and the same file.`,
					"They have not been validated. Your only question is whether any of them",
					"are the same finding.",
					"",
					wrapUntrusted(this.nonce, "candidates", group.map(describeCandidate).join("\n\n---\n\n")),
					"",
					"Merge what one patch would fix. If nothing here is a duplicate, say so",
					"and record nothing.",
				].join("\n"),
			});
		});

		const merged = this.ledger.listCandidates(this.scanId).filter((c) => c.merged_into).length;
		this.say(`reduce: ${merged} row(s) merged`);
		return merged;
	}

	async validate(candidates?: Candidate[]): Promise<void> {
		this.ledger.setPhase(this.scanId, "validate");
		const todo = (candidates ?? this.ledger.listLiveCandidates(this.scanId)).filter(
			(c) => !c.resolution?.validation,
		);
		if (todo.length === 0) return;
		this.say(`validate: ${todo.length} candidate(s), ${this.concurrency} at a time`);

		await mapConcurrent(todo, this.concurrency, async (c) => {
			this.checkBudget();
			const workerId = `validate-${c.id}`;
			await this.runAgent({
				ctx: {
					...this.ctx(workerId),
					verbs: VALIDATE_VERBS,
					resolvableIds: [c.id],
					dispositions: ["confirmed", "not_applicable", "needs_follow_up"],
				},
				onEvent: (m) => this.say(m),
				tracePath: this.tracePath(workerId),
				subagents: this.subagentDeps(),
				systemPrompt: this.prompts.get("validate.md"),
				prompt: [
					`Candidate ${c.id}, filed by ${c.worker_id}.`,
					"",
					wrapUntrusted(this.nonce, `candidate-${c.id}`, describeCandidate(c)),
					"",
					"You have no shell — this is a static review.",
					"",
					`Decide, then call opensec({ verb: "candidate.validate", id: "${c.id}", ... }) once.`,
				].join("\n"),
			});

			const after = this.ledger.getCandidate(this.scanId, c.id);
			if (after && !after.resolution?.validation) {
				this.ledger.resolveCandidate(this.scanId, c.id, {
					disposition: "needs_follow_up",
					rationale: "the validate agent finished without recording a verdict",
				});
				this.say(`  ${c.id} → needs_follow_up (no verdict recorded)`);
			} else {
				this.say(`  ${c.id} → ${after?.resolution?.validation?.disposition}  ${c.title}`);
			}
		});
	}

	async assess(): Promise<void> {
		this.ledger.setPhase(this.scanId, "attack_path");
		const todo = this.ledger
			.listLiveCandidates(this.scanId)
			.filter((c) => c.resolution?.validation?.disposition === "confirmed" && !c.resolution.computed);
		if (todo.length === 0) return;
		this.say(`attack path: ${todo.length} confirmed finding(s), ${this.concurrency} at a time`);

		await mapConcurrent(todo, this.concurrency, async (c) => {
			this.checkBudget();
			const workerId = `attack-path-${c.id}`;
			await this.runAgent({
				ctx: {
					...this.ctx(workerId),
					verbs: ASSESS_VERBS,
					resolvableIds: [c.id],
				},
				onEvent: (m) => this.say(m),
				tracePath: this.tracePath(workerId),
				subagents: this.subagentDeps(),
				systemPrompt: [
					this.prompts.get("attack-path.md"),
					"",
					this.prompts.get("refs/counterevidence.md"),
				].join("\n"),
				prompt: [
					`Candidate ${c.id}. Another reader has confirmed it is real.`,
					"",
					wrapUntrusted(this.nonce, `candidate-${c.id}`, describeCandidate(c)),
					"",
					"You have no shell — this is a static review. Nothing you conclude may",
					"claim execution, and `code_execution_proven` must be false.",
					"",
					`Trace it, then call opensec({ verb: "candidate.assess", id: "${c.id}", ... }) once.`,
				].join("\n"),
			});

			const after = this.ledger.getCandidate(this.scanId, c.id);
			if (after && !after.resolution?.attack_path) {
				this.ledger.resolveCandidate(this.scanId, c.id, {
					...(after.resolution ?? { disposition: "needs_follow_up", rationale: "" }),
					disposition: "needs_follow_up",
					rationale: "confirmed as real, but the attack-path pass recorded no rating",
				});
				this.say(`  ${c.id} → needs_follow_up (confirmed but unrated)`);
			} else {
				const sev = after?.resolution?.computed?.severity;
				this.say(
					`  ${c.id} → ${after?.resolution?.disposition}${sev ? ` (${sev})` : ""}  ${c.title}`,
				);
			}
		});
	}

	report(): ScanResult {
		this.ledger.setPhase(this.scanId, "report");
		return reportScan(this.ledger, this.scanId);
	}

	async run(): Promise<ScanResult> {
		// A resumed scan re-enters at startPhase; everything before it is already
		// in the ledger. Validate and assess always run — they skip individual
		// candidates that already carry a verdict, so on resume they only do what
		// is left.
		const skip = (p: Phase) => phaseBefore(p, this.startPhase);
		try {
			if (skip("inventory")) {
				this.partitions = partition(
					this.ledger.listInScopePaths(this.scanId).map((path) => ({ path, bytes: 0 })),
					{ maxFiles: this.opts.partitionMaxFiles, maxPartitions: this.concurrency * 2 },
				);
				this.say(
					`inventory: kept from the interrupted run — ` +
						`${this.ledger.coverage(this.scanId).files_in_scope} files in scope`,
				);
			} else {
				await this.inventory();
			}
			if (this.ledger.coverage(this.scanId).files_in_scope === 0) {
				this.say("inventory: no source files in scope — writing an empty report without calling agents");
				const result = this.report();
				this.ledger.finishScan(this.scanId, "completed");
				return result;
			}
			let tm: string | undefined;
			if (!skip("threat_model")) tm = await this.threatModel();
			if (!skip("discovery")) await this.discover(tm);
			if (!skip("reduce")) await this.reduce();
			await this.validate();
			await this.assess();
			const result = this.report();
			this.ledger.finishScan(this.scanId, "completed");
			return result;
		} catch (err) {
			this.ledger.finishScan(this.scanId, "failed");
			this.say(
				`scan failed — everything recorded so far is kept. ` +
					`'opensec resume ${this.scanId}' picks it back up; ` +
					`'opensec report ${this.scanId}' renders what exists.`,
			);
			throw err;
		}
	}

	static async estimate(opts: {
		repo: string;
		maxFiles?: number;
		exclude?: readonly string[];
		scope?: ScanScope;
	}): Promise<{ files: number; bytes: number; approxTokens: number; extensions: string[] }> {
		const root = resolve(opts.repo);
		const inv = await inventory(root, {
			maxFiles: opts.maxFiles,
			exclude: opts.exclude,
			include: await scopedPaths(root, opts.scope ?? { kind: "repository" }),
		});
		const bytes = inv.inScope.reduce((n, f) => n + f.bytes, 0);
		return {
			files: inv.inScope.length,
			bytes,
			approxTokens: Math.round(bytes / 3.6),
			extensions: inv.extensions,
		};
	}

	close(): void {
		this.ledger.close();
	}
}

/**
 * Render a scan's report from the ledger alone — no agents, no repo access, no
 * model. This is what makes a failed scan's work recoverable: everything the
 * report needs was recorded as it happened.
 */
export function reportScan(ledger: Ledger, scanId: string): ScanResult {
	const scan = ledger.getScan(scanId);
	if (!scan) {
		throw new Error(`no scan '${scanId}' in this ledger. 'opensec report' lists the scans it knows.`);
	}
	const repo = ledger.getRepo(scan.repo_id);
	const candidates = ledger.listCandidates(scanId);
	const coverage = ledger.coverage(scanId);
	const probeCoverage = ledger.workerCoverage(scanId);
	const extensions = [
		...new Set(ledger.listInScopePaths(scanId).map(ext).filter(Boolean)),
	].sort();

	const markdown = renderMarkdown({
		scan,
		repoName: repo?.name ?? scan.repo_id,
		repoPath: repo?.path ?? "(unknown)",
		candidates,
		coverage,
		probeCoverage,
		leads: ledger.listLeads(scanId),
		extensions,
		excludedFiles: ledger.excludedCount(scanId),
		modelRef: scan.model_ref ?? "(not recorded)",
		promptHash: scan.prompt_hash ?? "(not recorded)",
		// Part of reading the coverage number: one probe reaching every file
		// and four independently reaching every file are the same 100%, and
		// only the second means the repository was looked at four ways.
		ownership: scan.probes
			? `${scan.probes} probe(s), each over all ${coverage.files_in_scope} files`
			: undefined,
		threatModel: threatModelNote(scan.threat_model_source),
	});

	const dir = opensecDir("scans", scanId);
	const reportPath = join(dir, "report.md");
	const jsonPath = join(dir, "findings.json");
	writeFileSync(reportPath, markdown, { encoding: "utf8", mode: 0o600 });
	writeFileSync(
		jsonPath,
		JSON.stringify(
			{
				scan,
				coverage,
				probeCoverage,
				candidates,
			},
			null,
			2,
		),
		{
		encoding: "utf8",
		mode: 0o600,
		},
	);

	return { scanId, markdown, reportPath, jsonPath, candidates, coverage };
}

function threatModelNote(source: string | null): string | undefined {
	if (!source) return undefined;
	const sep = source.indexOf(":");
	const kind = sep === -1 ? source : source.slice(0, sep);
	const path = sep === -1 ? "" : source.slice(sep + 1);
	if (kind === "reused") return `reused from \`${path}\``;
	if (kind === "generated") return `written this run, saved to \`${path}\``;
	return source;
}

function formatLocation(l: {
	path: string;
	start_line: number;
	end_line: number;
	symbol?: string;
	role?: string;
}): string {
	return (
		`${l.path}:${l.start_line}-${l.end_line}` +
		`${l.symbol ? ` (${l.symbol})` : ""}${l.role ? ` [${l.role}]` : ""}`
	);
}

function describeCandidate(c: Candidate): string {
	return [
		`id: ${c.id}`,
		`title: ${c.title}`,
		`cwe: ${c.cwe_ids.length ? c.cwe_ids.join(", ") : "(none assigned)"}`,
		...(c.instance ? [`instance: ${c.instance}`] : []),
		"locations:",
		c.locations.map((l) => `  ${formatLocation(l)}`).join("\n"),
		"",
		"summary:",
		c.summary,
		"",
		"evidence as filed:",
		c.evidence,
	].join("\n");
}

/**
 * What a probe is told about the others.
 *
 * Probes overlap completely, so they need to hear that filing something a
 * sibling probably also found is the correct move. Left to itself a model
 * reasons that four reviewers on one repository make its own report redundant,
 * and that is the one belief that would make this arrangement worse than the
 * split worklists it replaced. The converse matters too: probes agreeing is a
 * property of the search, not evidence about the finding, and nothing
 * downstream treats it as such.
 */
function describeCompany(parts: number, passes: number): string {
	const bits: string[] = [];
	if (parts > 1) {
		bits.push(
			`There are ${parts} probes on this repository; you are accountable for your own ` +
				`worklist only, but you may read anything.`,
		);
	}
	if (passes > 1) {
		// Passes overlap completely, so a probe needs to hear that filing what a
		// sibling probably also found is correct. The converse matters too:
		// agreement is a property of the search, not evidence about the finding.
		bits.push(
			`This repository is being reviewed ${passes} times over, independently. Someone else ` +
				`may file what you file — do it anyway. Duplicates are merged, and two probes ` +
				`agreeing is not evidence that a finding is real.`,
		);
	}
	return bits.join(" ");
}

/**
 * How much of a stored threat model points outside this scan.
 *
 * Paths are pulled out of the prose rather than tracked, because the file is
 * the user's to edit and anything we required them to maintain would rot.
 */
export function citedOutOfScope(
	text: string,
	inScope: ReadonlySet<string>,
): { cited: number; outOfScope: number } {
	const paths = new Set(
		(text.match(/[A-Za-z0-9_@./-]+\.[A-Za-z0-9]{1,5}(?=[:`\s,)]|$)/g) ?? [])
			.map((p) => p.replace(/^[./]+/, ""))
			.filter((p) => p.includes("/")),
	);
	let outOfScope = 0;
	for (const p of paths) if (!inScope.has(p)) outOfScope++;
	return { cited: paths.size, outOfScope };
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
