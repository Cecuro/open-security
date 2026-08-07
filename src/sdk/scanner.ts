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
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";

import { AgentRunner, pricingOf } from "../agents/session.js";
import type { SubagentDeps } from "../agents/subagent.js";
import {
	ASSESS_VERBS,
	PROBE_VERBS,
	REDUCE_VERBS,
	type RunContext,
	VALIDATE_VERBS,
} from "../agents/tool.js";
import { Ledger, scanArtifactDir, shortHash } from "../db/db.js";
import { collisionGroups } from "../scan/identity.js";
import { inventory, type InventoryResult } from "../scan/inventory.js";
import {
	describeDistribution,
	mapConcurrent,
	partition,
	type Partition,
} from "../scan/partition.js";
import { loadPrompts, type Prompts, wrapUntrusted } from "../scan/prompts.js";
import { renderMarkdown } from "../scan/render.js";
import type { Candidate, Coverage, Profile } from "../types.js";

export interface ScannerOptions {
	repo: string;
	/** e.g. "azure-openai-responses/gpt-5.4". Required — nothing is guessed. */
	model?: string;
	/** Per-phase overrides; each falls back to `model`. */
	models?: Partial<
		Record<"threatModel" | "discovery" | "reduce" | "validate" | "attackPath", string>
	>;
	db?: string;
	profile?: Profile;
	promptsDir?: string;
	maxFiles?: number;
	/**
	 * Spend ceiling in USD. `null` is the explicit opt-out; omitted means the
	 * same for now. A model with no pricing entry refuses to start under a
	 * budget rather than running unbounded (plan §8).
	 */
	maxCostUsd?: number | null;
	/** Files per probe before the worklist is split again. */
	partitionMaxFiles?: number;
	/** How many agents run at once, across probes and per-candidate passes. */
	concurrency?: number;
	/**
	 * Regenerate the stored threat model instead of reusing it. The stored one is
	 * a file the user is invited to edit, so overwriting it is never implicit.
	 */
	refreshThreatModel?: boolean;
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
	private partitions?: Partition[];
	private threatModelNote?: string;

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
		const model = runner.resolveModel(undefined).model;

		// A budget you cannot price is not a budget (plan §8). Refusing to start
		// is the honest failure; running unbounded while printing a limit is not.
		if (typeof opts.maxCostUsd === "number" && !pricingOf(model)) {
			throw new Error(
				`--max-cost was given but '${model.provider}/${model.id}' has no pricing entry, ` +
					`so spend cannot be measured. Use --max-cost none to run without a ceiling, ` +
					`or add a price for this model.`,
			);
		}

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
			repoId,
			revision,
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

	private get concurrency(): number {
		return Math.max(1, this.opts.concurrency ?? 4);
	}

	private say(msg: string): void {
		this.opts.onEvent?.(msg);
	}

	private bill(r: { tokensIn: number; tokensOut: number; costUsd: number }): void {
		this.ledger.addUsage(this.scanId, r.tokensIn, r.tokensOut, r.costUsd);
	}

	/**
	 * Handed to the phases that benefit from delegation. threat-model and dedup
	 * do not get it: one is orientation, the other is a comparison over rows that
	 * are already in front of it.
	 */
	private subagentDeps(): SubagentDeps {
		return {
			prompts: this.prompts,
			run: (a) => this.runner.run(a),
			checkBudget: () => this.checkBudget(),
			bill: (r) => this.bill(r),
			tracePath: (w) => this.tracePath(w),
			onEvent: (m) => this.say(m),
		};
	}

	/** Where this run's agent transcripts go. In-memory sessions leave nothing otherwise. */
	private tracePath(workerId: string): string {
		return join(scanArtifactDir(this.scanId), "traces", `${workerId}.jsonl`);
	}

	/**
	 * Checked between phases and between candidates, not mid-stream. That means
	 * the ceiling can be overshot by one agent run, so it is reported as "spent X
	 * of Y" rather than presented as a hard cap.
	 */
	private checkBudget(): void {
		const max = this.opts.maxCostUsd;
		if (typeof max !== "number") return;
		const spent = this.ledger.getScan(this.scanId)?.cost_usd ?? 0;
		if (spent >= max) {
			throw new Error(
				`budget exhausted: spent $${spent.toFixed(4)} of $${max} at phase ` +
					`'${this.ledger.getScan(this.scanId)?.phase}'. Findings recorded so far are ` +
					`in the ledger; raise --max-cost to continue.`,
			);
		}
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
		this.partitions = partition(
			inv.inScope.map((f) => ({ path: f.path, bytes: f.bytes })),
			{ maxFiles: this.opts.partitionMaxFiles, maxPartitions: this.concurrency * 2 },
		);
		this.ledger.assignPartitions(this.scanId, this.partitions);

		this.inv = inv;
		this.say(
			`inventory: ${inv.inScope.length} files in scope, ${inv.entries.length - inv.inScope.length} excluded`,
		);
		return inv;
	}

	// ------------------------------------------------------------- phase 1

	/**
	 * Where this repository's threat model lives between scans. It is a plain
	 * markdown file outside the database on purpose: a threat model is the one
	 * artifact a user has standing to correct — they know what the system is for,
	 * which entry points are actually exposed, and which "sensitive asset" is
	 * test data. Editing a row in SQLite is not an invitation; editing a file is.
	 */
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
			this.threatModelNote = `reused from \`${path}\``;
			this.say(`threat model: reusing ${path} (edit it, or --refresh-threat-model to rewrite)`);
			if (wroteAt && wroteAt !== "none" && this.revision && wroteAt !== this.revision) {
				// Reused anyway: a threat model written two commits ago is still a far
				// better starting point than none, and the user is told so they can
				// decide. Refusing to reuse would punish exactly the users who edited it.
				this.say(
					`  it was written at ${wroteAt.slice(0, 8)}, the repo is at ${this.revision.slice(0, 8)}`,
				);
			}
			return stored;
		}

		this.checkBudget();
		this.say("threat model: 1 agent");

		const { files, total } = this.ledger.listWork(this.scanId, 200, 0);
		const result = await this.runner.run({
			ctx: this.ctx("threat-model"),
			tracePath: this.tracePath("threat-model"),
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

		const header =
			`<!-- opensec threat model · repo ${this.repoName} · revision ${this.revision ?? "none"} ` +
			`· written ${new Date().toISOString()} -->\n` +
			`<!-- This file is yours to edit. The next scan of this repository reads it as\n` +
			`     written; opensec only rewrites it when you pass --refresh-threat-model. -->\n\n`;
		mkdirSync(dirname(path), { recursive: true });
		writeFileSync(path, header + result.text, "utf8");

		this.ledger.setThreatModel(this.scanId, result.text, `generated:${path}`);
		this.threatModelNote = `written this run, saved to \`${path}\``;
		this.say(`threat model: written to ${path} — edit it and the next scan will use yours`);
		return result.text;
	}

	// ------------------------------------------------------------- phase 2

	async discover(threatModel?: string): Promise<Candidate[]> {
		this.ledger.setPhase(this.scanId, "discovery");
		const tm = threatModel ?? this.ledger.getThreatModel(this.scanId) ?? "";
		this.checkBudget();

		const parts = this.partitions ?? [{ id: 0, paths: [], bytes: 0 }];
		this.say(`discovery: ${describeDistribution(parts)}, ${this.concurrency} at a time`);

		await mapConcurrent(parts, this.concurrency, async (part) => {
			this.checkBudget();
			const workerId = `probe-${part.id + 1}`;
			const result = await this.runner.run({
				ctx: { ...this.ctx(workerId), partitionId: part.id, verbs: PROBE_VERBS },
				tracePath: this.tracePath(workerId),
				subagents: this.subagentDeps(),
				modelRef: this.opts.models?.discovery,
				systemPrompt: this.prompts.get("probe.md"),
				prompt: [
					`You are ${workerId}. ${parts.length > 1 ? `There are ${parts.length} probes on this repository; you are accountable for your own worklist only, but you may read anything.` : ""}`,
					"",
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
			this.say(`  ${workerId} done`);
		});

		const found = this.ledger.listCandidates(this.scanId);
		this.say(`discovery: ${found.length} candidate(s)`);
		return found;
	}

	// ------------------------------------------------------------- phase 3

	/**
	 * Dedup, second layer. The first is free and already happened: identical
	 * identities collapsed at `candidate.create`. This one reads.
	 *
	 * A model only sees groups that collide on (cwe family, primary file) and
	 * hold more than one row — usually none, on most scans, which is the point.
	 * Singleton findings never cost a token, and each group is judged on its own
	 * so one large group cannot bury a small one in the context.
	 *
	 * It runs BEFORE validation, so a duplicate is never investigated twice. It
	 * may set `duplicate` and nothing else: these rows have not been judged by
	 * anyone yet, and a reducer that could mark one `not_applicable` would drop a
	 * finding no one ever read.
	 */
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
			const result = await this.runner.run({
				ctx: {
					...this.ctx(workerId),
					verbs: REDUCE_VERBS,
					resolvableIds: group.map((c) => c.id),
					dispositions: ["duplicate"],
				},
				tracePath: this.tracePath(workerId),
				modelRef: this.opts.models?.reduce,
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
			this.bill(result);
		});

		const merged = this.ledger.listCandidates(this.scanId).filter((c) => c.merged_into).length;
		this.say(`reduce: ${merged} row(s) merged`);
		return merged;
	}

	// ------------------------------------------------------------ phase 3a

	/** Is it real? One agent per candidate, no severity, no reachability. */
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
			const result = await this.runner.run({
				ctx: {
					...this.ctx(workerId),
					verbs: VALIDATE_VERBS,
					resolvableIds: [c.id],
					// Not duplicate: the reducer already ran, and re-merging here would
					// let one agent that never saw the other row delete it.
					dispositions: ["confirmed", "not_applicable", "needs_follow_up"],
				},
				tracePath: this.tracePath(workerId),
				subagents: this.subagentDeps(),
				modelRef: this.opts.models?.validate,
				systemPrompt: [
					this.prompts.get("validate.md"),
					"",
					this.prompts.get("refs/counterevidence.md"),
				].join("\n"),
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
			this.bill(result);

			// Degradation is directional: an agent that returned without a verdict
			// leaves the row unsettled, which downgrades the scan's claim rather than
			// quietly dropping the candidate (plan §4).
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

	// ------------------------------------------------------------ phase 3b

	/**
	 * How far does it reach? Survivors only, and a fresh agent — one that has not
	 * seen the validating agent's reasoning, so it cannot inherit its confidence.
	 * This is where the reachability trace and the severity inputs are recorded.
	 */
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
			const result = await this.runner.run({
				ctx: {
					...this.ctx(workerId),
					verbs: ASSESS_VERBS,
					resolvableIds: [c.id],
				},
				tracePath: this.tracePath(workerId),
				subagents: this.subagentDeps(),
				modelRef: this.opts.models?.attackPath,
				systemPrompt: this.prompts.get("attack-path.md"),
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
			this.bill(result);

			const after = this.ledger.getCandidate(this.scanId, c.id);
			if (after && !after.resolution?.attack_path) {
				// The finding is real — validation said so — but nothing rated it. It
				// stays in the report as unsettled rather than as a confirmed finding
				// with no severity behind it.
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
			partitions: this.partitions ? describeDistribution(this.partitions) : undefined,
			threatModel: this.threatModelNote,
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
			await this.discover(tm);
			// Merge before judging, so no duplicate is investigated twice; judge
			// before rating, so nothing unreal is ever assigned a severity.
			await this.reduce();
			await this.validate();
			await this.assess();
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

/** One candidate as the later phases see it. Always wrapped as untrusted. */
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
