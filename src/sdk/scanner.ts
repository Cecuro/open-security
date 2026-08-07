import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";

import { AgentRunner, type AgentRunResult, pricingOf, type RunArgs } from "../agents/session.js";
import type { SubagentDeps } from "../agents/subagent.js";
import {
	ASSESS_VERBS,
	PROBE_VERBS,
	REDUCE_VERBS,
	type RunContext,
	VALIDATE_VERBS,
} from "../agents/tool.js";
import { Ledger, opensecDir, scanArtifactDir, shortHash } from "../db/db.js";
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
import { redactSecrets, stripControlChars } from "../text.js";
import type { Candidate, Coverage, Profile } from "../types.js";

export interface ScannerOptions {
	repo: string;
	model?: string;
	models?: Partial<
		Record<"threatModel" | "discovery" | "reduce" | "validate" | "attackPath", string>
	>;
	db?: string;
	profile?: Profile;
	promptsDir?: string;
	maxFiles?: number;
	maxCostUsd?: number | null;
	partitionMaxFiles?: number;
	concurrency?: number;
	maxTurns?: number;
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
			throw new Error(
				"--profile container is not implemented yet (M2). Use --profile static.",
			);
		}

		const prompts = loadPrompts(opts.promptsDir);
		const ledger = Ledger.open(opts.db);
		const runner = await AgentRunner.create({ repoRoot, modelRef: opts.model });
		const model = runner.resolveModel(undefined).model;

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
			overflowDir: this.overflowDir(workerId),
		};
	}

	private overflowDir(workerId: string): string {
		return join(scanArtifactDir(this.scanId), "overflow", workerId.replaceAll("/", "_"));
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

	private async runAgent(args: RunArgs): Promise<AgentRunResult> {
		const result = await this.runner.run({
			...args,
			maxTurns: args.maxTurns ?? this.opts.maxTurns,
		});
		this.bill(result);
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
			run: (a) => this.runner.run({ ...a, maxTurns: this.opts.maxTurns }),
			checkBudget: () => this.checkBudget(),
			bill: (r) => this.bill(r),
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
		const spent = this.ledger.getScan(this.scanId)?.cost_usd ?? 0;
		if (spent >= max) {
			throw new Error(
				`budget exhausted: spent $${spent.toFixed(4)} of $${max} at phase ` +
					`'${this.ledger.getScan(this.scanId)?.phase}'. Findings recorded so far are ` +
					`in the ledger; raise --max-cost to continue.`,
			);
		}
	}

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
				this.say(
					`  it was written at ${wroteAt.slice(0, 8)}, the repo is at ${this.revision.slice(0, 8)}`,
				);
			}
			return stored;
		}

		this.checkBudget();
		this.say("threat model: 1 agent");

		const { files, total } = this.ledger.listWork(this.scanId, 200, 0);
		const result = await this.runAgent({
			ctx: this.ctx("threat-model"),
			onEvent: (m) => this.say(m),
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

		// Redacted on write only. This file is the user's to edit, so redacting it
		// again on read would silently eat their edits.
		const text = stripControlChars(redactSecrets(result.text));

		const header =
			`<!-- opensec threat model · repo ${this.repoName} · revision ${this.revision ?? "none"} ` +
			`· written ${new Date().toISOString()} -->\n` +
			`<!-- This file is yours to edit. The next scan of this repository reads it as\n` +
			`     written; opensec only rewrites it when you pass --refresh-threat-model. -->\n\n`;
		opensecDir("repos", this.repoId);
		writeFileSync(path, header + text, { encoding: "utf8", mode: 0o600 });
		chmodSync(path, 0o600);

		this.ledger.setThreatModel(this.scanId, text, `generated:${path}`);
		this.threatModelNote = `written this run, saved to \`${path}\``;
		this.say(`threat model: written to ${path} — edit it and the next scan will use yours`);
		return text;
	}

	async discover(threatModel?: string): Promise<Candidate[]> {
		this.ledger.setPhase(this.scanId, "discovery");
		const tm = threatModel ?? this.ledger.getThreatModel(this.scanId) ?? "";
		this.checkBudget();

		const parts = this.partitions ?? [{ id: 0, paths: [], bytes: 0 }];
		this.say(`discovery: ${describeDistribution(parts)}, ${this.concurrency} at a time`);

		await mapConcurrent(parts, this.concurrency, async (part) => {
			this.checkBudget();
			const workerId = `probe-${part.id + 1}`;
			const result = await this.runAgent({
				ctx: { ...this.ctx(workerId), partitionId: part.id, verbs: PROBE_VERBS },
				onEvent: (m) => this.say(m),
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
			this.say(`  ${workerId} done`);
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
			const result = await this.runAgent({
				ctx: {
					...this.ctx(workerId),
					verbs: REDUCE_VERBS,
					resolvableIds: group.map((c) => c.id),
					dispositions: ["duplicate"],
				},
				onEvent: (m) => this.say(m),
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
			const result = await this.runAgent({
				ctx: {
					...this.ctx(workerId),
					verbs: VALIDATE_VERBS,
					resolvableIds: [c.id],
					dispositions: ["confirmed", "not_applicable", "needs_follow_up"],
				},
				onEvent: (m) => this.say(m),
				tracePath: this.tracePath(workerId),
				subagents: this.subagentDeps(),
				modelRef: this.opts.models?.validate,
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
			const result = await this.runAgent({
				ctx: {
					...this.ctx(workerId),
					verbs: ASSESS_VERBS,
					resolvableIds: [c.id],
				},
				onEvent: (m) => this.say(m),
				tracePath: this.tracePath(workerId),
				subagents: this.subagentDeps(),
				modelRef: this.opts.models?.attackPath,
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

		const dir = opensecDir("scans", this.scanId);
		const reportPath = join(dir, "report.md");
		const jsonPath = join(dir, "findings.json");
		writeFileSync(reportPath, markdown, { encoding: "utf8", mode: 0o600 });
		writeFileSync(jsonPath, JSON.stringify({ scan, coverage, candidates }, null, 2), {
			encoding: "utf8",
			mode: 0o600,
		});

		return { scanId: this.scanId, markdown, reportPath, jsonPath, candidates, coverage };
	}

	async run(): Promise<ScanResult> {
		try {
			await this.inventory();
			const tm = await this.threatModel();
			await this.discover(tm);
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
