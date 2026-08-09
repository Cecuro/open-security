import { chmodSync, mkdirSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
	createAgentSession,
	createFindToolDefinition,
	createGrepToolDefinition,
	createLsToolDefinition,
	createReadToolDefinition,
	DefaultResourceLoader,
	getAgentDir,
	ModelRuntime,
	resolveCliModel,
	SessionManager,
	SettingsManager,
	type ToolDefinition,
} from "@earendil-works/pi-coding-agent";
import type { TSchema } from "typebox";

import { opensecDir } from "../db/db.js";
import { createSubagentTool, type SubagentDeps } from "./subagent.js";
import { createOpensecTool, type RunContext } from "./tool.js";

export interface AgentRunResult {
	text: string;
	/** All prompt tokens, including the provider's cache read/write buckets. */
	tokensIn: number;
	tokensOut: number;
	costUsd: number;
	/** PI reports these separately from ordinary input. */
	inputTokens: number;
	cacheReadTokens: number;
	cacheWriteTokens: number;
	cacheCostUsd: number;
	/** What cache reads saved relative to the same tokens at the input rate. */
	cacheSavingsUsd: number;
	stoppedAtTurnLimit?: boolean;
}

// Not redundant with --max-cost: the budget is only checked between agent runs,
// so nothing else bounds a single agent that loops on grep.
export const DEFAULT_MAX_TURNS = 80;

export interface RunArgs {
	ctx: RunContext;
	systemPrompt: string;
	prompt: string;
	modelRef?: string;
	tracePath?: string;
	subagents?: SubagentDeps;
	onEvent?: (msg: string) => void;
	maxTurns?: number;
}

type CliModelResult = ReturnType<typeof resolveCliModel>;
export type ResolvedModel = Omit<CliModelResult, "model"> & {
	model: NonNullable<CliModelResult["model"]>;
};

export interface ModelPricing {
	input: number;
	output: number;
}

export function pricingOf(model: { cost?: ModelPricing }): ModelPricing | null {
	const c = model.cost;
	if (!c || (c.input === 0 && c.output === 0)) return null;
	return c;
}

function agentWorkDir(): string {
	return opensecDir("agent");
}

export class AgentRunner {
	private constructor(
		private readonly runtime: ModelRuntime,
		private readonly defaultModelRef: string | undefined,
		private readonly repoRoot: string,
	) {}

	static async create(opts: { repoRoot: string; modelRef?: string }): Promise<AgentRunner> {
		const runtime = await ModelRuntime.create();
		return new AgentRunner(runtime, opts.modelRef, opts.repoRoot);
	}

	resolveModel(ref: string | undefined): ResolvedModel {
		const wanted = ref ?? this.defaultModelRef;
		const res = resolveCliModel({ cliModel: wanted, modelRuntime: this.runtime });
		if (res.error || !res.model) {
			throw new Error(
				res.error ??
					`could not resolve model '${wanted ?? "(default)"}'. ` +
						`Set --model provider/model, e.g. --model azure-openai-responses/gpt-5.4`,
			);
		}
		return { ...res, model: res.model };
	}

	async run(args: RunArgs): Promise<AgentRunResult> {
		const { ctx } = args;
		const resolved = this.resolveModel(args.modelRef);
		const workDir = agentWorkDir();

		// Load-bearing, and nothing tests it: pi trusts <project>/.pi/settings.json
		// and spawns its npmCommand, and splices .pi/APPEND_SYSTEM.md above our
		// system prompt. cwd is a directory we own, never the scanned repo.
		const settingsManager = SettingsManager.inMemory({}, { projectTrusted: false });
		const resourceLoader = new DefaultResourceLoader({
			cwd: workDir,
			agentDir: getAgentDir(),
			settingsManager,
			noContextFiles: true,
			noExtensions: true,
			noSkills: true,
			noPromptTemplates: true,
			noThemes: true,
			systemPrompt: args.systemPrompt,
			appendSystemPrompt: [],
		});
		await resourceLoader.reload();

		const tools: AnyToolDef[] = [
			instrumentRead(confine(createReadToolDefinition(this.repoRoot) as AnyToolDef, ctx), ctx),
			instrumentGrep(confine(createGrepToolDefinition(this.repoRoot) as AnyToolDef, ctx), ctx),
			confine(createFindToolDefinition(this.repoRoot) as AnyToolDef, ctx),
			confine(createLsToolDefinition(this.repoRoot) as AnyToolDef, ctx),
			createOpensecTool(ctx) as AnyToolDef,
		];

		if (args.subagents) {
			const delegate = createSubagentTool(ctx, args.subagents);
			if (delegate) tools.push(delegate as AnyToolDef);
		}

		const { session } = await createAgentSession({
			cwd: workDir,
			model: resolved.model,
			thinkingLevel: resolved.thinkingLevel,
			modelRuntime: this.runtime,
			resourceLoader,
			settingsManager,
			sessionManager: SessionManager.inMemory(),
			noTools: "builtin",
			customTools: tools,
		});

		const failures: string[] = [];
		const maxTurns = args.maxTurns ?? DEFAULT_MAX_TURNS;
		let turns = 0;
		let stoppedAtTurnLimit = false;

		const unsubscribe = session.subscribe((event) => {
			if (event.type === "turn_start") {
				turns += 1;
				if (turns > maxTurns && !stoppedAtTurnLimit) {
					stoppedAtTurnLimit = true;
					// Not awaited: abort() waits for idle and we are inside a listener.
					// The catch is not optional — an unhandled rejection here exits.
					void session.abort().catch(() => {});
				}
				return;
			}
			// Without this a provider 404 reads as "the probe found nothing" and the
			// scan completes clean. willRetry excludes blips pi recovers from.
			if (event.type !== "agent_end" || event.willRetry) return;
			const err = (event.messages.at(-1) as { errorMessage?: string } | undefined)?.errorMessage;
			if (err) failures.push(err);
		});

		try {
			try {
				await session.prompt(args.prompt, { expandPromptTemplates: false });
				await session.waitForIdle();
			} catch (err) {
				if (!stoppedAtTurnLimit) throw err;
			}

			if (failures.length > 0 && !stoppedAtTurnLimit) {
				throw new Error(`agent run failed: ${failures[0]}`);
			}

			const stats = session.getSessionStats();
			const cache = cacheCosts(session.messages, resolved.model);
			return {
				text: session.getLastAssistantText() ?? "",
				tokensIn: stats.tokens.input + stats.tokens.cacheRead + stats.tokens.cacheWrite,
				tokensOut: stats.tokens.output,
				costUsd: stats.cost,
				inputTokens: stats.tokens.input,
				cacheReadTokens: stats.tokens.cacheRead,
				cacheWriteTokens: stats.tokens.cacheWrite,
				cacheCostUsd: cache.costUsd,
				cacheSavingsUsd: cache.savingsUsd,
				...(stoppedAtTurnLimit ? { stoppedAtTurnLimit: true } : {}),
			};
		} finally {
			if (args.tracePath) {
				try {
					mkdirSync(dirname(args.tracePath), { recursive: true, mode: 0o700 });
					session.exportToJsonl(args.tracePath);
					chmodSync(args.tracePath, 0o600);
				} catch (err) {
					args.onEvent?.(
						`  warning: no transcript for ${ctx.workerId} — ${(err as Error).message}`,
					);
				}
			}
			unsubscribe();
			session.dispose();
		}
	}
}

interface PiUsage {
	input: number;
	cacheRead: number;
	cost: { input: number; cacheRead: number; cacheWrite: number };
}

/**
 * PI's session summary retains only the total cost. Sum the public messages to
 * keep the cache cost and the saving from cache reads. The model rate is a
 * fallback for a full cache hit, where a response has no ordinary input tokens
 * from which to infer the input rate.
 */
function cacheCosts(
	messages: readonly unknown[],
	model: { cost?: { input?: number; cacheRead?: number } },
): { costUsd: number; savingsUsd: number } {
	let costUsd = 0;
	let savingsUsd = 0;
	for (const message of messages) {
		const usage = piUsage(message);
		if (!usage) continue;
		costUsd += usage.cost.cacheRead + usage.cost.cacheWrite;
		if (usage.cacheRead === 0) continue;
		const inputRate =
			usage.input > 0 ? usage.cost.input / usage.input : (model.cost?.input ?? 0) / 1_000_000;
		const cacheReadRate =
			usage.cacheRead > 0
				? usage.cost.cacheRead / usage.cacheRead
				: (model.cost?.cacheRead ?? 0) / 1_000_000;
		savingsUsd += usage.cacheRead * Math.max(0, inputRate - cacheReadRate);
	}
	return { costUsd, savingsUsd };
}

function piUsage(message: unknown): PiUsage | undefined {
	if (typeof message !== "object" || message === null || !("usage" in message)) return undefined;
	const usage = (message as { usage?: unknown }).usage;
	if (typeof usage !== "object" || usage === null || !("cost" in usage)) return undefined;
	const cost = (usage as { cost?: unknown }).cost;
	if (typeof cost !== "object" || cost === null) return undefined;
	const tokens = usage as Partial<Pick<PiUsage, "input" | "cacheRead">>;
	const costs = cost as Partial<PiUsage["cost"]>;
	if (
		typeof tokens.input !== "number" ||
		typeof tokens.cacheRead !== "number" ||
		typeof costs.input !== "number" ||
		typeof costs.cacheRead !== "number" ||
		typeof costs.cacheWrite !== "number"
	) {
		return undefined;
	}
	return { input: tokens.input, cacheRead: tokens.cacheRead, cost: costs as PiUsage["cost"] };
}

type AnyToolDef = ToolDefinition<TSchema, unknown, unknown>;

function confine(def: AnyToolDef, ctx: RunContext): AnyToolDef {
	const inner = def.execute.bind(def);
	return {
		...def,
		async execute(id, params, signal, onUpdate, extCtx) {
			const path = (params as { path?: unknown } | undefined)?.path;
			if (typeof path === "string" && path.length > 0 && !readableFrom(ctx, path)) {
				throw new Error(
					`'${path}' is outside the repository under review. ` +
						`This scan may only read inside ${ctx.repoRoot}` +
						`${ctx.overflowDir ? ` and ${ctx.overflowDir}` : ""}.`,
				);
			}
			return inner(id, params, signal, onUpdate, extCtx);
		},
	} as AnyToolDef;
}

export function readableFrom(
	ctx: Pick<RunContext, "repoRoot" | "overflowDir">,
	path: string,
): boolean {
	if (withinRepo(ctx.repoRoot, path)) return true;
	return ctx.overflowDir !== undefined && withinRepo(ctx.overflowDir, path);
}

const UNICODE_SPACES = /[\u00A0\u2000-\u200A\u202F\u205F\u3000]/g;

export function normalizeLikePi(p: string): string {
	let s = p.replace(UNICODE_SPACES, " ");
	if (s.startsWith("@")) s = s.slice(1);
	if (s === "~") return homedir();
	if (s.startsWith("~/")) return join(homedir(), s.slice(2));
	if (/^file:\/\//.test(s)) {
		try {
			return fileURLToPath(s);
		} catch {
			return s;
		}
	}
	return s;
}

export function withinRepo(root: string, p: string): boolean {
	const abs = resolve(root, normalizeLikePi(p));
	if (outside(root, abs)) return false;
	let real: string;
	try {
		real = realpathSync(abs);
	} catch {
		return true;
	}
	return !outside(realpathSync(root), real);
}

function outside(root: string, abs: string): boolean {
	const rel = relative(root, abs);
	return rel.startsWith("..") || isAbsolute(rel);
}

function resultText(result: { content?: Array<{ type: string; text?: string }> }): string {
	return (result.content ?? [])
		.filter((c) => c.type === "text")
		.map((c) => c.text ?? "")
		.join("\n");
}

function instrumentRead(def: AnyToolDef, ctx: RunContext): AnyToolDef {
	const inner = def.execute.bind(def);
	return {
		...def,
		async execute(id, params, signal, onUpdate, extCtx) {
			const result = await inner(id, params, signal, onUpdate, extCtx);
			const path = (params as { path?: unknown } | undefined)?.path;
			if (typeof path === "string") {
				const rel = toRepoRelative(ctx.repoRoot, path);
				if (rel) {
					// A read with an offset is the agent continuing through a file it
					// has already seen the start of, so it adds rather than replaces.
					const offset = (params as { offset?: unknown } | undefined)?.offset;
					const continued = typeof offset === "number" && offset > 1;
					ctx.ledger.recordTouch(
						ctx.scanId,
						rel,
						Buffer.byteLength(resultText(result), "utf8"),
						continued,
						ctx.readGroup,
						ctx.workerId,
					);
				}
			}
			return result;
		},
	} as AnyToolDef;
}

export function instrumentGrep(def: AnyToolDef, ctx: RunContext): AnyToolDef {
	const inner = def.execute.bind(def);
	return {
		...def,
		async execute(id, params, signal, onUpdate, extCtx) {
			const result = await inner(id, params, signal, onUpdate, extCtx);
			const asked = (params as { path?: unknown } | undefined)?.path;
			const searchRoot = resolve(
				ctx.repoRoot,
				normalizeLikePi(typeof asked === "string" && asked.length > 0 ? asked : "."),
			);

			if (isFile(searchRoot)) {
				const rel = toRepoRelative(ctx.repoRoot, searchRoot);
				if (rel && ctx.ledger.fileInScope(ctx.scanId, rel)) {
					ctx.ledger.recordTouch(ctx.scanId, rel, 0, false, ctx.readGroup, ctx.workerId);
				}
				return result;
			}

			for (const hit of parseGrepPaths(resultText(result))) {
				const rel = toRepoRelative(ctx.repoRoot, resolve(searchRoot, hit));
				if (rel && ctx.ledger.fileInScope(ctx.scanId, rel)) {
					ctx.ledger.recordTouch(ctx.scanId, rel, 0, false, ctx.readGroup, ctx.workerId);
				}
			}
			return result;
		},
	} as AnyToolDef;
}

function isFile(p: string): boolean {
	try {
		return statSync(p).isFile();
	} catch {
		return false;
	}
}

function parseGrepPaths(output: string): Set<string> {
	const paths = new Set<string>();
	for (const line of output.split("\n")) {
		const m = /^([^\s:][^:]*):\d+[:-]/.exec(line);
		if (m?.[1]) paths.add(m[1]);
	}
	return paths;
}

function toRepoRelative(root: string, p: string): string | null {
	const rel = relative(resolve(root), resolve(root, p));
	return rel.length > 0 && !rel.startsWith("..") && !isAbsolute(rel) ? rel : null;
}
