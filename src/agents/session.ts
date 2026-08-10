import { chmodSync, existsSync, mkdirSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
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
import { OpensecBridge } from "./bridge.js";
import { createSubagentTool, type SubagentDeps } from "./subagent.js";
import { createBashTool, DockerSandbox } from "./docker.js";
import { LocalSandbox } from "./local.js";
import type { RunContext } from "./tool.js";

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

export interface UsageDelta {
	tokensIn: number;
	tokensOut: number;
	costUsd: number;
	inputTokens: number;
	cacheReadTokens: number;
	cacheWriteTokens: number;
	cacheCostUsd: number;
	cacheSavingsUsd: number;
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
	/** Called after each completed model turn, and once more for any remainder. */
	/** Return false to stop after this completed model turn. */
	onUsage?: (usage: UsageDelta) => boolean | void;
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
		private readonly sandbox: "local" | "docker",
	) {}

	static async create(opts: {
		repoRoot: string;
		modelRef?: string;
		sandbox?: "local" | "docker";
	}): Promise<AgentRunner> {
		const runtime = await ModelRuntime.create();
		return new AgentRunner(runtime, opts.modelRef, opts.repoRoot, opts.sandbox ?? "local");
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
		let sandbox: DockerSandbox | LocalSandbox | undefined;
		let bridge: OpensecBridge | undefined;

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
			systemPrompt: [
				`Repository root: ${this.repoRoot}`,
				"File tools use repository-relative paths. Reuse paths returned by find, grep, or ls unchanged.",
				"read takes one file, find takes a glob, and grep takes a regex; set literal: true for exact code text.",
				"",
				args.systemPrompt,
				"",
				...(this.sandbox === "docker"
					? [
						"Bash runs with no network in a writable Docker copy at /workspace/repo. Container changes are visible only to bash.",
					]
					: ["Bash runs on the host in the checked-out repository. Any file changes persist in the user's working tree."]),
				"Use bash for compound searches, builds, tests, and reproductions. Keep read for assigned-file review because read records coverage.",
				"Record work with the opensec CLI in bash. Start with `opensec work next`; run `opensec help` for the commands in this pass. For complex records, write JSON to a file and pass it with `--input`. There is no opensec function tool.",
			].join("\n"),
			appendSystemPrompt: [],
		});
		await resourceLoader.reload();

		try {
			const workspace = this.sandbox === "docker" ? "/workspace/repo" : this.repoRoot;
			bridge = await OpensecBridge.create(ctx, { workspace });
			sandbox =
				this.sandbox === "docker"
					? await DockerSandbox.create(this.repoRoot, { bridge: bridge.mount })
					: await LocalSandbox.create(this.repoRoot, bridge.mount);
			const tools: AnyToolDef[] = [
				instrumentRead(confine(createReadToolDefinition(this.repoRoot) as AnyToolDef, ctx), ctx),
				instrumentGrep(confine(createGrepToolDefinition(this.repoRoot) as AnyToolDef, ctx), ctx),
				rootRelativeResults(confine(createFindToolDefinition(this.repoRoot) as AnyToolDef, ctx), ctx),
				rootRelativeResults(confine(createLsToolDefinition(this.repoRoot) as AnyToolDef, ctx), ctx),
				createBashTool(
					sandbox,
					this.sandbox === "docker"
						? `Run Bash with no network in the writable Docker copy at ${sandbox.repoDir}. Commands run for at most 10 minutes. Large output is saved in the container for later inspection.`
						: `Run Bash on the host in ${sandbox.repoDir}. Changes affect the user's working tree. Commands run for at most 10 minutes.`,
				) as AnyToolDef,
			];

			if (args.subagents) {
				const delegate = createSubagentTool(ctx, args.subagents);
				if (delegate) tools.push(delegate as AnyToolDef);
			}

			const { session } = await createAgentSession({
				// The agent and every file tool share the scanned repository as their
				// working directory. The resource loader above stays isolated so a
				// repository cannot load its own PI configuration or prompts.
				cwd: this.repoRoot,
				model: resolved.model,
				thinkingLevel: resolved.thinkingLevel,
				modelRuntime: this.runtime,
				resourceLoader,
				settingsManager,
				sessionManager: SessionManager.inMemory(this.repoRoot),
				noTools: "builtin",
				customTools: tools,
			});

			const failures: string[] = [];
			let reported: UsageDelta = emptyUsage();
			let stoppedAtBudget = false;
			const reportUsage = (usage: UsageDelta): void => {
				if (usage.tokensIn === 0 && usage.tokensOut === 0 && usage.costUsd === 0) return;
				reported = {
					tokensIn: reported.tokensIn + usage.tokensIn,
					tokensOut: reported.tokensOut + usage.tokensOut,
					costUsd: reported.costUsd + usage.costUsd,
					inputTokens: reported.inputTokens + usage.inputTokens,
					cacheReadTokens: reported.cacheReadTokens + usage.cacheReadTokens,
					cacheWriteTokens: reported.cacheWriteTokens + usage.cacheWriteTokens,
					cacheCostUsd: reported.cacheCostUsd + usage.cacheCostUsd,
					cacheSavingsUsd: reported.cacheSavingsUsd + usage.cacheSavingsUsd,
				};
				if (args.onUsage?.(usage) === false && !stoppedAtBudget) {
					stoppedAtBudget = true;
					void session.abort().catch(() => {});
				}
				ctx.ledger.recordEvent(
					ctx.scanId,
					"model_usage",
					{ ...usage, model: `${resolved.model.provider}/${resolved.model.id}` },
					ctx.workerId,
				);
			};
			ctx.ledger.recordEvent(
				ctx.scanId,
				"agent_start",
				{ model: `${resolved.model.provider}/${resolved.model.id}`, thinking: resolved.thinkingLevel ?? "medium" },
				ctx.workerId,
			);
			const maxTurns = args.maxTurns ?? DEFAULT_MAX_TURNS;
			let turns = 0;
			let stoppedAtTurnLimit = false;

			const unsubscribe = session.subscribe((event) => {
				if (event.type === "turn_end") {
					const usage = usageOf(event.message, resolved.model);
					if (usage) reportUsage(usage);
					for (const result of event.toolResults) {
						if (!result.isError) continue;
						ctx.ledger.recordEvent(
							ctx.scanId,
							"tool_error",
							{ tool: result.toolName, error: resultText(result).slice(0, 500) },
							ctx.workerId,
						);
					}
					return;
				}
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
					if (!stoppedAtTurnLimit && !stoppedAtBudget) throw err;
				}
				if (stoppedAtBudget) {
					throw new Error(`budget exhausted during ${ctx.workerId}; usage up to this response is recorded`);
				}

				if (failures.length > 0 && !stoppedAtTurnLimit) {
					throw new Error(`agent run failed: ${failures[0]}`);
				}

				const stats = session.getSessionStats();
				const cache = cacheCosts(session.messages, resolved.model);
				const total: UsageDelta = {
					tokensIn: stats.tokens.input + stats.tokens.cacheRead + stats.tokens.cacheWrite,
					tokensOut: stats.tokens.output,
					costUsd: stats.cost,
					inputTokens: stats.tokens.input,
					cacheReadTokens: stats.tokens.cacheRead,
					cacheWriteTokens: stats.tokens.cacheWrite,
					cacheCostUsd: cache.costUsd,
					cacheSavingsUsd: cache.savingsUsd,
				};
				reportUsage(subtractUsage(total, reported));
				ctx.ledger.recordEvent(
					ctx.scanId,
					"agent_end",
					{ stoppedAtTurnLimit, ...total },
					ctx.workerId,
				);
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
			} catch (err) {
				ctx.ledger.recordEvent(
					ctx.scanId,
					"agent_error",
					{ error: (err as Error).message, stoppedAtTurnLimit, stoppedAtBudget },
					ctx.workerId,
				);
				throw err;
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
		} finally {
			if (sandbox) {
				try {
					await sandbox.dispose();
				} catch (err) {
					args.onEvent?.(`  warning: could not remove execution workspace — ${(err as Error).message}`);
				}
			}
			if (bridge) {
				try {
					await bridge.dispose();
				} catch (err) {
					args.onEvent?.(`  warning: could not remove OpenSec bridge — ${(err as Error).message}`);
				}
			}
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

export function confine(def: AnyToolDef, ctx: RunContext): AnyToolDef {
	const inner = def.execute.bind(def);
	return {
		...def,
		async execute(id, params, signal, onUpdate, extCtx) {
			const path = (params as { path?: unknown } | undefined)?.path;
			const resolvedPath = typeof path === "string" ? resolveToolPath(ctx, path) : path;
			if (typeof resolvedPath === "string" && resolvedPath.length > 0 && !readableFrom(ctx, resolvedPath)) {
				if (typeof path === "string" && (path === "/workspace/repo" || path.startsWith("/workspace/repo/"))) {
					const relativePath = path.slice("/workspace/repo".length).replace(/^\//, "") || ".";
					throw new Error(
						`'${path}' is a Docker bash path. File tools use repository-relative paths; pass '${relativePath}'.`,
					);
				}
				throw new Error(
					`'${path}' is outside the repository under review. ` +
						`This scan may only read inside ${ctx.repoRoot}` +
						`${ctx.overflowDir ? ` and ${ctx.overflowDir}` : ""}.`,
				);
			}
			const problem = fileToolPathProblem(def.name, resolvedPath);
			if (problem) throw new Error(problem);
			const next =
				typeof resolvedPath === "string" ? { ...(params as object), path: resolvedPath } : params;
			return inner(id, next, signal, onUpdate, extCtx);
		},
	} as AnyToolDef;
}

function fileToolPathProblem(tool: string, path: unknown): string | undefined {
	if (typeof path !== "string" || path.length === 0) return undefined;
	if (!existsSync(path)) {
		const name = basename(path);
		if (tool === "read") {
			return (
				`No file exists at this repository-relative path. read takes one file path. ` +
				`Call find with pattern '**/${name}', then pass the returned path to read unchanged.`
			);
		}
		return (
			`No path exists at this repository-relative location. ` +
			`Use find from '.' to locate '${name}', then reuse the returned path unchanged.`
		);
	}
	if (tool === "read" && !statSync(path).isFile()) {
		return "read takes one file, not a directory. Call ls on this path, then read a returned file path unchanged.";
	}
	return undefined;
}

/** Resolve agent paths from the scanned repository's root. */
export function resolveToolPath(ctx: Pick<RunContext, "repoRoot">, path: string): string {
	const normalized = normalizeLikePi(path);
	return isAbsolute(normalized) ? normalized : resolve(ctx.repoRoot, normalized);
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
			const path = (params as { path?: unknown } | undefined)?.path;
			const next =
				typeof path === "string" ? { ...(params as object), path: resolveToolPath(ctx, path) } : params;
			const result = await inner(id, next, signal, onUpdate, extCtx);
			if (typeof path === "string") {
				const rel = toRepoRelative(ctx.repoRoot, resolveToolPath(ctx, path));
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
			const asked = (params as { path?: unknown } | undefined)?.path;
			const normalizedAsked = typeof asked === "string" ? resolveToolPath(ctx, asked) : asked;
			const next =
				typeof normalizedAsked === "string"
					? { ...(params as object), path: normalizedAsked }
					: params;
			let result;
			try {
				result = await inner(id, next, signal, onUpdate, extCtx);
			} catch (err) {
				const message = (err as Error).message;
				if (/regular expression|regex|parse error/i.test(message)) {
					throw new Error(
						`${message}. grep takes a regular expression; set literal: true to search for exact code text.`,
					);
				}
				throw err;
			}
			const searchRoot = resolve(
				ctx.repoRoot,
				normalizeLikePi(
					typeof normalizedAsked === "string" && normalizedAsked.length > 0
						? normalizedAsked
						: ".",
				),
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
			return rootRelativeResult(result, ctx.repoRoot, searchRoot, "grep");
		},
	} as AnyToolDef;
}

/**
 * PI reports grep, find, and ls entries relative to the directory passed to
 * that tool. That makes a scoped result ambiguous to the next tool call. Keep
 * the agent-facing path format uniform: every returned path is repo-relative.
 */
export function rootRelativeResults(def: AnyToolDef, ctx: Pick<RunContext, "repoRoot">): AnyToolDef {
	const inner = def.execute.bind(def);
	return {
		...def,
		async execute(id, params, signal, onUpdate, extCtx) {
			const path = (params as { path?: unknown } | undefined)?.path;
			const searchRoot = resolveToolPath(ctx, typeof path === "string" && path.length > 0 ? path : ".");
			const result = await inner(id, params, signal, onUpdate, extCtx);
			return rootRelativeResult(result, ctx.repoRoot, searchRoot, def.name);
		},
	} as AnyToolDef;
}

function rootRelativeResult<T>(result: T, repoRoot: string, searchRoot: string, tool: string): T {
	const withContent = result as T & {
		content?: Array<{ type: string; text?: string; [key: string]: unknown }>;
	};
	if (!withContent.content) return result;

	return {
		...withContent,
		content: withContent.content.map((block) => {
			if (block.type !== "text" || block.text === undefined) return block;
			return { ...block, text: rootRelativeOutput(block.text, repoRoot, searchRoot, tool) };
		}),
	} as T;
}

function rootRelativeOutput(output: string, repoRoot: string, searchRoot: string, tool: string): string {
	if (tool === "grep") {
		return output
			.split("\n")
			.map((line) => {
				const match = /^(.*?)(?=:\d+:|-\d+-)/.exec(line);
				if (!match?.[1]) return line;
				const path = toRepoRelative(repoRoot, resolve(searchRoot, match[1]));
				return path ? `${path}${line.slice(match[1].length)}` : line;
			})
			.join("\n");
	}

	return output
		.split("\n")
		.map((line) => {
			if (!line || line.startsWith("[") || line.startsWith("(") || line.startsWith("No files")) return line;
			const directory = line.endsWith("/");
			const path = toRepoRelative(repoRoot, resolve(searchRoot, line));
			return path ? `${path}${directory ? "/" : ""}` : line;
		})
		.join("\n");
}

function emptyUsage(): UsageDelta {
	return {
		tokensIn: 0,
		tokensOut: 0,
		costUsd: 0,
		inputTokens: 0,
		cacheReadTokens: 0,
		cacheWriteTokens: 0,
		cacheCostUsd: 0,
		cacheSavingsUsd: 0,
	};
}

function subtractUsage(total: UsageDelta, reported: UsageDelta): UsageDelta {
	return {
		tokensIn: Math.max(0, total.tokensIn - reported.tokensIn),
		tokensOut: Math.max(0, total.tokensOut - reported.tokensOut),
		costUsd: Math.max(0, total.costUsd - reported.costUsd),
		inputTokens: Math.max(0, total.inputTokens - reported.inputTokens),
		cacheReadTokens: Math.max(0, total.cacheReadTokens - reported.cacheReadTokens),
		cacheWriteTokens: Math.max(0, total.cacheWriteTokens - reported.cacheWriteTokens),
		cacheCostUsd: Math.max(0, total.cacheCostUsd - reported.cacheCostUsd),
		cacheSavingsUsd: Math.max(0, total.cacheSavingsUsd - reported.cacheSavingsUsd),
	};
}

function usageOf(
	message: unknown,
	model: { cost?: { input?: number; cacheRead?: number } },
): UsageDelta | null {
	const usage = (message as { usage?: Record<string, unknown> } | undefined)?.usage;
	if (!usage) return null;
	const number = (value: unknown): number => (typeof value === "number" ? value : 0);
	const cost = usage.cost as Record<string, unknown> | undefined;
	const cache = cacheCosts([message], model);
	return {
		tokensIn: number(usage.input) + number(usage.cacheRead) + number(usage.cacheWrite),
		tokensOut: number(usage.output),
		costUsd: number(cost?.total),
		inputTokens: number(usage.input),
		cacheReadTokens: number(usage.cacheRead),
		cacheWriteTokens: number(usage.cacheWrite),
		cacheCostUsd: cache.costUsd,
		cacheSavingsUsd: cache.savingsUsd,
	};
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
