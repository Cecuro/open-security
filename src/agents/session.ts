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
	tokensIn: number;
	tokensOut: number;
	costUsd: number;
	stoppedAtTurnLimit?: boolean;
}

export interface UsageDelta {
	tokensIn: number;
	tokensOut: number;
	costUsd: number;
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
			systemPrompt: [
				`Repository root: ${this.repoRoot}`,
				"Use repository-relative paths for read, grep, find, and ls (for example, src/handler.ts).",
				"Those tools return repository-relative paths too.",
				"",
				args.systemPrompt,
			].join("\n"),
			appendSystemPrompt: [],
		});
		await resourceLoader.reload();

		const tools: AnyToolDef[] = [
			instrumentRead(confine(createReadToolDefinition(this.repoRoot) as AnyToolDef, ctx), ctx),
			instrumentGrep(confine(createGrepToolDefinition(this.repoRoot) as AnyToolDef, ctx), ctx),
			rootRelativeResults(confine(createFindToolDefinition(this.repoRoot) as AnyToolDef, ctx), ctx),
			rootRelativeResults(confine(createLsToolDefinition(this.repoRoot) as AnyToolDef, ctx), ctx),
			createOpensecTool(ctx) as AnyToolDef,
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
		let reported: UsageDelta = { tokensIn: 0, tokensOut: 0, costUsd: 0 };
		let stoppedAtBudget = false;
		const reportUsage = (usage: UsageDelta): void => {
			if (usage.tokensIn === 0 && usage.tokensOut === 0 && usage.costUsd === 0) return;
			reported = {
				tokensIn: reported.tokensIn + usage.tokensIn,
				tokensOut: reported.tokensOut + usage.tokensOut,
				costUsd: reported.costUsd + usage.costUsd,
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
				const usage = usageOf(event.message);
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
			const total: UsageDelta = {
				tokensIn: stats.tokens.input + stats.tokens.cacheRead + stats.tokens.cacheWrite,
				tokensOut: stats.tokens.output,
				costUsd: stats.cost,
			};
			reportUsage({
				tokensIn: Math.max(0, total.tokensIn - reported.tokensIn),
				tokensOut: Math.max(0, total.tokensOut - reported.tokensOut),
				costUsd: Math.max(0, total.costUsd - reported.costUsd),
			});
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
	}
}

type AnyToolDef = ToolDefinition<TSchema, unknown, unknown>;

function confine(def: AnyToolDef, ctx: RunContext): AnyToolDef {
	const inner = def.execute.bind(def);
	return {
		...def,
		async execute(id, params, signal, onUpdate, extCtx) {
			const path = (params as { path?: unknown } | undefined)?.path;
			const resolvedPath = typeof path === "string" ? resolveToolPath(ctx, path) : path;
			if (typeof resolvedPath === "string" && resolvedPath.length > 0 && !readableFrom(ctx, resolvedPath)) {
				throw new Error(
					`'${path}' is outside the repository under review. ` +
						`This scan may only read inside ${ctx.repoRoot}` +
						`${ctx.overflowDir ? ` and ${ctx.overflowDir}` : ""}.`,
				);
			}
			const next =
				typeof resolvedPath === "string" ? { ...(params as object), path: resolvedPath } : params;
			return inner(id, next, signal, onUpdate, extCtx);
		},
	} as AnyToolDef;
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
					ctx.ledger.recordTouch(ctx.scanId, rel, Buffer.byteLength(resultText(result), "utf8"));
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
			const result = await inner(id, next, signal, onUpdate, extCtx);
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
					ctx.ledger.recordTouch(ctx.scanId, rel, 0);
				}
				return result;
			}

			for (const hit of parseGrepPaths(resultText(result))) {
				const rel = toRepoRelative(ctx.repoRoot, resolve(searchRoot, hit));
				if (rel && ctx.ledger.fileInScope(ctx.scanId, rel)) {
					ctx.ledger.recordTouch(ctx.scanId, rel, 0);
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

function usageOf(message: unknown): UsageDelta | null {
	const usage = (message as { usage?: Record<string, unknown> } | undefined)?.usage;
	if (!usage) return null;
	const number = (value: unknown): number => (typeof value === "number" ? value : 0);
	const cost = usage.cost as Record<string, unknown> | undefined;
	return {
		tokensIn: number(usage.input) + number(usage.cacheRead) + number(usage.cacheWrite),
		tokensOut: number(usage.output),
		costUsd: number(cost?.total),
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
