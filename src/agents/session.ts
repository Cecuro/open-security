/**
 * Fan-out is in-process `createAgentSession()`, not pi's `subagent` extension:
 * that spawns a fresh `pi` process where `customTools` don't cross the boundary
 * (the `opensec` tool silently vanishes), traces are lost, and budget and abort
 * don't propagate (plan §3).
 *
 * Two things here are load-bearing beyond "call the model":
 *
 * 1. `noContextFiles` — the scanned repo's AGENTS.md/CLAUDE.md must never become
 *    instructions. Scope comes from the human, never from the repo (plan §5).
 * 2. read/grep are wrapped so coverage is derived from what actually happened.
 *    There is no self-report verb (plan §6).
 */

import {
	createAgentSession,
	createBashToolDefinition,
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

import type { Ledger } from "../db/db.js";
import { createOpensecTool, type RunContext } from "./tool.js";

export interface AgentRunResult {
	text: string;
	tokensIn: number;
	tokensOut: number;
	costUsd: number;
}

export interface RunArgs {
	ctx: RunContext;
	/** Replaces pi's default system prompt entirely. */
	systemPrompt: string;
	/** The turn itself. */
	prompt: string;
	/** Only investigate gets bash, and only under the container profile. */
	allowBash?: boolean;
	/** Per-phase model override; falls back to the runner's default. */
	modelRef?: string;
}

export class AgentRunner {
	private constructor(
		private readonly runtime: ModelRuntime,
		private readonly defaultModelRef: string | undefined,
		private readonly repoRoot: string,
	) {}

	static async create(opts: {
		repoRoot: string;
		modelRef?: string;
	}): Promise<AgentRunner> {
		const runtime = await ModelRuntime.create();
		return new AgentRunner(runtime, opts.modelRef, opts.repoRoot);
	}

	/** Resolve a model reference, failing loudly rather than silently picking one. */
	resolveModel(ref: string | undefined) {
		const wanted = ref ?? this.defaultModelRef;
		const res = resolveCliModel({ cliModel: wanted, modelRuntime: this.runtime });
		if (res.error || !res.model) {
			throw new Error(
				res.error ??
					`could not resolve model '${wanted ?? "(default)"}'. ` +
						`Set --model provider/model, e.g. --model azure-openai-responses/gpt-5.4`,
			);
		}
		return res;
	}

	async run(args: RunArgs): Promise<AgentRunResult> {
		const { ctx } = args;
		const resolved = this.resolveModel(args.modelRef);

		const settingsManager = SettingsManager.create(this.repoRoot, getAgentDir());
		const resourceLoader = new DefaultResourceLoader({
			cwd: this.repoRoot,
			agentDir: getAgentDir(),
			settingsManager,
			// The repo under review is attacker-authored. None of it is instruction.
			noContextFiles: true,
			noExtensions: true,
			noSkills: true,
			noPromptTemplates: true,
			noThemes: true,
			systemPrompt: args.systemPrompt,
		});
		await resourceLoader.reload();

		const tools: AnyToolDef[] = [
			instrumentRead(createReadToolDefinition(this.repoRoot) as AnyToolDef, ctx),
			instrumentGrep(createGrepToolDefinition(this.repoRoot) as AnyToolDef, ctx),
			createFindToolDefinition(this.repoRoot) as AnyToolDef,
			createLsToolDefinition(this.repoRoot) as AnyToolDef,
			createOpensecTool(ctx) as AnyToolDef,
		];
		if (args.allowBash) tools.push(createBashToolDefinition(this.repoRoot) as AnyToolDef);

		const { session } = await createAgentSession({
			cwd: this.repoRoot,
			model: resolved.model,
			thinkingLevel: resolved.thinkingLevel,
			modelRuntime: this.runtime,
			resourceLoader,
			settingsManager,
			// In-memory: writing pi session files into the scanned repo would be a
			// side effect on code we are only supposed to read.
			sessionManager: SessionManager.inMemory(),
			// Our instrumented copies replace the built-ins wholesale.
			noTools: "builtin",
			customTools: tools,
		});

		try {
			await session.prompt(args.prompt, { expandPromptTemplates: false });
			await session.waitForIdle();
			const stats = session.getSessionStats();
			return {
				text: session.getLastAssistantText() ?? "",
				tokensIn: stats.tokens.input + stats.tokens.cacheRead + stats.tokens.cacheWrite,
				tokensOut: stats.tokens.output,
				costUsd: stats.cost,
			};
		} finally {
			session.dispose();
		}
	}
}

type AnyToolDef = ToolDefinition<TSchema, unknown, unknown>;

/** Tool results are content blocks; coverage cares about the text in them. */
function resultText(result: { content?: Array<{ type: string; text?: string }> }): string {
	return (result.content ?? [])
		.filter((c) => c.type === "text")
		.map((c) => c.text ?? "")
		.join("\n");
}

/**
 * A file counts as touched only when a read actually reached it, and the bytes
 * recorded are the bytes the agent was handed — not the file's size, since the
 * read tool offsets and truncates. A throwing read records nothing.
 */
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
					ctx.ledger.recordTouch(ctx.scanId, rel, Buffer.byteLength(resultText(result), "utf8"));
				}
			}
			return result;
		},
	} as AnyToolDef;
}

/**
 * A searched file is not a completed file, so grep marks a touch with zero
 * bytes read. That is exactly the distinction the "one repo-wide grep" gaming
 * case needs (plan §6).
 */
function instrumentGrep(def: AnyToolDef, ctx: RunContext): AnyToolDef {
	const inner = def.execute.bind(def);
	return {
		...def,
		async execute(id, params, signal, onUpdate, extCtx) {
			const result = await inner(id, params, signal, onUpdate, extCtx);
			for (const path of parseGrepPaths(resultText(result))) {
				if (ctx.ledger.fileInScope(ctx.scanId, path)) {
					ctx.ledger.recordTouch(ctx.scanId, path, 0);
				}
			}
			return result;
		},
	} as AnyToolDef;
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
	const norm = p.startsWith(root) ? p.slice(root.length) : p;
	const rel = norm.replace(/^\/+/, "");
	return rel.length > 0 && !rel.startsWith("..") ? rel : null;
}


/** Convenience for building a RunContext for a given worker. */
export function runContext(args: {
	scanId: string;
	workerId: string;
	repoRoot: string;
	profile: RunContext["profile"];
	ledger: Ledger;
	nonce: string;
}): RunContext {
	return args;
}
