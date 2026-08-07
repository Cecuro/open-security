/**
 * Fan-out is in-process `createAgentSession()`, not pi's `subagent` extension:
 * that spawns a fresh `pi` process where `customTools` don't cross the boundary
 * (the `opensec` tool silently vanishes), traces are lost, and budget and abort
 * don't propagate (plan §3).
 *
 * Three things here are load-bearing beyond "call the model":
 *
 * 1. **pi's "project" is never the scanned repo.** A repo under review is
 *    attacker-authored. If pi treats it as the current project it will read
 *    `<repo>/.pi/settings.json` (trusted by default) and act on it — including
 *    `npmCommand`, which is spawned to install `packages`. That is host command
 *    execution from a file in the scanned repo, under the profile that promises
 *    to execute nothing. It will also pick up `<repo>/.pi/APPEND_SYSTEM.md` and
 *    splice it into the system prompt, above our instructions and outside any
 *    nonce. So settings are in-memory and untrusted, resources are loaded from a
 *    directory we own, and the repo path is passed ONLY to the file tools.
 * 2. Tool reads are confined to the repo root. Without that, one injected
 *    instruction reads ~/.ssh or the opensec ledger into a finding.
 * 3. read/grep are wrapped so coverage is derived from what actually happened.
 *    There is no self-report verb (plan §6).
 */

import { chmodSync, mkdirSync, realpathSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve } from "node:path";

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
}

export interface RunArgs {
	ctx: RunContext;
	/** Replaces pi's default system prompt entirely. */
	systemPrompt: string;
	/** The turn itself. */
	prompt: string;
	/** Per-phase model override; falls back to the runner's default. */
	modelRef?: string;
	/**
	 * Where to write this run's session transcript. Sessions are in-memory, so
	 * without this a failed scan leaves nothing to debug — and the transcript is
	 * the only record of what the agent actually did.
	 */
	tracePath?: string;
	/**
	 * When set, this agent may delegate focused questions to subagents. Absent
	 * for subagents themselves, so the tool is missing rather than present and
	 * always failing.
	 */
	subagents?: SubagentDeps;
}

/**
 * A resolution that definitely produced a model. Spelled via `ReturnType` so the
 * emitted declarations don't have to name pi's internal model types, which live
 * in a transitive package we don't depend on directly.
 */
type CliModelResult = ReturnType<typeof resolveCliModel>;
export type ResolvedModel = Omit<CliModelResult, "model"> & {
	model: NonNullable<CliModelResult["model"]>;
};

/** Per-million-token rates. A model with no pricing cannot be budgeted. */
export interface ModelPricing {
	input: number;
	output: number;
}

export function pricingOf(model: { cost?: ModelPricing }): ModelPricing | null {
	const c = model.cost;
	if (!c || (c.input === 0 && c.output === 0)) return null;
	return c;
}

/** A directory opensec owns, used as pi's "project" so the repo never is. */
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

	/** Resolve a model reference, failing loudly rather than silently picking one. */
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
		// Narrowed: callers get a model, or this threw.
		return { ...res, model: res.model };
	}

	async run(args: RunArgs): Promise<AgentRunResult> {
		const { ctx } = args;
		const resolved = this.resolveModel(args.modelRef);
		const workDir = agentWorkDir();

		// No file I/O and explicitly untrusted: nothing in any repo can reach
		// npmCommand, packages, or any other setting pi would act on.
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
			// Explicit: without this, pi discovers .pi/APPEND_SYSTEM.md from cwd and
			// appends it to the system prompt.
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

		// The agent loop converts a failed turn into an assistant message carrying
		// `errorMessage` and lets prompt() resolve normally. Left alone, a 404 from
		// the provider reads as "the probe found nothing" and the scan completes
		// clean. A scan must never claim evidence it does not have.
		//
		// Only terminal failures count: pi emits the errored message *before*
		// deciding to retry, and flags the retry on agent_end. Treating a
		// recovered-from blip as fatal would throw away a scan that succeeded.
		const failures: string[] = [];
		const unsubscribe = session.subscribe((event) => {
			if (event.type !== "agent_end" || event.willRetry) return;
			const err = (event.messages.at(-1) as { errorMessage?: string } | undefined)?.errorMessage;
			if (err) failures.push(err);
		});

		try {
			await session.prompt(args.prompt, { expandPromptTemplates: false });
			await session.waitForIdle();

			if (failures.length > 0) {
				throw new Error(`agent run failed: ${failures[0]}`);
			}

			const stats = session.getSessionStats();
			return {
				text: session.getLastAssistantText() ?? "",
				tokensIn: stats.tokens.input + stats.tokens.cacheRead + stats.tokens.cacheWrite,
				tokensOut: stats.tokens.output,
				costUsd: stats.cost,
			};
		} finally {
			if (args.tracePath) {
				// Best effort: losing a transcript must not fail a scan that worked.
				try {
					// A transcript is a verbatim copy of everything the agent read. pi's
					// exportToJsonl writes with no mode, so the containing directory is
					// what keeps it private — 0700, and chmod'd afterwards for anyone
					// whose ~/.opensec predates this.
					mkdirSync(dirname(args.tracePath), { recursive: true, mode: 0o700 });
					session.exportToJsonl(args.tracePath);
					chmodSync(args.tracePath, 0o600);
				} catch {
					/* ignore */
				}
			}
			unsubscribe();
			session.dispose();
		}
	}
}

type AnyToolDef = ToolDefinition<TSchema, unknown, unknown>;

/**
 * pi's file tools take the repo root only as a base for relative paths — the
 * schemas accept absolute paths and resolve them anywhere on the host. Plan §5
 * says reads are confined to the repo root, so confine them.
 */
function confine(def: AnyToolDef, ctx: RunContext): AnyToolDef {
	const inner = def.execute.bind(def);
	return {
		...def,
		async execute(id, params, signal, onUpdate, extCtx) {
			const path = (params as { path?: unknown } | undefined)?.path;
			if (typeof path === "string" && path.length > 0 && !withinRepo(ctx.repoRoot, path)) {
				throw new Error(
					`'${path}' is outside the repository under review. ` +
						`This scan may only read inside ${ctx.repoRoot}.`,
				);
			}
			return inner(id, params, signal, onUpdate, extCtx);
		},
	} as AnyToolDef;
}

/**
 * Lexical containment is not enough, for the same reason it wasn't in
 * `validateLocation`: a symlinked *directory* inside the repo resolves out of
 * it while every string check still passes. Resolve first, then compare.
 */
function withinRepo(root: string, p: string): boolean {
	const abs = resolve(root, p);
	if (outside(root, abs)) return false;
	// A path that doesn't exist yet can't be a symlink; let the tool report it.
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
	const rel = relative(resolve(root), resolve(root, p));
	return rel.length > 0 && !rel.startsWith("..") && !isAbsolute(rel) ? rel : null;
}
