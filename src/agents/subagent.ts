/**
 * Subagents, in-process.
 *
 * Every published pi subagent extension — pi's own shipped example, and the
 * community ones — spawns a fresh `pi` process (`--mode json -p --no-session`).
 * For a general coding agent that is fine. For opensec it would destroy the
 * four things the design rests on: `customTools` don't cross the boundary so
 * the child loses the `opensec` tool entirely, `--no-session` discards the
 * trace that coverage is derived from, the budget can't be enforced against a
 * process that bills independently, and the child inherits the API key.
 *
 * We don't need any of that. `AgentRunner.run()` already creates in-process
 * sessions, so a subagent is that same call with a child RunContext. The child
 * shares the ledger, so its reads count toward coverage and its spend counts
 * toward the budget, automatically.
 *
 * There is deliberately no menu of agent types. There were two — `tracer` and
 * `skeptic` — and they were the same read-only agent with a different paragraph
 * at the top, which meant the caller had to classify its question before asking
 * it and could pick wrong. A general agent given a well-posed task does both
 * jobs, which is also how codex-security launches its workers: a standard
 * coding agent, and the brief carries the specialisation.
 *
 * What we keep from the prior art: a depth cap, a concurrency cap, a per-parent
 * count cap, and the child's final message as the return value. What we
 * deliberately don't: worktree isolation (we never write), context inheritance
 * (the point is to spend less context, not copy the parent's), and
 * resumable/background agents (a scan phase is not an interactive session).
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { defineTool } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

import type { Prompts } from "../scan/prompts.js";
import { wrapUntrusted } from "../scan/prompts.js";
import { type RunContext, sanitize, SUBAGENT_VERBS } from "./tool.js";

/** A subagent cannot spawn subagents. One level is delegation; two is a fork bomb. */
export const MAX_DEPTH = 1;
export const MAX_CONCURRENT = 4;
export const MAX_PER_PARENT = 8;

/**
 * How much of a subagent's report goes straight into its parent's context.
 *
 * A delegated answer cannot be truncated the way a file read can. `read` at
 * `offset=401` returns the rest of the same file; re-running a subagent costs
 * another full agent run and produces a *different* answer, not the remainder
 * of this one. So the whole report is written down once and the parent is given
 * the head plus a path it can page with `read`.
 *
 * 16 KB rather than pi's 50 KB because this is prose, not source: a subagent
 * that needs more than about four thousand tokens to answer one question has
 * usually been asked the wrong question, and the parent delegated precisely to
 * avoid holding that much.
 */
export const MAX_INLINE_REPORT_BYTES = 16 * 1024;

const ParamsSchema = Type.Object(
	{
		task: Type.String({
			description:
				"The complete brief, self-contained. The subagent cannot see your conversation, " +
				"so name the files, the claim and what would count as an answer.",
		}),
		description: Type.String({ description: "3-5 words, shown in scan output" }),
	},
	{ additionalProperties: false },
);

export interface SubagentDeps {
	prompts: Prompts;
	/** Runs a child session. Injected to avoid a cycle with AgentRunner. */
	run: (args: {
		ctx: RunContext;
		systemPrompt: string;
		prompt: string;
		tracePath?: string;
	}) => Promise<{ text: string; tokensIn: number; tokensOut: number; costUsd: number }>;
	/** Called before each spawn; throws when the scan is out of budget. */
	checkBudget: () => void;
	bill: (r: { tokensIn: number; tokensOut: number; costUsd: number }) => void;
	tracePath: (workerId: string) => string;
	onEvent?: (msg: string) => void;
}

/**
 * Returns null when the parent is already at the depth limit, so the tool is
 * simply absent from the child rather than present-and-always-failing. A tool
 * that exists but never works wastes a turn every time it is tried.
 */
export function createSubagentTool(parent: RunContext, deps: SubagentDeps) {
	const depth = parent.depth ?? 0;
	if (depth >= MAX_DEPTH) return null;

	let spawned = 0;
	let running = 0;

	return defineTool({
		name: "delegate",
		label: "delegate",
		description:
			`Delegate one task to a subagent that starts with a fresh context and the same ` +
			`read-only tools you have. Use it when answering something yourself would mean ` +
			`pulling far more into your context than the answer is worth, or when a claim ` +
			`deserves a reader who has not already seen your reasoning.\n\n` +
			`Typical briefs: follow one input from a specific entry point to a specific sink ` +
			`and report every check on the way; take one claim and try to refute it; map every ` +
			`caller of one function and say which ones pass attacker-controlled data.\n\n` +
			`The subagent shares your worklist and reads the same repository, but it cannot ` +
			`record findings — it reports back to you, and you decide what to file. Its task ` +
			`must be self-contained: it cannot see your conversation.`,
		parameters: ParamsSchema,
		promptSnippet: "delegate - hand one self-contained task to a subagent with a fresh context",
		executionMode: "parallel",
		async execute(_id, params) {
			const { task, description } = params as { task: string; description: string };

			if (spawned >= MAX_PER_PARENT) {
				throw new Error(
					`you have already delegated ${MAX_PER_PARENT} times, which is the limit. ` +
						`Finish the review yourself.`,
				);
			}
			if (running >= MAX_CONCURRENT) {
				throw new Error(
					`${MAX_CONCURRENT} subagents are already running. Wait for one to finish.`,
				);
			}
			// Spend is shared, so a subagent must not be a way around the ceiling.
			deps.checkBudget();

			spawned += 1;
			running += 1;
			const workerId = `${parent.workerId}/sub-${spawned}`;
			deps.onEvent?.(`  ${workerId}: ${description}`);

			try {
				const child: RunContext = {
					...parent,
					workerId,
					depth: depth + 1,
					// Read and page the worklist, record dead ends. Not findings.
					verbs: SUBAGENT_VERBS,
					// Inherited from the parent otherwise, which would let a subagent
					// write to rows through a verb set it doesn't even have.
					resolvableIds: [],
					dispositions: [],
				};

				const result = await deps.run({
					ctx: child,
					systemPrompt: deps.prompts.get("agents/delegate.md"),
					prompt: [
						`You were delegated this task by ${parent.workerId}. It is the whole brief —`,
						"there is no prior conversation to refer to.",
						"",
						wrapUntrusted(parent.nonce, `task-from-${parent.workerId}`, task),
						"",
						"Investigate, then answer in your final message. Cite path:line for every",
						"claim. If you could not settle it, say so and say what is missing.",
					].join("\n"),
					tracePath: deps.tracePath(workerId.replaceAll("/", "_")),
				});

				deps.bill(result);
				// The child read attacker-authored files and its answer lands straight
				// in the parent's context, so it gets the same treatment as every other
				// piece of agent prose: nonce stripped so repo text cannot forge the
				// trust boundary the parent reads its own prompt through, control
				// characters stripped, secrets redacted.
				//
				// Deliberately without sanitize's own length cap. That cap exists to
				// stop one delegation eating the context it was spawned to save, and
				// spill() now does that job better — 16KB inline, the rest on disk.
				// Applying both would truncate the report *before* it is written down,
				// silently losing exactly the tail the file exists to preserve.
				const answer = sanitize(parent, result.text, Number.POSITIVE_INFINITY).trim();
				const report =
					answer ||
					"(the subagent returned nothing — treat this as unsettled, not as a negative result)";
				return {
					content: [{ type: "text" as const, text: spill(report, workerId, parent) }],
					details: undefined,
				};
			} finally {
				running -= 1;
			}
		},
	});
}

/**
 * Keep the whole report, inline the head, and hand back a path.
 *
 * The parent is told the byte count and how to continue, because a truncation
 * the reader cannot see is worse than no answer at all: it looks like a
 * complete finding that happens to stop mid-sentence. Falling back to plain
 * truncation when the spill fails is deliberate — a scan that worked must not
 * die because a cache directory is read-only — but it says so in the text.
 */
function spill(report: string, workerId: string, parent: RunContext): string {
	const bytes = Buffer.byteLength(report, "utf8");
	if (bytes <= MAX_INLINE_REPORT_BYTES || !parent.overflowDir) {
		return bytes <= MAX_INLINE_REPORT_BYTES
			? report
			: `${report.slice(0, MAX_INLINE_REPORT_BYTES)}\n\n[Truncated: ${bytes} bytes of report, ` +
					`${MAX_INLINE_REPORT_BYTES} shown. The rest could not be written down, so it is lost — ` +
					`delegate a narrower question rather than assuming this answer is complete.]`;
	}

	const file = join(parent.overflowDir, `${workerId.replaceAll("/", "_")}.md`);
	try {
		mkdirSync(parent.overflowDir, { recursive: true, mode: 0o700 });
		writeFileSync(file, report, { encoding: "utf8", mode: 0o600 });
	} catch {
		return (
			`${report.slice(0, MAX_INLINE_REPORT_BYTES)}\n\n[Truncated: ${bytes} bytes of report, ` +
			`${MAX_INLINE_REPORT_BYTES} shown, and it could not be written down. Delegate a narrower ` +
			`question rather than assuming this answer is complete.]`
		);
	}

	return (
		`${report.slice(0, MAX_INLINE_REPORT_BYTES)}\n\n` +
		`[This report is ${bytes} bytes; the first ${MAX_INLINE_REPORT_BYTES} are above. ` +
		`The whole thing was written to ${file} — read it with offset to continue. ` +
		`Do NOT delegate again to see the rest: a second subagent answers a second time, ` +
		`it does not resume this one.]`
	);
}
