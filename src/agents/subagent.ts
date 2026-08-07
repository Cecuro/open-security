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

import { defineTool } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

import type { Prompts } from "../scan/prompts.js";
import { wrapUntrusted } from "../scan/prompts.js";
import { type RunContext, SUBAGENT_VERBS } from "./tool.js";

/** A subagent cannot spawn subagents. One level is delegation; two is a fork bomb. */
export const MAX_DEPTH = 1;
export const MAX_CONCURRENT = 4;
export const MAX_PER_PARENT = 8;

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
				return {
					content: [
						{
							type: "text" as const,
							text:
								result.text.trim() ||
								"(the subagent returned nothing — treat this as unsettled, not as a negative result)",
						},
					],
					details: undefined,
				};
			} finally {
				running -= 1;
			}
		},
	});
}
