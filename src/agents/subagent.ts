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
 * What we do take from the prior art:
 *
 * - agent types declared as prompt files, so they are data like every other
 *   prompt and travel through `--prompts`
 * - a depth cap, a concurrency cap, and a per-parent count cap
 * - a child may tighten an inherited limit but never relax it
 * - the child's final message is the return value
 *
 * What we deliberately don't: worktree isolation (we never write), context
 * inheritance (the point is to spend less context, not copy the parent's), and
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

export type SubagentType = "tracer" | "skeptic";

const TYPES: Record<SubagentType, { prompt: keyof PromptsByName; blurb: string }> = {
	tracer: {
		prompt: "agents/tracer.md",
		blurb: "follows one data path end to end and reports whether it completes",
	},
	skeptic: {
		prompt: "agents/skeptic.md",
		blurb: "tries to refute one specific claim, and reports what would disprove it",
	},
};

type PromptsByName = Record<string, string>;

const ParamsSchema = Type.Object(
	{
		agent_type: Type.Union([Type.Literal("tracer"), Type.Literal("skeptic")], {
			description: "tracer: follow a path. skeptic: try to refute a claim.",
		}),
		task: Type.String({
			description:
				"The complete question, self-contained. The subagent cannot see your conversation.",
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
			`Delegate one focused question to a subagent with a fresh context. Use this when ` +
			`answering something would mean reading far more than you need in your own context, ` +
			`or when a claim deserves an independent look rather than your own second opinion.\n\n` +
			Object.entries(TYPES)
				.map(([name, t]) => `- ${name}: ${t.blurb}`)
				.join("\n") +
			`\n\nThe subagent shares your worklist and reads the same repository, but it cannot ` +
			`record findings — it reports back to you, and you decide what to file. ` +
			`Its task must be self-contained: it cannot see your conversation.`,
		parameters: ParamsSchema,
		promptSnippet: "delegate - hand one focused question to a subagent with a fresh context",
		executionMode: "parallel",
		async execute(_id, params) {
			const { agent_type, task, description } = params as {
				agent_type: SubagentType;
				task: string;
				description: string;
			};

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
			const workerId = `${parent.workerId}/${agent_type}-${spawned}`;
			deps.onEvent?.(`  ${workerId}: ${description}`);

			try {
				const child: RunContext = {
					...parent,
					workerId,
					depth: depth + 1,
					// Read and page the worklist, record dead ends. Not findings.
					verbs: SUBAGENT_VERBS,
				};

				const result = await deps.run({
					ctx: child,
					systemPrompt: deps.prompts.get(TYPES[agent_type].prompt as never),
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
