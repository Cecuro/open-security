import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { defineTool } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

import type { Prompts } from "../scan/prompts.js";
import { wrapUntrusted } from "../scan/prompts.js";
import { type RunContext, sanitize, SUBAGENT_VERBS } from "./tool.js";

export const MAX_DEPTH = 1;
export const MAX_CONCURRENT = 4;
export const MAX_PER_PARENT = 24;

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
	run: (args: {
		ctx: RunContext;
		systemPrompt: string;
		prompt: string;
		tracePath?: string;
	}) => Promise<{ text: string; tokensIn: number; tokensOut: number; costUsd: number }>;
	checkBudget: () => void;
	tracePath: (workerId: string) => string;
	onEvent?: (msg: string) => void;
}

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
			`repository tools you have. Use it when answering something yourself would mean ` +
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
					verbs: SUBAGENT_VERBS,
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
						// The parent saw the nonce in its own prompt, so its task text could
						// carry a forged end-marker that breaks out of this fence.
						wrapUntrusted(
							parent.nonce,
							`task-from-${parent.workerId}`,
							sanitize(parent, task, Number.POSITIVE_INFINITY),
						),
						"",
						"Investigate, then answer in your final message. Cite path:line for every",
						"claim. If you could not settle it, say so and say what is missing.",
					].join("\n"),
					tracePath: deps.tracePath(workerId.replaceAll("/", "_")),
				});

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

function spill(report: string, workerId: string, parent: RunContext): string {
	const bytes = Buffer.byteLength(report, "utf8");
	if (bytes <= MAX_INLINE_REPORT_BYTES) return report;

	const head = headBytes(report, MAX_INLINE_REPORT_BYTES);

	if (parent.overflowDir) {
		const file = join(parent.overflowDir, `${workerId.replaceAll("/", "_")}.md`);
		try {
			mkdirSync(parent.overflowDir, { recursive: true, mode: 0o700 });
			writeFileSync(file, report, { encoding: "utf8", mode: 0o600 });
			return (
				`${head}\n\n` +
				`[This report is ${bytes} bytes; the first ${MAX_INLINE_REPORT_BYTES} are above. ` +
				`The whole thing was written to ${file} — read it with offset to continue. ` +
				`Do NOT delegate again to see the rest: a second subagent answers a second time, ` +
				`it does not resume this one.]`
			);
		} catch {
			// The tail is gone either way; say so below.
		}
	}

	return (
		`${head}\n\n[Truncated: ${bytes} bytes of report, ` +
		`${MAX_INLINE_REPORT_BYTES} shown. The rest could not be written down, so it is lost — ` +
		`delegate a narrower question rather than assuming this answer is complete.]`
	);
}

// The budget is in bytes; string .slice() counts UTF-16 code units and can both
// blow the budget threefold and split a code point in half.
function headBytes(s: string, maxBytes: number): string {
	const buf = Buffer.from(s, "utf8");
	if (buf.length <= maxBytes) return s;
	let end = maxBytes;
	while (end > 0 && ((buf[end] ?? 0) & 0xc0) === 0x80) end--;
	return buf.subarray(0, end).toString("utf8");
}
