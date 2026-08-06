#!/usr/bin/env node
/**
 * The CLI shapes arguments and formats results. All behaviour lives in the SDK.
 *
 * Terminal output strips ESC sequences before printing (plan §8): OSC 52 writes
 * the clipboard and OSC 8 forges links, and finding prose is attacker-authored.
 */

import { Scanner } from "../sdk/scanner.js";
import { stripControlChars } from "../text.js";
import { renderMatrix } from "../scan/severity.js";
import type { Profile } from "../types.js";

const USAGE = `opensec — point it at a repository, get findings you can defend.

  opensec scan <path> [options]
  opensec scan <path> --estimate      files and tokens; spends nothing
  opensec models                      models with a price, so budgets are enforceable
  opensec help severity               how severity is computed

Options
  --model <ref>        provider/model, e.g. azure-openai-responses/gpt-5.4
  --profile <p>        static (default) | container (M2, not yet implemented)
  --db <path>          ledger location (default ~/.opensec/opensec.db)
  --prompts <dir>      override the prompt pack
  --max-files <n>      refuse rather than run away on a monorepo
  --max-cost <usd>     spend ceiling, or "none" (default). Refuses to start if
                       the model has no price, since that budget is unenforceable.
  --json               print the findings JSON path only
`;

async function main(argv: string[]): Promise<number> {
	const [command, ...rest] = argv;

	if (!command || command === "help" || command === "--help" || command === "-h") {
		if (rest[0] === "severity") {
			process.stdout.write(`${renderMatrix()}\n`);
			return 0;
		}
		process.stdout.write(USAGE);
		return 0;
	}

	if (command === "models") {
		const models = await listPricedModels();
		if (models.length === 0) {
			process.stdout.write(
				"No models are available. Set a provider API key, e.g. AZURE_OPENAI_API_KEY.\n",
			);
			return 1;
		}
		process.stdout.write(
			`${models.length} model(s) available. A price is what makes --max-cost enforceable.\n\n`,
		);
		for (const m of models) {
			process.stdout.write(
				`  ${m.ref.padEnd(48)} ${m.priced ? `$${m.input}/$${m.output} per Mtok` : "no price — --max-cost will refuse"}\n`,
			);
		}
		return 0;
	}

	if (command !== "scan") {
		process.stderr.write(`unknown command '${command}'\n\n${USAGE}`);
		return 2;
	}

	const opts = parseFlags(rest);
	const target = opts.positional[0] ?? ".";

	// A flag that is silently ignored, or a profile that is silently accepted and
	// then printed in the report header, is a wrong claim about what ran.
	const PROFILES: Profile[] = ["static", "container"];
	const profileFlag = opts.flags.profile;
	if (profileFlag !== undefined && !PROFILES.includes(profileFlag as Profile)) {
		process.stderr.write(`opensec: unknown profile '${profileFlag}'. Use: ${PROFILES.join(" | ")}\n`);
		return 2;
	}
	let maxFiles: number | undefined;
	if (opts.flags["max-files"] !== undefined) {
		maxFiles = Number(opts.flags["max-files"]);
		if (!Number.isFinite(maxFiles) || maxFiles < 1) {
			process.stderr.write(`opensec: --max-files needs a positive number\n`);
			return 2;
		}
	}
	// `none` is the explicit opt-out, so an unpriced model is a deliberate choice
	// rather than an accident.
	let maxCostUsd: number | null = null;
	const costFlag = opts.flags["max-cost"];
	if (costFlag !== undefined && costFlag !== "none") {
		maxCostUsd = Number(costFlag);
		if (!Number.isFinite(maxCostUsd) || maxCostUsd <= 0) {
			process.stderr.write(`opensec: --max-cost needs a positive number, or 'none'\n`);
			return 2;
		}
	}

	const known = new Set(["estimate", "json"]);
	const unknown = Object.keys(opts.bools).find((b) => !known.has(b));
	if (unknown) {
		process.stderr.write(`opensec: unknown flag '--${unknown}'\n\n${USAGE}`);
		return 2;
	}

	// Estimating spends nothing, writes nothing, and needs no model.
	if (opts.bools.estimate) {
		const e = await Scanner.estimate({ repo: target, maxFiles });
		process.stdout.write(
			`${e.files} files, ${(e.bytes / 1024).toFixed(0)} KB, ~${e.approxTokens.toLocaleString()} tokens of source.\n` +
				`Extensions: ${e.languages.map((l) => `.${l}`).join(" ") || "none"}\n` +
				`This is a floor, not a quote — actual spend depends on how much the agents re-read.\n`,
		);
		return 0;
	}

	const scanner = await Scanner.open({
		repo: target,
		model: opts.flags.model,
		db: opts.flags.db,
		profile: (profileFlag as Profile | undefined) ?? "static",
		promptsDir: opts.flags.prompts,
		maxFiles,
		maxCostUsd,
		onEvent: (m) => process.stderr.write(`${safe(m)}\n`),
	});

	try {
		const result = await scanner.run();

		if (opts.bools.json) {
			process.stdout.write(`${result.jsonPath}\n`);
		} else {
			process.stdout.write(`${safe(result.markdown)}\n`);
			process.stderr.write(`\nreport: ${result.reportPath}\n`);
		}

		const confirmed = result.candidates.filter(
			(c) => c.resolution?.disposition === "confirmed" && !c.merged_into,
		);
		return confirmed.length > 0 ? 1 : 0;
	} finally {
		scanner.close();
	}
}

interface Parsed {
	flags: Record<string, string | undefined>;
	bools: Record<string, boolean>;
	positional: string[];
}

function parseFlags(argv: string[]): Parsed {
	const flags: Record<string, string | undefined> = {};
	const bools: Record<string, boolean> = {};
	const positional: string[] = [];
	const valueFlags = new Set(["model", "profile", "db", "prompts", "max-files", "max-cost"]);

	for (let i = 0; i < argv.length; i++) {
		const arg = argv[i] ?? "";
		if (arg.startsWith("--")) {
			const name = arg.slice(2);
			if (valueFlags.has(name)) {
				flags[name] = argv[++i];
			} else {
				bools[name] = true;
			}
		} else {
			positional.push(arg);
		}
	}
	return { flags, bools, positional };
}

/** Strip ESC and other C0 controls before anything reaches a terminal. */
const safe = stripControlChars;

/** Only models whose provider is actually authenticated — the ones you can run. */
async function listPricedModels(): Promise<
	Array<{ ref: string; priced: boolean; input: number; output: number }>
> {
	const { ModelRuntime } = await import("@earendil-works/pi-coding-agent");
	const runtime = await ModelRuntime.create();
	const available = await runtime.getAvailable();
	return available
		.map((m) => {
			const cost = (m as { cost?: { input: number; output: number } }).cost;
			const priced = cost !== undefined && (cost.input > 0 || cost.output > 0);
			return {
				ref: `${m.provider}/${m.id}`,
				priced,
				input: cost?.input ?? 0,
				output: cost?.output ?? 0,
			};
		})
		.sort((a, b) => a.ref.localeCompare(b.ref));
}

main(process.argv.slice(2))
	.then((code) => process.exit(code))
	.catch((err: unknown) => {
		process.stderr.write(`opensec: ${(err as Error).message}\n`);
		process.exit(2);
	});
