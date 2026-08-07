#!/usr/bin/env node

import { describeEnv, loadEnv, piAuthPath } from "../env.js";
import { Scanner } from "../sdk/scanner.js";
import { stripControlChars } from "../text.js";
import { renderMatrix } from "../scan/severity.js";
import type { Profile } from "../types.js";

const USAGE = `opensec — point it at a repository, get findings you can defend.

  opensec scan <path> [options]
  opensec scan <path> --estimate      files and tokens; spends nothing
  opensec models                      models with a price, so budgets are enforceable
  opensec env                         which credentials are configured, by name
  opensec help severity               how severity is computed

Options
  --model <ref>        provider/model, e.g. azure-openai-responses/gpt-5.4
  --profile <p>        static (default) | container (M2, not yet implemented)
  --db <path>          ledger location (default ~/.opensec/opensec.db)
  --prompts <dir>      override the prompt pack
  --max-files <n>      refuse rather than run away on a monorepo
  --max-cost <usd>     spend ceiling, or "none" (default). Refuses to start if
                       the model has no price, since that budget is unenforceable.
  --concurrency <n>    agents in flight at once (default 4)
  --max-turns <n>      turns one agent may take before it is stopped (default 80).
                       --max-cost is only checked between agents, so this is what
                       bounds a single agent that loops.
  --partition-max-files <n>  files per probe before the worklist splits again
  --refresh-threat-model     rewrite the stored threat model instead of reusing it
  --json               print the findings JSON path only

The threat model for each repository is kept at
~/.opensec/repos/<repo>/threat-model.md. Edit it — the next scan reads yours as
written, and only --refresh-threat-model overwrites it.
`;

async function main(argv: string[]): Promise<number> {
	const [command, ...rest] = argv;

	// Before anything resolves a model. Values already in the environment win, so
	// this only fills gaps.
	const env = loadEnv();
	for (const w of env.warnings) process.stderr.write(`opensec: ${safe(w)}\n`);

	if (command === "env") {
		process.stdout.write(`${safe(describeEnv(env))}\n`);
		return 0;
	}

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
			// pi's own message points at a `/login` command opensec does not have,
			// so say what this tool actually reads.
			process.stdout.write(
				`No models are available — no provider key is set.\n\n` +
					`opensec reads the credentials pi already stores, at\n${piAuthPath()}.\n` +
					`Log in with pi, or export the provider's own variables:\n\n` +
					`  AZURE_OPENAI_API_KEY=...\n` +
					`  AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com\n\n` +
					`Then run: opensec env\n`,
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

	// A value flag at the end of the line, or followed by another flag, silently
	// became undefined and ran the scan with the default. Refuse instead.
	for (const [name, value] of Object.entries(opts.flags)) {
		if (value === undefined || value.startsWith("--")) {
			process.stderr.write(`opensec: --${name} needs a value\n`);
			return 2;
		}
	}

	const PROFILES: Profile[] = ["static", "container"];
	const profileFlag = opts.flags.profile;
	if (profileFlag !== undefined && !PROFILES.includes(profileFlag as Profile)) {
		process.stderr.write(`opensec: unknown profile '${profileFlag}'. Use: ${PROFILES.join(" | ")}\n`);
		return 2;
	}
	let maxFiles: number | undefined;
	let concurrency: number | undefined;
	let maxTurns: number | undefined;
	let partitionMaxFiles: number | undefined;
	try {
		maxFiles = intFlag("max-files", opts.flags["max-files"]);
		concurrency = intFlag("concurrency", opts.flags.concurrency);
		maxTurns = intFlag("max-turns", opts.flags["max-turns"]);
		partitionMaxFiles = intFlag("partition-max-files", opts.flags["partition-max-files"]);
	} catch (err) {
		process.stderr.write(`opensec: ${(err as Error).message}\n`);
		return 2;
	}
	let maxCostUsd: number | null = null;
	const costFlag = opts.flags["max-cost"];
	if (costFlag !== undefined && costFlag !== "none") {
		maxCostUsd = Number(costFlag);
		if (!Number.isFinite(maxCostUsd) || maxCostUsd <= 0) {
			process.stderr.write(`opensec: --max-cost needs a positive number, or 'none'\n`);
			return 2;
		}
	}

	const known = new Set(["estimate", "json", "refresh-threat-model"]);
	const unknown = Object.keys(opts.bools).find((b) => !known.has(b));
	if (unknown) {
		process.stderr.write(`opensec: unknown flag '--${unknown}'\n\n${USAGE}`);
		return 2;
	}

	if (opts.bools.estimate) {
		const e = await Scanner.estimate({ repo: target, maxFiles });
		process.stdout.write(
			`${e.files} files, ${(e.bytes / 1024).toFixed(0)} KB, ~${e.approxTokens.toLocaleString()} tokens of source.\n` +
				`Extensions: ${e.extensions.map((x) => `.${x}`).join(" ") || "none"}\n` +
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
		concurrency,
		maxTurns,
		partitionMaxFiles,
		refreshThreatModel: opts.bools["refresh-threat-model"] === true,
		onEvent: (m) => process.stderr.write(`${safe(m)}\n`),
	});

	try {
		const result = await scanner.run();

		if (opts.bools.json) {
			await flushed(`${result.jsonPath}\n`);
		} else {
			// Awaited: process.exit() drops whatever stdout has not flushed, and on
			// a pipe (`opensec scan . > report.md`) a large report is exactly what
			// would be truncated.
			await flushed(`${safe(result.markdown)}\n`);
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
	const valueFlags = new Set(["model", "profile", "db", "prompts", "max-files", "max-cost", "concurrency", "partition-max-files", "max-turns"]);

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

function intFlag(name: string, v: string | undefined): number | undefined {
	if (v === undefined) return undefined;
	const n = Number(v);
	if (!Number.isInteger(n) || n < 1) {
		throw new Error(`--${name} needs a positive integer`);
	}
	return n;
}

function flushed(text: string): Promise<void> {
	return new Promise((resolve) => {
		process.stdout.write(text, () => resolve());
	});
}

const safe = stripControlChars;

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
