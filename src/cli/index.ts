#!/usr/bin/env node

import { Ledger } from "../db/db.js";
import { describeEnv, loadEnv, piAuthPath } from "../env.js";
import { reportScan, type ScanResult, Scanner } from "../sdk/scanner.js";
import { stripControlChars } from "../text.js";
import { renderMatrix } from "../scan/severity.js";
import type { Profile } from "../types.js";

const USAGE = `opensec — point it at a repository, get findings you can defend.

  opensec scan <path> [options]
  opensec scan <path> --estimate      files and tokens; spends nothing
  opensec report [scanId]             re-render a scan's report from the ledger,
                                      no agents run. Works on failed scans; with
                                      no id it lists the scans it knows.
  opensec resume <scanId> [options]   pick a failed or interrupted scan back up
                                      at the phase it stopped in. Spend so far
                                      still counts against --max-cost.
  opensec models                      models with a price, so budgets are enforceable
  opensec env                         which credentials are configured, by name
  opensec help severity               how severity is computed

Options
  --model <ref>        provider/model, e.g. azure-openai-responses/gpt-5.4
  --profile <p>        static (default) | container (M2, not yet implemented)
  --db <path>          ledger location (default ~/.opensec/opensec.db)
  --prompts <dir>      override the prompt pack
  --max-files <n>      refuse rather than run away on a monorepo
  --exclude <globs>    comma-separated repo-relative globs to leave out, e.g.
                       "vendor/**,**/examples/**". Excluded files are counted
                       and given this reason in the report, not dropped silently.
  --max-cost <usd>     spend ceiling, or "none" (default). Refuses to start if
                       the model has no price, since that budget is unenforceable.
  --concurrency <n>    agents in flight at once (default 4)
  --max-turns <n>      turns one agent may take before it is stopped (default 80).
                       --max-cost is only checked between agents, so this is what
                       bounds a single agent that loops.
  --probes <n>         independent passes over the repository (default 1). Each
                       pass reviews every file with its own agents and its own
                       read state, so it is a second opinion rather than more
                       hands: n passes cost about n times the reading. Measured
                       on one repo, findings went 6 / 10 / 12 / 13 for passes
                       1 / 2 / 3 / 4, so a fixed setup is close to spent by 4.
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

	if (command === "report") {
		const opts = parseFlags(rest);
		const bad = rejectMissingValues(opts);
		if (bad) return fail(bad);
		const id = opts.positional[0];
		const ledger = Ledger.open(opts.flags.db);
		try {
			if (!id) {
				const scans = ledger.listScans(20);
				if (scans.length === 0) {
					process.stdout.write("no scans in this ledger yet.\n");
					return 0;
				}
				for (const s of scans) {
					process.stdout.write(
						`  ${s.id}  ${s.repo_name.padEnd(20)} ${s.status.padEnd(10)} ` +
							`${s.phase.padEnd(12)} $${s.cost_usd.toFixed(2)}\n`,
					);
				}
				process.stdout.write("\nopensec report <scanId> renders one.\n");
				return 0;
			}
			return await emit(reportScan(ledger, id), opts.bools.json === true);
		} finally {
			ledger.close();
		}
	}

	if (command === "resume") {
		const opts = parseFlags(rest);
		const id = opts.positional[0];
		if (!id) return fail("resume needs a scan id — 'opensec report' lists them");
		const bad = rejectMissingValues(opts);
		if (bad) return fail(bad);
		const parsed = parseScanNumbers(opts);
		if (typeof parsed === "string") return fail(parsed);
		const unknown = unknownBool(opts, ["json", "refresh-threat-model"]);
		if (unknown) return fail(`unknown flag '--${unknown}'\n\n${USAGE}`);

		const scanner = await Scanner.resume(id, {
			model: opts.flags.model,
			db: opts.flags.db,
			promptsDir: opts.flags.prompts,
			...parsed,
			refreshThreatModel: opts.bools["refresh-threat-model"] === true,
			onEvent: (m) => process.stderr.write(`${safe(m)}\n`),
		});
		try {
			return await emit(await scanner.run(), opts.bools.json === true);
		} finally {
			scanner.close();
		}
	}

	if (command !== "scan") {
		process.stderr.write(`unknown command '${command}'\n\n${USAGE}`);
		return 2;
	}

	const opts = parseFlags(rest);
	const target = opts.positional[0] ?? ".";

	const bad = rejectMissingValues(opts);
	if (bad) return fail(bad);

	const PROFILES: Profile[] = ["static", "container"];
	const profileFlag = opts.flags.profile;
	if (profileFlag !== undefined && !PROFILES.includes(profileFlag as Profile)) {
		process.stderr.write(`opensec: unknown profile '${profileFlag}'. Use: ${PROFILES.join(" | ")}\n`);
		return 2;
	}
	const parsed = parseScanNumbers(opts);
	if (typeof parsed === "string") return fail(parsed);

	const unknown = unknownBool(opts, ["estimate", "json", "refresh-threat-model"]);
	if (unknown) return fail(`unknown flag '--${unknown}'\n\n${USAGE}`);

	if (opts.bools.estimate) {
		const e = await Scanner.estimate({
			repo: target,
			maxFiles: parsed.maxFiles,
			exclude: (opts.flags.exclude ?? "").split(",").map((g) => g.trim()).filter(Boolean),
		});
		process.stdout.write(
			`${e.files} files, ${(e.bytes / 1024).toFixed(0)} KB, ~${e.approxTokens.toLocaleString()} tokens of source.\n` +
				`Extensions: ${e.extensions.map((x) => `.${x}`).join(" ") || "none"}\n` +
				`This is a floor, not a quote — actual spend depends on how much the agents re-read.\n`,
		);
		return 0;
	}

	const exclude = (opts.flags.exclude ?? "")
		.split(",")
		.map((g) => g.trim())
		.filter(Boolean);

	const scanner = await Scanner.open({
		repo: target,
		exclude,
		model: opts.flags.model,
		db: opts.flags.db,
		profile: (profileFlag as Profile | undefined) ?? "static",
		promptsDir: opts.flags.prompts,
		...parsed,
		refreshThreatModel: opts.bools["refresh-threat-model"] === true,
		onEvent: (m) => process.stderr.write(`${safe(m)}\n`),
	});

	try {
		return await emit(await scanner.run(), opts.bools.json === true);
	} finally {
		scanner.close();
	}
}

function fail(message: string): number {
	process.stderr.write(`opensec: ${message}\n`);
	return 2;
}

// A value flag at the end of the line, or followed by another flag, silently
// became undefined and ran the scan with the default. Refuse instead.
function rejectMissingValues(opts: Parsed): string | null {
	for (const [name, value] of Object.entries(opts.flags)) {
		if (value === undefined || value.startsWith("--")) return `--${name} needs a value`;
	}
	return null;
}

function unknownBool(opts: Parsed, known: string[]): string | undefined {
	const set = new Set(known);
	return Object.keys(opts.bools).find((b) => !set.has(b));
}

interface ScanNumbers {
	maxFiles?: number;
	concurrency?: number;
	maxTurns?: number;
	probes?: number;
	maxCostUsd: number | null;
}

function parseScanNumbers(opts: Parsed): ScanNumbers | string {
	const out: ScanNumbers = { maxCostUsd: null };
	try {
		out.maxFiles = intFlag("max-files", opts.flags["max-files"]);
		out.concurrency = intFlag("concurrency", opts.flags.concurrency);
		out.maxTurns = intFlag("max-turns", opts.flags["max-turns"]);
		out.probes = intFlag("probes", opts.flags.probes);
	} catch (err) {
		return (err as Error).message;
	}
	const costFlag = opts.flags["max-cost"];
	if (costFlag !== undefined && costFlag !== "none") {
		out.maxCostUsd = Number(costFlag);
		if (!Number.isFinite(out.maxCostUsd) || out.maxCostUsd <= 0) {
			return "--max-cost needs a positive number, or 'none'";
		}
	}
	return out;
}

async function emit(result: ScanResult, json: boolean): Promise<number> {
	if (json) {
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
	const valueFlags = new Set(["model", "profile", "db", "prompts", "max-files", "max-cost", "concurrency", "probes", "max-turns", "exclude"]);

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
