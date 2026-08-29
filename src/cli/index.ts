#!/usr/bin/env node

import { writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { spawn } from "node:child_process";

import { isAgentCliCommand, runAgentCli } from "./agent.js";
import { Ledger } from "../db/db.js";
import { describeEnv, loadEnv, piAuthPath } from "../env.js";
import { renderExport, type ExportFormat } from "../scan/export.js";
import { reportScan, type ScanResult, Scanner } from "../sdk/scanner.js";
import { stripControlChars } from "../text.js";
import { policyExitCode } from "../scan/policy.js";
import { renderMatrix } from "../scan/severity.js";
import type { Profile, ScanScope, Severity } from "../types.js";
import { startReviewServer } from "../review/server.js";

const require = createRequire(import.meta.url);
const { version } = require("../../package.json") as { version: string };

const USAGE = `opensec — point it at a repository, get findings you can defend.

  opensec scan <path> [options]
  opensec scan <path> --estimate      files and tokens; spends nothing
  opensec report [scanId]             re-render a scan's report from the ledger,
                                      no agents run. Works on failed scans; with
                                      no id it lists the scans it knows.
  opensec events <scanId>             show recent durable lifecycle, usage and
                                      tool-error events for a scan
  opensec resume <scanId> [options]   pick a failed or interrupted scan back up
                                      at the phase it stopped in. Spend so far
                                      still counts against --max-cost.

  opensec export <scanId> --format <format> --output <path>
                                      write sarif, csv, or json from the ledger
  opensec review [scanId] [options]    open the local review UI for runs and findings
  opensec models                      models with a price, so budgets are enforceable
  opensec env                         which credentials are configured, by name
  opensec help severity               how severity is computed

Options
  --model <ref>        provider/model, e.g. azure-openai-responses/gpt-5.4
  --profile <p>        container (default, network-isolated) | local (Bash on the host)
                       Container requires Docker Engine 28+. The cached default image includes Node,
                       Rust/Cargo, Git, Python, ripgrep, curl, jq, and build tools.
                       Set OPENSEC_SANDBOX_IMAGE and OPENSEC_SANDBOX_USER to override it;
                       a custom image must include Bash and Node 20+.
  --db <path>          ledger location (default ~/.opensec/opensec.db)
  --prompts <dir>      override the prompt pack
  --max-files <n>      refuse rather than run away on a monorepo
  --exclude <globs>    comma-separated repo-relative globs to leave out, e.g.
                       "vendor/**,**/examples/**". Excluded files are counted
                       and given this reason in the report, not dropped silently.
  --scope-file <path>  scan newline-separated repository-relative paths from a file
  --diff <base>        scan source files changed from merge-base(base, HEAD)
  --working-tree       scan staged, unstaged, and untracked source files against HEAD
  --fail-on-severity <severity>
                       CI policy: critical | high | medium | low | info. A partial
                       scan exits 2; a completed policy violation exits 1.
  --max-cost <usd>     spend ceiling, or "none" (default). Refuses to start if
                       the model has no price, since that budget is unenforceable.
  --concurrency <n>    agents in flight at once (default 4)
  --max-turns <n>      turns one agent may take before it is stopped (default 80).
                       --max-cost is only checked between agents, so this is what
                       bounds a single agent that loops.
  --passes <n>         independent passes over the repository (default 1). Each
                       pass reviews every file with its own agents and its own
                       read state, so it is a second opinion rather than more
                       hands: n passes cost about n times the reading. Measured
                       on one repo, findings went 6 / 10 / 12 / 13 for passes
                       1 / 2 / 3 / 4, so a fixed setup is close to spent by 4.
  --refresh-threat-model     rewrite the stored threat model instead of reusing it
  --json               print the findings JSON path only

Review options
  --port <n>           local port (default: choose an available port)
  --no-open            print the URL without opening a browser

The threat model for each repository is kept at
~/.opensec/repos/<repo>/threat-model.md. Edit it — the next scan reads yours as
written, and only --refresh-threat-model overwrites it.
`;

async function main(argv: string[]): Promise<number> {
	const [command, ...rest] = argv;
	if (command === "--version" || command === "-v") {
		process.stdout.write(`${version}\n`);
		return 0;
	}
	if (isAgentCliCommand(command) || (command === "help" && isAgentCliCommand(rest[0]))) {
		return runAgentCli(argv);
	}

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
		const unknownValue = unknownValueFlag(opts, ["db"]);
		if (unknownValue) return fail(`unknown flag '--${unknownValue}'\n\n${USAGE}`);
		const unknown = unknownBool(opts, ["json"]);
		if (unknown) return fail(`unknown flag '--${unknown}'\n\n${USAGE}`);
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

	if (command === "events") {
		const opts = parseFlags(rest);
		const id = opts.positional[0];
		if (!id) return fail("events needs a scan id — 'opensec report' lists them");
		const bad = rejectMissingValues(opts);
		if (bad) return fail(bad);
		const unknownValue = unknownValueFlag(opts, ["db"]);
		if (unknownValue) return fail(`unknown flag '--${unknownValue}'\n\n${USAGE}`);
		const unknown = unknownBool(opts, []);
		if (unknown) return fail(`unknown flag '--${unknown}'\n\n${USAGE}`);
		const ledger = Ledger.open(opts.flags.db);
		try {
			if (!ledger.getScan(id)) return fail(`no scan '${id}' in this ledger`);
			for (const event of ledger.listEvents(id)) {
				const detail = event.detail_json ? ` ${safe(event.detail_json)}` : "";
				process.stdout.write(
					`${event.at} ${event.type}${event.worker_id ? ` ${event.worker_id}` : ""}${detail}\n`,
				);
			}
			return 0;
		} finally {
			ledger.close();
		}
	}

	if (command === "export") {
		const opts = parseFlags(rest);
		const id = opts.positional[0];
		if (!id) return fail("export needs a scan id — 'opensec report' lists them");
		const bad = rejectMissingValues(opts);
		if (bad) return fail(bad);
		const unknownValue = unknownValueFlag(opts, ["db", "format", "output"]);
		if (unknownValue) return fail(`unknown flag '--${unknownValue}'\n\n${USAGE}`);
		const unknown = unknownBool(opts, []);
		if (unknown) return fail(`unknown flag '--${unknown}'\n\n${USAGE}`);
		const format = opts.flags.format as ExportFormat | undefined;
		if (format !== "sarif" && format !== "csv" && format !== "json") {
			return fail("--format must be sarif, csv, or json");
		}
		if (!opts.flags.output) return fail("export needs --output <path>");
		const ledger = Ledger.open(opts.flags.db);
		try {
			const scan = ledger.getScan(id);
			if (!scan) return fail(`no scan '${id}' in this ledger. 'opensec report' lists the scans it knows.`);
			const output = resolve(opts.flags.output);
			writeFileSync(
				output,
				renderExport({ scan, coverage: ledger.coverage(id), candidates: ledger.listCandidates(id) }, format),
				{ encoding: "utf8", flag: "wx", mode: 0o600 },
			);
			await flushed(`${output}\n`);
			return 0;
		} finally {
			ledger.close();
		}
	}

	if (command === "review") {
		const opts = parseFlags(rest);
		const bad = rejectMissingValues(opts);
		if (bad) return fail(bad);
		const unknownValue = unknownValueFlag(opts, ["db", "port"]);
		if (unknownValue) return fail(`unknown flag '--${unknownValue}'\n\n${USAGE}`);
		const unknown = unknownBool(opts, ["no-open"]);
		if (unknown) return fail(`unknown flag '--${unknown}'\n\n${USAGE}`);
		let port: number | undefined;
		if (opts.flags.port !== undefined) {
			port = Number(opts.flags.port);
			if (!Number.isInteger(port) || port < 1 || port > 65_535) {
				return fail("--port needs an integer from 1 to 65535");
			}
		}
		const scanId = opts.positional[0];
		const ledger = Ledger.open(opts.flags.db);
		try {
			if (scanId && !ledger.getScan(scanId)) return fail(`no scan '${scanId}' in this ledger`);
		} finally {
			ledger.close();
		}
		const reviewer = await startReviewServer({ db: opts.flags.db, port, scanId });
		process.stdout.write(`OpenSec review: ${reviewer.url}\n`);
		process.stdout.write("Press Ctrl-C to stop.\n");
		if (!opts.bools["no-open"]) openBrowser(reviewer.url);
		await new Promise<void>((resolve) => {
			const stop = () => {
				process.off("SIGINT", stop);
				process.off("SIGTERM", stop);
				reviewer.close().then(resolve, resolve);
			};
			process.on("SIGINT", stop);
			process.on("SIGTERM", stop);
		});
		return 0;
	}

	if (command === "resume") {
		const opts = parseFlags(rest);
		const id = opts.positional[0];
		if (!id) return fail("resume needs a scan id — 'opensec report' lists them");
		const bad = rejectMissingValues(opts);
		if (bad) return fail(bad);
		const parsed = parseScanNumbers(opts);
		if (typeof parsed === "string") return fail(parsed);
		const failSeverity = parseFailSeverity(opts.flags["fail-on-severity"]);
		if (typeof failSeverity === "string") return fail(failSeverity);
		const unknownValue = unknownValueFlag(opts, ["model", "db", "prompts", "max-files", "max-cost", "concurrency", "passes", "max-turns", "exclude", "fail-on-severity"]);
		if (unknownValue) return fail(`unknown flag '--${unknownValue}'\n\n${USAGE}`);
		const unknown = unknownBool(opts, ["json", "refresh-threat-model"]);
		if (unknown) return fail(`unknown flag '--${unknown}'\n\n${USAGE}`);

		const scanner = await Scanner.resume(id, {
			model: opts.flags.model,
			db: opts.flags.db,
			promptsDir: opts.flags.prompts,
			...parsed,
			...(opts.flags.exclude === undefined
				? {}
				: { exclude: opts.flags.exclude.split(",").map((g) => g.trim()).filter(Boolean) }),
			refreshThreatModel: opts.bools["refresh-threat-model"] === true,
			onEvent: (m) => process.stderr.write(`${safe(m)}\n`),
		});
		try {
			return await emit(await scanner.run(), opts.bools.json === true, failSeverity);
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

	const PROFILES: Profile[] = ["container", "local"];
	const profileFlag = opts.flags.profile;
	if (profileFlag !== undefined && !PROFILES.includes(profileFlag as Profile)) {
		process.stderr.write(`opensec: unknown profile '${profileFlag}'. Use: ${PROFILES.join(" | ")}\n`);
		return 2;
	}
	const parsed = parseScanNumbers(opts);
	if (typeof parsed === "string") return fail(parsed);
	const scope = parseScope(opts);
	if (typeof scope === "string") return fail(scope);
	const failSeverity = parseFailSeverity(opts.flags["fail-on-severity"]);
	if (typeof failSeverity === "string") return fail(failSeverity);

	const unknownValue = unknownValueFlag(opts, ["model", "profile", "db", "prompts", "max-files", "max-cost", "concurrency", "passes", "max-turns", "exclude", "scope-file", "diff", "fail-on-severity"]);
	if (unknownValue) return fail(`unknown flag '--${unknownValue}'\n\n${USAGE}`);
	const unknown = unknownBool(opts, ["estimate", "json", "refresh-threat-model", "working-tree"]);
	if (unknown) return fail(`unknown flag '--${unknown}'\n\n${USAGE}`);

	if (opts.bools.estimate) {
		const e = await Scanner.estimate({
			repo: target,
			maxFiles: parsed.maxFiles,
			exclude: (opts.flags.exclude ?? "").split(",").map((g) => g.trim()).filter(Boolean),
			scope,
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
		profile: (profileFlag as Profile | undefined) ?? "container",
		scope,
		promptsDir: opts.flags.prompts,
		...parsed,
		refreshThreatModel: opts.bools["refresh-threat-model"] === true,
		onEvent: (m) => process.stderr.write(`${safe(m)}\n`),
	});

	try {
		return await emit(await scanner.run(), opts.bools.json === true, failSeverity);
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

function unknownValueFlag(opts: Parsed, known: string[]): string | undefined {
	const set = new Set(known);
	return Object.keys(opts.flags).find((name) => !set.has(name));
}

interface ScanNumbers {
	maxFiles?: number;
	concurrency?: number;
	maxTurns?: number;
	passes?: number;
	maxCostUsd?: number | null;
}

function parseScanNumbers(opts: Parsed): ScanNumbers | string {
	const out: ScanNumbers = {};
	try {
		out.maxFiles = intFlag("max-files", opts.flags["max-files"]);
		out.concurrency = intFlag("concurrency", opts.flags.concurrency);
		out.maxTurns = intFlag("max-turns", opts.flags["max-turns"]);
		out.passes = intFlag("passes", opts.flags.passes);
	} catch (err) {
		return (err as Error).message;
	}
	const costFlag = opts.flags["max-cost"];
	if (costFlag === "none") {
		out.maxCostUsd = null;
	} else if (costFlag !== undefined) {
		out.maxCostUsd = Number(costFlag);
		if (!Number.isFinite(out.maxCostUsd) || out.maxCostUsd <= 0) {
			return "--max-cost needs a positive number, or 'none'";
		}
	}
	return out;
}

async function emit(result: ScanResult, json: boolean, failSeverity?: Severity): Promise<number> {
	if (json) {
		await flushed(`${result.jsonPath}\n`);
	} else {
		// Awaited: process.exit() drops whatever stdout has not flushed, and on
		// a pipe (`opensec scan . > report.md`) a large report is exactly what
		// would be truncated.
		await flushed(`${safe(result.markdown)}\n`);
		process.stderr.write(`\nreport: ${result.reportPath}\n`);
	}
	const code = policyExitCode(result, failSeverity);
	if (code === 2) {
		process.stderr.write("opensec: scan coverage is incomplete; CI policy cannot pass\n");
	}
	return code;
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
	const valueFlags = new Set(["model", "profile", "db", "prompts", "max-files", "max-cost", "concurrency", "passes", "max-turns", "exclude", "scope-file", "diff", "fail-on-severity", "format", "output", "port"]);

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

function openBrowser(url: string): void {
	const command = process.platform === "darwin" ? "open" : process.platform === "win32" ? "cmd" : "xdg-open";
	const args = process.platform === "win32" ? ["/c", "start", "", url] : [url];
	const child = spawn(command, args, { detached: true, stdio: "ignore" });
	child.on("error", () => {
		process.stderr.write("opensec: could not open a browser; use the URL printed above\n");
	});
	child.unref();
}

function parseScope(opts: Parsed): ScanScope | string {
	const selected = [
		opts.flags.diff !== undefined,
		opts.flags["scope-file"] !== undefined,
		opts.bools["working-tree"] === true,
	].filter(Boolean).length;
	if (selected > 1) return "--scope-file, --diff, and --working-tree are mutually exclusive";
	if (opts.flags.diff !== undefined) return { kind: "diff", base: opts.flags.diff };
	if (opts.flags["scope-file"] !== undefined) {
		return { kind: "scope_file", path: resolve(opts.flags["scope-file"]) };
	}
	if (opts.bools["working-tree"]) return { kind: "working_tree" };
	return { kind: "repository" };
}

function parseFailSeverity(value: string | undefined): Severity | string | undefined {
	if (value === undefined) return undefined;
	const values: Severity[] = ["critical", "high", "medium", "low", "info"];
	return values.includes(value as Severity)
		? (value as Severity)
		: "--fail-on-severity must be critical, high, medium, low, or info";
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
