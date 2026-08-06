#!/usr/bin/env node
/**
 * The CLI shapes arguments and formats results. All behaviour lives in the SDK.
 *
 * Terminal output strips ESC sequences before printing (plan §8): OSC 52 writes
 * the clipboard and OSC 8 forges links, and finding prose is attacker-authored.
 */

import { Scanner } from "../sdk/scanner.js";
import { renderMatrix } from "../scan/severity.js";
import type { Profile } from "../types.js";

const USAGE = `opensec — point it at a repository, get findings you can defend.

  opensec scan <path> [options]
  opensec scan <path> --estimate      files and tokens; spends nothing
  opensec help severity               how severity is computed

Options
  --model <ref>        provider/model, e.g. azure-openai-responses/gpt-5.4
  --profile <p>        static (default) | container (M2, not yet implemented)
  --db <path>          ledger location (default ~/.opensec/opensec.db)
  --prompts <dir>      override the prompt pack
  --max-files <n>      refuse rather than run away on a monorepo
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

	if (command !== "scan") {
		process.stderr.write(`unknown command '${command}'\n\n${USAGE}`);
		return 2;
	}

	const opts = parseFlags(rest);
	const target = opts.positional[0] ?? ".";
	const maxFiles = opts.flags["max-files"] ? Number(opts.flags["max-files"]) : undefined;

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
		profile: (opts.flags.profile as Profile | undefined) ?? "static",
		promptsDir: opts.flags.prompts,
		maxFiles,
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
	const valueFlags = new Set(["model", "profile", "db", "prompts", "max-files"]);

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
function safe(s: string): string {
	// biome-ignore lint/suspicious/noControlCharactersInRegex: stripping them is the point
	return s.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
}

main(process.argv.slice(2))
	.then((code) => process.exit(code))
	.catch((err: unknown) => {
		process.stderr.write(`opensec: ${(err as Error).message}\n`);
		process.exit(2);
	});
