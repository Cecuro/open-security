/**
 * Provider credentials, loaded from one file the user owns.
 *
 * **Never from the current directory, and never from the repository under
 * review.** Those are frequently the same place — `opensec scan .` is the
 * common case — and a `.env` in a repository under review is attacker-authored
 * input like every other file in it. Reading one would let a scanned repository
 * set `AZURE_OPENAI_BASE_URL` to a host it controls and receive every model
 * call this tool makes, which is to say the source code of whatever is being
 * scanned, plus the API key in the Authorization header. That is a worse
 * outcome than any finding this tool could report, so the search path has
 * exactly one entry and it lives outside every repository:
 *
 *     ~/.opensec/env
 *
 * Same reasoning as the prompt pack (plan §5, `scan/prompts.ts`): prompts are
 * instructions, the repo is evidence. Credentials are further still.
 *
 * A variable already present in the environment always wins, so CI and an
 * explicit `export` keep working and the file is only a fallback.
 */

import { existsSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export function envFilePath(): string {
	return join(homedir(), ".opensec", "env");
}

/**
 * Names that mean the same thing to different tools.
 *
 * pi wants `AZURE_OPENAI_BASE_URL`. Azure's own portal, the `.dev.vars`
 * convention and most Azure SDKs call it `AZURE_OPENAI_ENDPOINT`. Having one
 * spelling silently not work is the exact failure that costs an afternoon, so
 * the aliases are filled in rather than documented.
 */
const ALIASES: Array<[from: string, to: string]> = [
	["AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_BASE_URL"],
	["AZURE_OPENAI_KEY", "AZURE_OPENAI_API_KEY"],
	["OPENAI_BASE_URL", "OPENAI_API_BASE"],
];

export interface EnvLoadResult {
	/** The file that was read, or null when there wasn't one. */
	path: string | null;
	/** Names set from the file. Never values. */
	applied: string[];
	/** Names in the file that the environment already defined, so were skipped. */
	skipped: string[];
	/** Aliases filled in, as "FROM -> TO". */
	aliased: string[];
	/** Non-fatal complaints worth printing once. */
	warnings: string[];
}

let loaded: EnvLoadResult | undefined;

/** Idempotent: the CLI and the SDK both call this and only the first one works. */
export function loadEnv(): EnvLoadResult {
	if (loaded) return loaded;
	loaded = read(envFilePath());
	return loaded;
}

function read(path: string): EnvLoadResult {
	const result: EnvLoadResult = {
		path: null,
		applied: [],
		skipped: [],
		aliased: [],
		warnings: [],
	};

	if (existsSync(path)) {
		result.path = path;

		// A credentials file readable by other accounts is worth one line of
		// warning. We do not refuse — it is the user's machine and their call.
		try {
			const mode = statSync(path).mode & 0o077;
			if (mode !== 0) {
				result.warnings.push(
					`${path} is readable by other users (chmod 600 to fix) — it holds API keys`,
				);
			}
		} catch {
			/* stat is advisory here */
		}

		let text: string;
		try {
			text = readFileSync(path, "utf8");
		} catch (err) {
			result.warnings.push(`could not read ${path}: ${(err as Error).message}`);
			return result;
		}

		for (const [name, value] of parse(text)) {
			if (process.env[name] !== undefined) {
				result.skipped.push(name);
				continue;
			}
			process.env[name] = value;
			result.applied.push(name);
		}
	}

	// Aliases apply to whatever the environment holds now, however it got there,
	// so an exported AZURE_OPENAI_ENDPOINT works with no file at all.
	result.aliased = applyAliases(process.env);

	return result;
}

/**
 * Fill in alternate spellings, in place. Takes the environment as an argument
 * rather than reaching for `process.env` so it is testable without a module
 * cache dance — the memoized `loadEnv` runs exactly once per process.
 *
 * Returns the aliases it filled, as "FROM -> TO".
 */
export function applyAliases(env: Record<string, string | undefined>): string[] {
	const filled: string[] = [];
	for (const [from, to] of ALIASES) {
		const value = env[from];
		if (value !== undefined && env[to] === undefined) {
			env[to] = value;
			filled.push(`${from} -> ${to}`);
		}
	}
	return filled;
}

/**
 * KEY=VALUE, `#` comments, optional `export `, optional matching quotes.
 * Deliberately small: this reads one file the user wrote, not a dotenv dialect.
 */
export function parse(text: string): Array<[string, string]> {
	const out: Array<[string, string]> = [];
	for (const raw of text.split("\n")) {
		const line = raw.trim();
		if (line.length === 0 || line.startsWith("#")) continue;

		const withoutExport = line.startsWith("export ") ? line.slice(7).trim() : line;
		const eq = withoutExport.indexOf("=");
		if (eq <= 0) continue;

		const name = withoutExport.slice(0, eq).trim();
		if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) continue;

		let value = withoutExport.slice(eq + 1).trim();
		const quote = value[0];
		if ((quote === '"' || quote === "'") && value.endsWith(quote) && value.length >= 2) {
			value = value.slice(1, -1);
		} else {
			// Unquoted values may carry a trailing comment; quoted ones may not,
			// because a `#` inside quotes is part of the secret.
			const hash = value.indexOf(" #");
			if (hash >= 0) value = value.slice(0, hash).trim();
		}
		out.push([name, value]);
	}
	return out;
}

/** Provider key names, for `opensec env`. Never their values. */
const PROVIDER_KEYS = [
	"ANTHROPIC_API_KEY",
	"AZURE_OPENAI_API_KEY",
	"GEMINI_API_KEY",
	"GROQ_API_KEY",
	"MISTRAL_API_KEY",
	"OPENAI_API_KEY",
	"OPENROUTER_API_KEY",
	"XAI_API_KEY",
];

/**
 * What is configured, by name only. A tool that prints an API key to a terminal
 * has put it in scrollback, and probably in a screenshot.
 */
export function describeEnv(result: EnvLoadResult): string {
	const lines: string[] = [];

	lines.push(
		result.path
			? `credentials file: ${result.path}`
			: `credentials file: none (create ${envFilePath()})`,
	);
	if (result.applied.length > 0) lines.push(`  set from file: ${result.applied.join(", ")}`);
	if (result.skipped.length > 0) {
		lines.push(`  already in the environment, file ignored: ${result.skipped.join(", ")}`);
	}
	if (result.aliased.length > 0) lines.push(`  aliased: ${result.aliased.join(", ")}`);
	for (const w of result.warnings) lines.push(`  warning: ${w}`);

	lines.push("");
	const present = PROVIDER_KEYS.filter((k) => process.env[k]);
	if (present.length === 0) {
		lines.push("No provider key is set, so no model can be resolved.");
	} else {
		lines.push(`provider keys present: ${present.join(", ")}`);
	}
	if (process.env.AZURE_OPENAI_API_KEY && !process.env.AZURE_OPENAI_BASE_URL) {
		lines.push(
			"AZURE_OPENAI_API_KEY is set but AZURE_OPENAI_BASE_URL is not — Azure needs both.",
		);
	}

	lines.push("");
	lines.push("Credentials are read from ~/.opensec/env only. Never from the current");
	lines.push("directory or the repository under review: `opensec scan .` makes those the");
	lines.push("same place, and a scanned repo that could set AZURE_OPENAI_BASE_URL would");
	lines.push("receive every model call, source code included.");

	return lines.join("\n");
}
