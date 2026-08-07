/**
 * Provider credentials, read from pi's credential store.
 *
 * **Never from the current directory, and never from the repository under
 * review.** Those are frequently the same place — `opensec scan .` is the
 * common case — and a `.env` in a repository under review is attacker-authored
 * input like every other file in it. Reading one would let a scanned repository
 * set `AZURE_OPENAI_BASE_URL` to a host it controls and receive every model
 * call this tool makes, which is to say the source code of whatever is being
 * scanned, plus the API key in the Authorization header. That is a worse
 * outcome than any finding this tool could report, so the search path has
 * exactly one entry and it is anchored at the user's home directory:
 *
 *     ~/.pi/agent/auth.json
 *
 * The anchor is what makes this safe, not the count. It resolves through pi's
 * own `getAgentDir()`, so `PI_CODING_AGENT_DIR` keeps working and the two tools
 * cannot disagree about where credentials live. A repository under review can
 * influence neither the path nor its contents. Another entry may be added on
 * those same terms; one that resolves from `cwd()` or the repo root may not.
 *
 * opensec runs its agents through pi, so pi is already the thing the user
 * logged into. Asking them to copy the same key into a second file we own would
 * add a place for it to leak and a way for the two to drift apart, and buy
 * nothing — that file would sit one directory over, in the same trust domain.
 *
 * Same reasoning as the prompt pack (plan §5, `scan/prompts.ts`): prompts are
 * instructions, the repo is evidence. Credentials are further still.
 *
 * A variable already present in the environment always wins, so CI and an
 * explicit `export` keep working and pi is only a fallback.
 */

import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

import { getAgentDir } from "@earendil-works/pi-coding-agent";

/**
 * pi's credential store. Resolved through pi's own `getAgentDir()` rather than
 * a hardcoded `~/.pi/agent`, so the two agree about `PI_CODING_AGENT_DIR`
 * instead of disagreeing silently on machines that set it.
 */
export function piAuthPath(): string {
	return join(getAgentDir(), "auth.json");
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
	/** pi's auth.json, if one was read. Null when absent or unparseable. */
	authPath: string | null;
	/** Names set from pi, as "NAME (provider)". Never values. */
	applied: string[];
	/** Names pi offered that the environment already defined, so were skipped. */
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
	loaded = read(piAuthPath(), process.env);
	return loaded;
}

/**
 * Exported for tests: `loadEnv` is memoized and reads one fixed path, so this
 * is otherwise unreachable without a module-cache dance.
 */
export function read(
	authPath: string,
	env: Record<string, string | undefined>,
): EnvLoadResult {
	const result: EnvLoadResult = {
		authPath: null,
		applied: [],
		skipped: [],
		aliased: [],
		warnings: [],
	};

	if (existsSync(authPath)) readPiAuth(authPath, env, result);

	// Not conditional on the read above: aliasing applies to whatever the
	// environment holds now, however it got there, so an exported
	// AZURE_OPENAI_ENDPOINT works with no auth.json at all — and an unreadable
	// one must not skip it.
	result.aliased = applyAliases(env);

	return result;
}

/**
 * A credentials file readable by other accounts is worth one line of warning.
 * We do not refuse — it is the user's machine and their call.
 */
function warnIfWorldReadable(path: string, result: EnvLoadResult): void {
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
}

/**
 * Which environment variable each pi provider id means, mirroring pi's own
 * table in `pi-ai/dist/env-api-keys.js`. Only providers that authenticate with
 * a plain API key are here: an OAuth credential is a refresh token pi renews,
 * not something that can be handed to a provider as a key, so there is nothing
 * honest to export for one.
 */
const PI_PROVIDER_KEYS: Record<string, string> = {
	anthropic: "ANTHROPIC_API_KEY",
	"azure-openai-responses": "AZURE_OPENAI_API_KEY",
	cerebras: "CEREBRAS_API_KEY",
	deepseek: "DEEPSEEK_API_KEY",
	fireworks: "FIREWORKS_API_KEY",
	google: "GEMINI_API_KEY",
	groq: "GROQ_API_KEY",
	mistral: "MISTRAL_API_KEY",
	moonshotai: "MOONSHOT_API_KEY",
	openai: "OPENAI_API_KEY",
	openrouter: "OPENROUTER_API_KEY",
	together: "TOGETHER_API_KEY",
	xai: "XAI_API_KEY",
	zai: "ZAI_API_KEY",
};

/** Sentinel for a `!command` value, which we recognise but refuse to run. */
export const COMMAND_VALUE = Symbol("command");

interface PiCredential {
	type?: string;
	key?: string;
	/** Provider-scoped variables — a base URL, and the scope `$VAR` resolves in. */
	env?: Record<string, string>;
}

/**
 * Read pi's auth.json and export what it holds into `env`, gap-filling only.
 *
 * pi stores a credential per provider id. We translate the ones that are plain
 * API keys into the variable name that provider's SDK reads, and export each
 * credential's own `env` block alongside it — that block is where the Azure
 * base URL lives, and a key without its endpoint is not usable.
 *
 * Takes the environment as an argument for the same reason `applyAliases` does:
 * so a test can exercise it without a module-cache dance.
 */
export function readPiAuth(
	authPath: string,
	env: Record<string, string | undefined>,
	result: EnvLoadResult,
): void {
	warnIfWorldReadable(authPath, result);

	let parsed: unknown;
	try {
		parsed = JSON.parse(readFileSync(authPath, "utf8"));
	} catch (err) {
		// pi rewrites this file under a lock; a torn or hand-edited one is not
		// fatal to us, it just means we have no credentials from it.
		result.warnings.push(`could not read ${authPath}: ${(err as Error).message}`);
		return;
	}
	if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return;

	result.authPath = authPath;

	for (const [provider, raw] of Object.entries(parsed as Record<string, unknown>)) {
		if (typeof raw !== "object" || raw === null) continue;
		const credential = raw as PiCredential;

		// Providers we have no variable name for are skipped whole — including
		// their env block. pi supports far more providers than we resolve models
		// for, and exporting a base URL on behalf of a provider opensec will never
		// call is how an unrelated entry ends up redirecting the one we do use.
		const name = PI_PROVIDER_KEYS[provider];
		if (!name) continue;

		// The credential's own env block: it carries the base URL, and it is the
		// scope the key template resolves against. Applied even when the key below
		// is skipped, because a key exported by hand with no endpoint anywhere is
		// not usable.
		const scope = credential.env ?? {};
		for (const [envName, value] of Object.entries(scope)) {
			if (typeof value !== "string") continue;
			if (env[envName] !== undefined) {
				result.skipped.push(envName);
				continue;
			}
			env[envName] = value;
			result.applied.push(`${envName} (${provider})`);
		}

		if (credential.type !== "api_key" || credential.key === undefined) continue;

		if (env[name] !== undefined) {
			result.skipped.push(name);
			continue;
		}

		const key = resolvePiValue(credential.key, scope, env);
		if (key === undefined) {
			result.warnings.push(
				`${authPath}: the ${provider} key is a reference that did not resolve here — ` +
					`export ${name} instead`,
			);
			continue;
		}
		if (key === COMMAND_VALUE) {
			// pi runs `!cmd` keys through a shell. Loading credentials is not a
			// reason for this process to spawn one, so we decline and say so rather
			// than failing later with a 401 that looks like a bad key.
			result.warnings.push(
				`${authPath}: the ${provider} key runs a shell command, which opensec does not ` +
					`execute — export ${name} instead`,
			);
			continue;
		}

		env[name] = key;
		result.applied.push(`${name} (${provider})`);
	}
}

/**
 * pi's config-value grammar, minus command execution: `$NAME` and `${NAME}`
 * interpolate, `$$` and `$!` escape a literal `$` and `!`, a leading `!` means
 * a shell command, and anything else is a literal.
 *
 * Mirrors `pi-coding-agent/dist/core/resolve-config-value.js`. Getting this
 * subtly wrong would truncate a key and produce a 401 that reads like a wrong
 * key rather than a parser bug, so it follows that file rather than improvising.
 *
 * Returns undefined when a referenced variable is not set.
 */
export function resolvePiValue(
	config: string,
	scope: Record<string, string> = {},
	env: Record<string, string | undefined> = {},
): string | undefined | typeof COMMAND_VALUE {
	if (config.startsWith("!")) return COMMAND_VALUE;

	const NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
	const NAME_PREFIX = /^[A-Za-z_][A-Za-z0-9_]*/;

	let out = "";
	let index = 0;
	while (index < config.length) {
		const dollar = config.indexOf("$", index);
		if (dollar < 0) {
			out += config.slice(index);
			break;
		}
		out += config.slice(index, dollar);

		const next = config[dollar + 1];
		if (next === "$" || next === "!") {
			out += next;
			index = dollar + 2;
			continue;
		}

		if (next === "{") {
			const end = config.indexOf("}", dollar + 2);
			if (end < 0) {
				out += "$";
				index = dollar + 1;
				continue;
			}
			const name = config.slice(dollar + 2, end);
			if (NAME.test(name)) {
				const value = scope[name] ?? env[name];
				if (value === undefined) return undefined;
				out += value;
			} else {
				out += config.slice(dollar, end + 1);
			}
			index = end + 1;
			continue;
		}

		const match = config.slice(dollar + 1).match(NAME_PREFIX);
		if (match) {
			const value = scope[match[0]] ?? env[match[0]];
			if (value === undefined) return undefined;
			out += value;
			index = dollar + 1 + match[0].length;
			continue;
		}

		out += "$";
		index = dollar + 1;
	}
	return out;
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
		result.authPath
			? `pi credentials: ${result.authPath}`
			: `pi credentials: none (${piAuthPath()})`,
	);
	if (result.applied.length > 0) lines.push(`  set from pi: ${result.applied.join(", ")}`);
	if (result.skipped.length > 0) {
		lines.push(`  already in the environment, pi ignored: ${result.skipped.join(", ")}`);
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
	lines.push("Credentials come from pi's auth.json, or from the environment, which wins.");
	lines.push("Never from the current directory or the repository under review: `opensec");
	lines.push("scan .` makes those the same place, and a scanned repo that could set");
	lines.push("AZURE_OPENAI_BASE_URL would receive every model call, source code included.");

	return lines.join("\n");
}
