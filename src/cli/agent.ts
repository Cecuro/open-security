import { readFileSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

const COMMANDS = [
	{ words: ["work", "next"], verb: "work.next", usage: "opensec work next [--limit <n>]", note: "Get the files you must review." },
	{ words: ["work", "complete"], verb: "work.complete", usage: "opensec work complete --input <path|->", note: "Record completed review work from JSON." },
	{ words: ["candidate", "create"], verb: "candidate.create", usage: "opensec candidate create --input <path|->", note: "Create a suspected finding from JSON: title, description, locations, optional cwe and instance." },
	{ words: ["candidate", "validate"], verb: "candidate.validate", usage: "opensec candidate validate --input <path|->", note: "Record a validation verdict from JSON." },
	{ words: ["candidate", "assess"], verb: "candidate.assess", usage: "opensec candidate assess --input <path|->", note: "Record assessment and severity inputs." },
] as const;

const GROUPS = ["work", "candidate"] as const;

type Command = (typeof COMMANDS)[number];
type AgentResponse = { ok: boolean; output?: string; error?: string };

export function isAgentCliCommand(command: string | undefined): boolean {
	return command === "work" || command === "candidate" || command === "context";
}

/** Dispatch the agent-only part of the public opensec command tree. */
export async function runAgentCli(args: string[]): Promise<number> {
	try {
		if (args.length === 0 || args[0] === "--help" || args[0] === "-h") return output(help());
		if (args[0] === "help") {
			const rest = args.slice(1);
			const command = findCommand(rest);
			if (command) return output(commandHelp(command));
			if (isGroup(rest[0])) return output(groupHelp(rest[0]));
			return output(help());
		}
		if (args[0] === "context") return output(await context());
		if (isGroup(args[0]) && (args.length === 1 || args[1] === "--help" || args[1] === "-h")) {
			return output(groupHelp(args[0]));
		}
		const command = findCommand(args);
		if (!command) throw new Error(`unknown command '${args.slice(0, 2).join(" ")}'. Run 'opensec help'.`);
		const rest = args.slice(command.words.length);
		if (rest[0] === "--help" || rest[0] === "-h") return output(commandHelp(command));

		const endpoint = process.env.OPENSEC_ENDPOINT;
		const token = process.env.OPENSEC_TOKEN;
		if (!endpoint || !token) throw new Error("this command is only available inside an OpenSec agent run");
		const allowed = allowedVerbs();
		if (allowed.size > 0 && !allowed.has(command.verb)) {
			throw new Error(`${command.words.join(" ")} is not available in this review pass. Run 'opensec context'.`);
		}
		const response = await request(endpoint, token, { verb: command.verb, params: params(command, rest) });
		if (!response.ok) throw new Error(response.error ?? "OpenSec command failed");
		return output(response.output ?? "");
	} catch (err) {
		process.stderr.write(`opensec: ${(err as Error).message}\n`);
		return 2;
	}
}

function findCommand(args: string[]): Command | undefined {
	return COMMANDS.find((entry) => entry.words.every((word, i) => args[i] === word));
}

function isGroup(value: string | undefined): value is (typeof GROUPS)[number] {
	return GROUPS.some((group) => group === value);
}

function params(command: Command, args: string[]): Record<string, unknown> | Record<string, unknown>[] {
	if (command.verb === "work.next") {
		const flags = flagsOf(args, ["--limit"]);
		return flags.size === 0 ? {} : { limit: numberFlag(flags, "--limit") };
	}
	return jsonParams(command, args);
}

function jsonParams(command: Command, args: string[]): Record<string, unknown> | Record<string, unknown>[] {
	if (args.length === 2 && args[0] === "--input") {
		const value = parseJson(args[1] === "-" ? readStdin() : read(args[1] ?? ""), args[1] ?? "");
		if (!Array.isArray(value)) return object(value);
		if (command.verb !== "candidate.validate") throw new Error(`${command.verb} does not accept an input array`);
		if (value.length === 0) throw new Error("candidate.validate input array must not be empty");
		if (value.length > 50) throw new Error("candidate.validate accepts at most 50 items per batch");
		return value.map((item, index) => {
			if (typeof item !== "object" || item === null || Array.isArray(item)) {
				throw new Error(`candidate.validate input[${index}] must be a JSON object`);
			}
			return item as Record<string, unknown>;
		});
	}
	throw new Error("use --input <path|->");
}

function flagsOf(args: string[], permitted: string[]): Map<string, string> {
	const flags = new Map<string, string>();
	for (let i = 0; i < args.length; i += 2) {
		const name = args[i];
		const value = args[i + 1];
		if (!name || !name.startsWith("--") || !value || value.startsWith("--")) throw new Error(`expected option/value pairs, got '${args.join(" ")}'`);
		if (!permitted.includes(name)) throw new Error(`unknown option ${name}`);
		if (flags.has(name)) throw new Error(`${name} was given more than once`);
		flags.set(name, value);
	}
	return flags;
}

function requiredFlag(flags: Map<string, string>, name: string): string {
	const value = flags.get(name);
	if (!value) throw new Error(`${name} is required`);
	return value;
}

function numberFlag(flags: Map<string, string>, name: string): number {
	const number = Number(requiredFlag(flags, name));
	if (!Number.isInteger(number) || number < 1) throw new Error(`${name} must be a positive integer`);
	return number;
}

function read(path: string): string {
	try { return readFileSync(path, "utf8"); } catch { throw new Error(`cannot read '${path}'`); }
}

function readStdin(): string {
	try { return readFileSync(0, "utf8"); } catch { throw new Error("cannot read stdin"); }
}

function parseJson(text: string, source: string): unknown {
	try { return JSON.parse(text); } catch { throw new Error(`invalid JSON from ${source}`); }
}

function object(value: unknown): Record<string, unknown> {
	if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("command input must be a JSON object");
	return value as Record<string, unknown>;
}

async function request(endpoint: string, token: string, payload: object): Promise<AgentResponse> {
	let response: Response;
	try {
		response = await fetch(endpoint, {
			method: "POST",
			headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
			body: JSON.stringify(payload),
			signal: AbortSignal.timeout(10_000),
		});
	} catch (err) {
		if ((err as Error).name === "TimeoutError") throw new Error("OpenSec bridge timed out");
		throw new Error(`cannot reach OpenSec bridge: ${(err as Error).message}`);
	}
	try {
		return JSON.parse(await response.text()) as AgentResponse;
	} catch {
		throw new Error("invalid response from OpenSec bridge");
	}
}

function allowedVerbs(): Set<string> {
	return new Set((process.env.OPENSEC_VERBS ?? "").split(",").filter(Boolean));
}

function help(): string {
	const allowed = allowedVerbs();
	return [
		"AGENT COMMANDS",
		"  These commands work only inside an OpenSec agent run.",
		"",
		...COMMANDS.filter((command) => allowed.size === 0 || allowed.has(command.verb)).map((command) => `  ${command.usage}\n      ${command.note}`),
		"",
		"Use 'opensec help <group> <command>' for details. Commands print JSON.",
	].join("\n");
}

function groupHelp(group: (typeof GROUPS)[number]): string {
	return [
		`${group.toUpperCase()} COMMANDS`,
		"",
		...COMMANDS.filter((command) => command.words[0] === group).map(
			(command) => `  ${command.usage}\n      ${command.note}`,
		),
		"",
		`Use 'opensec ${group} <command> --help' for fields and a valid example.`,
	].join("\n");
}

const COMMAND_DETAILS: Partial<Record<Command["verb"], string>> = {
	"work.complete": [
		"JSON fields: summary.",
		"",
		"Example:",
		'{"summary":"Reviewed all assigned files; no new finding."}',
	].join("\n"),
	"candidate.create": [
		"JSON fields:",
		"  title        short finding title",
		"  description  complete finding with path:line evidence",
		"  locations    [{ path, start_line, end_line, role?, symbol? }]",
		"  cwe          optional CWE id array",
		"  instance     optional sibling identifier",
		"",
		"Example:",
		'{"title":"Missing authorization","description":"src/app.ts:12 permits the call without checking the user.","locations":[{"path":"src/app.ts","start_line":12,"end_line":12,"role":"sink"}],"cwe":["CWE-862"]}',
	].join("\n"),
	"candidate.validate": [
		"JSON fields: id, disposition, rationale, and optional duplicate_of.",
		"Disposition: confirmed | not_applicable | needs_follow_up | duplicate.",
		"Duplicate also requires duplicate_of.",
		"Input may be one object or an array of up to 50 objects; arrays commit atomically.",
		"",
		"Examples:",
		'{"id":"c1","disposition":"confirmed","rationale":"The public path reaches the sink without the claimed control."}',
		'{"id":"c2","disposition":"duplicate","duplicate_of":"c1","rationale":"Both candidates describe the same path and impact."}',
	].join("\n"),
	"candidate.assess": [
		"JSON fields: id, entry_point, path[], controls[], rationale, and:",
		"  impact        none | low | medium | high",
		"  vector        remote | local_network | localhost | none | unknown",
		"  auth_required none | user | admin",
		"  method        reproduced_poc | asan | debugger | code_reading | counterevidence",
		"Boolean fields: network_reachable, cross_tenant, code_execution_proven,",
		"traced_path_no_control. Optional suppression object:",
		"  boolean keys: self_only, requires_preexisting_privilege,",
		"    privilege_delta_is_the_bug, precondition_unreachable",
		"  evidence: string; source: code_evidence | repo_claim",
		"",
		"Example:",
		'{"id":"c1","entry_point":"src/app.ts:8","path":["src/app.ts:8 accepts input","src/app.ts:12 executes it"],"controls":["src/app.ts:9 checks only presence"],"rationale":"Remote input reaches execution without escaping.","impact":"high","vector":"remote","auth_required":"none","method":"code_reading","network_reachable":true,"cross_tenant":true,"code_execution_proven":false,"traced_path_no_control":true}',
	].join("\n"),
};

function commandHelp(command: Command): string {
	const detail = COMMAND_DETAILS[command.verb];
	return `${command.usage}\n\n${command.note}${detail ? `\n\n${detail}` : ""}`;
}

async function context(): Promise<string> {
	const endpoint = process.env.OPENSEC_ENDPOINT;
	const token = process.env.OPENSEC_TOKEN;
	if (!endpoint || !token) throw new Error("context is only available inside an OpenSec agent run");
	const response = await request(endpoint, token, { verb: "context" });
	if (!response.ok) throw new Error(response.error ?? "OpenSec command failed");
	const remote = object(parseJson(response.output ?? "", "OpenSec bridge"));
	const allowed = allowedVerbs();
	return JSON.stringify(
		{
			...remote,
			commands: COMMANDS.filter((command) => allowed.size === 0 || allowed.has(command.verb)).map(
				(command) => command.words.join(" "),
			),
		},
		null,
		2,
	);
}

function output(text: string): number { process.stdout.write(`${text}\n`); return 0; }

function isMain(moduleUrl: string, argv1: string | undefined): boolean {
	if (argv1 === undefined) return false;
	try {
		return realpathSync(fileURLToPath(moduleUrl)) === realpathSync(argv1);
	} catch {
		return false;
	}
}

if (isMain(import.meta.url, process.argv[1])) {
	process.exitCode = await runAgentCli(process.argv.slice(2));
}
