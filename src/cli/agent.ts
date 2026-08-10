import { readFileSync } from "node:fs";
import { connect } from "node:net";

const COMMANDS = [
	{ words: ["work", "next"], verb: "work.next", usage: "opensec work next [--limit <n>]", note: "Get the files you must review." },
	{ words: ["work", "complete"], verb: "work.complete", usage: "opensec work complete --summary <text> | --summary-file <path>", note: "Record completed review work." },
	{ words: ["lead", "record"], verb: "lead.record", usage: "opensec lead record --text <text> | --text-file <path> [--status open|dead_end]", note: "Record a lead or dead end." },
	{ words: ["candidate", "create"], verb: "candidate.create", usage: "opensec candidate create --input <path|->", note: "Create a suspected finding." },
	{ words: ["candidate", "validate"], verb: "candidate.validate", usage: "opensec candidate validate <id> --disposition <value> --rationale <text> | --rationale-file <path>", note: "Record a validation verdict." },
	{ words: ["candidate", "assess"], verb: "candidate.assess", usage: "opensec candidate assess --input <path|->", note: "Record attack-path and severity inputs." },
] as const;

type Command = (typeof COMMANDS)[number];
type AgentResponse = { ok: boolean; output?: string; error?: string };

export function isAgentCliCommand(command: string | undefined): boolean {
	return command === "work" || command === "lead" || command === "candidate" || command === "context";
}

/** Dispatch the agent-only part of the public opensec command tree. */
export async function runAgentCli(args: string[]): Promise<number> {
	try {
		if (args.length === 0 || args[0] === "--help" || args[0] === "-h") return output(help());
		if (args[0] === "help") {
			const command = findCommand(args.slice(1));
			return output(command ? commandHelp(command) : help());
		}
		if (args[0] === "context") return output(context());
		const command = findCommand(args);
		if (!command) throw new Error(`unknown command '${args.slice(0, 2).join(" ")}'. Run 'opensec help'.`);
		const rest = args.slice(command.words.length);
		if (rest[0] === "--help" || rest[0] === "-h") return output(commandHelp(command));

		const socket = process.env.OPENSEC_SOCKET;
		const token = process.env.OPENSEC_TOKEN;
		if (!socket || !token) throw new Error("this command is only available inside an OpenSec container run");
		const allowed = allowedVerbs();
		if (allowed.size > 0 && !allowed.has(command.verb)) {
			throw new Error(`${command.words.join(" ")} is not available in this review pass. Run 'opensec context'.`);
		}
		const response = await request(socket, { token, verb: command.verb, params: params(command, rest) });
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

function params(command: Command, args: string[]): Record<string, unknown> {
	if (command.verb === "work.next") {
		const flags = flagsOf(args, ["--limit"]);
		return flags.size === 0 ? {} : { limit: numberFlag(flags, "--limit") };
	}
	if (command.verb === "work.complete") return { summary: textFlag(flagsOf(args, ["--summary", "--summary-file"]), "--summary") };
	if (command.verb === "lead.record") {
		const flags = flagsOf(args, ["--text", "--text-file", "--status"]);
		const status = flags.get("--status");
		return { text: textFlag(flags, "--text"), ...(status ? { status } : {}) };
	}
	if (command.verb === "candidate.validate") {
		const [id, ...options] = args;
		if (!id || id.startsWith("--")) throw new Error("candidate validate needs a candidate id");
		const flags = flagsOf(options, ["--disposition", "--rationale", "--rationale-file", "--duplicate-of"]);
		const duplicate = flags.get("--duplicate-of");
		return {
			id,
			disposition: requiredFlag(flags, "--disposition"),
			rationale: textFlag(flags, "--rationale"),
			...(duplicate ? { duplicate_of: duplicate } : {}),
		};
	}
	return jsonParams(args);
}

function jsonParams(args: string[]): Record<string, unknown> {
	if (args.length === 2 && args[0] === "--json") return object(parseJson(args[1] ?? "", "--json"));
	if (args.length === 2 && args[0] === "--input") return object(parseJson(args[1] === "-" ? readStdin() : read(args[1] ?? ""), args[1] ?? ""));
	throw new Error("use --input <path|-> or --json <object>");
}

function textFlag(flags: Map<string, string>, name: string): string {
	const value = flags.get(name);
	const file = flags.get(`${name}-file`);
	if ((value ? 1 : 0) + (file ? 1 : 0) !== 1) throw new Error(`use exactly one of ${name} <text> or ${name}-file <path>`);
	return value ?? read(file!);
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

function request(socket: string, payload: object): Promise<AgentResponse> {
	return new Promise((resolve, reject) => {
		const connection = connect(socket);
		let body = "";
		connection.setEncoding("utf8");
		connection.setTimeout(10_000);
		connection.on("connect", () => connection.write(`${JSON.stringify(payload)}\n`));
		connection.on("data", (chunk: string) => (body += chunk));
		connection.on("timeout", () => connection.destroy(new Error("OpenSec bridge timed out")));
		connection.on("end", () => {
			try { resolve(JSON.parse(body) as AgentResponse); } catch { reject(new Error("invalid response from OpenSec bridge")); }
		});
		connection.on("error", reject);
	});
}

function allowedVerbs(): Set<string> {
	return new Set((process.env.OPENSEC_VERBS ?? "").split(",").filter(Boolean));
}

function help(): string {
	const allowed = allowedVerbs();
	return [
		"AGENT COMMANDS",
		"  These commands work only inside an OpenSec container run.",
		"",
		...COMMANDS.filter((command) => allowed.size === 0 || allowed.has(command.verb)).map((command) => `  ${command.usage}\n      ${command.note}`),
		"",
		"Use 'opensec help <group> <command>' for details. Commands print JSON.",
	].join("\n");
}

function commandHelp(command: Command): string { return `${command.usage}\n\n${command.note}`; }

function context(): string {
	if (!process.env.OPENSEC_SOCKET || !process.env.OPENSEC_TOKEN) throw new Error("context is only available inside an OpenSec container run");
	const allowed = allowedVerbs();
	return JSON.stringify({ workspace: "/workspace/repo", worker: process.env.OPENSEC_WORKER ?? "unknown", commands: COMMANDS.filter((command) => allowed.size === 0 || allowed.has(command.verb)).map((command) => command.words.join(" ")) }, null, 2);
}

function output(text: string): number { process.stdout.write(`${text}\n`); return 0; }
