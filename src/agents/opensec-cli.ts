#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { connect } from "node:net";

const socket = process.env.OPENSEC_SOCKET;
const token = process.env.OPENSEC_TOKEN;
const allowed = new Set((process.env.OPENSEC_VERBS ?? "").split(",").filter(Boolean));

const commands = [
	{ words: ["work", "next"], verb: "work.next", usage: "opensec work next [--limit <n>]", note: "Get the files you must review." },
	{ words: ["work", "complete"], verb: "work.complete", usage: "opensec work complete --summary <text> | --summary-file <path>", note: "Record completed review work." },
	{ words: ["lead", "record"], verb: "lead.record", usage: "opensec lead record --text <text> | --text-file <path> [--status open|dead_end]", note: "Record a lead or dead end." },
	{ words: ["candidate", "create"], verb: "candidate.create", usage: "opensec candidate create --input <path|->", note: "Create a suspected finding." },
	{ words: ["candidate", "validate"], verb: "candidate.validate", usage: "opensec candidate validate <id> --disposition <value> --rationale <text> | --rationale-file <path>", note: "Record a validation verdict." },
	{ words: ["candidate", "assess"], verb: "candidate.assess", usage: "opensec candidate assess --input <path|->", note: "Record attack-path and severity inputs." },
] as const;

type Command = (typeof commands)[number];

async function main(): Promise<void> {
	const args = process.argv.slice(2);
	if (args.length === 0 || args[0] === "--help" || args[0] === "-h") die(help(), 0);
	if (args[0] === "help") {
		const command = commands.find((entry) => entry.words.every((word, i) => args[i + 1] === word));
		die(command ? commandHelp(command) : help(), 0);
	}
	if (args[0] === "--version") die("opensec container CLI 0.0.0", 0);
	if (args[0] === "context") die(context(), 0);
	if (!socket || !token) die("this command only works inside an OpenSec container run");
	const command = commands.find((entry) => entry.words.every((word, i) => args[i] === word));
	if (!command) die(`unknown command '${args.slice(0, 2).join(" ")}'. Run 'opensec help'.`);
	const rest = args.slice(command.words.length);
	if (rest[0] === "--help" || rest[0] === "-h") die(commandHelp(command), 0);
	if (allowed.size > 0 && !allowed.has(command.verb)) {
		die(`${command.words.join(" ")} is not available in this review pass. Run 'opensec help'.`);
	}
	const response = await request({ token, verb: command.verb, params: params(command, rest) });
	if (!response.ok) die(response.error ?? "OpenSec command failed");
	process.stdout.write(`${response.output}\n`);
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
		if (!id || id.startsWith("--")) die("candidate validate needs a candidate id");
		const flags = flagsOf(options, ["--disposition", "--rationale", "--rationale-file", "--duplicate-of"]);
		const disposition = requiredFlag(flags, "--disposition");
		const duplicate = flags.get("--duplicate-of");
		return {
			id,
			disposition,
			rationale: textFlag(flags, "--rationale"),
			...(duplicate ? { duplicate_of: duplicate } : {}),
		};
	}
	return jsonParams(args);
}

function jsonParams(args: string[]): Record<string, unknown> {
	if (args.length === 2 && args[0] === "--json") return object(parseJson(args[1] ?? "", "--json"));
	if (args.length === 2 && args[0] === "--input") return object(parseJson(args[1] === "-" ? readStdin() : read(args[1] ?? ""), args[1] ?? ""));
	die("use --input <path|-> or --json <object>");
}

function textFlag(flags: Map<string, string>, name: string): string {
	const value = flags.get(name);
	const file = flags.get(`${name}-file`);
	if ((value ? 1 : 0) + (file ? 1 : 0) !== 1) die(`use exactly one of ${name} <text> or ${name}-file <path>`);
	return value ?? read(file!);
}

function flagsOf(args: string[], permitted: string[]): Map<string, string> {
	const flags = new Map<string, string>();
	for (let i = 0; i < args.length; i += 2) {
		const name = args[i];
		const value = args[i + 1];
		if (!name || !name.startsWith("--") || !value || value.startsWith("--")) die(`expected option/value pairs, got '${args.join(" ")}'`);
		if (!permitted.includes(name)) die(`unknown option ${name}`);
		if (flags.has(name)) die(`${name} was given more than once`);
		flags.set(name, value);
	}
	return flags;
}

function requiredFlag(flags: Map<string, string>, name: string): string {
	return flags.get(name) ?? die(`${name} is required`);
}

function numberFlag(flags: Map<string, string>, name: string): number {
	const value = requiredFlag(flags, name);
	const number = Number(value);
	if (!Number.isInteger(number) || number < 1) die(`${name} must be a positive integer`);
	return number;
}

function read(path: string): string {
	try {
		return readFileSync(path, "utf8");
	} catch {
		die(`cannot read '${path}'`);
	}
}

function readStdin(): string {
	try {
		return readFileSync(0, "utf8");
	} catch {
		die("cannot read stdin");
	}
}

function parseJson(text: string, source: string): unknown {
	try {
		return JSON.parse(text);
	} catch {
		die(`invalid JSON from ${source}`);
	}
}

function object(value: unknown): Record<string, unknown> {
	if (typeof value !== "object" || value === null || Array.isArray(value)) die("command input must be a JSON object");
	return value as Record<string, unknown>;
}

function request(payload: object): Promise<{ ok: boolean; output?: string; error?: string }> {
	return new Promise((resolve, reject) => {
		const connection = connect(socket!);
		let body = "";
		connection.setEncoding("utf8");
		connection.setTimeout(10_000);
		connection.on("connect", () => connection.write(`${JSON.stringify(payload)}\n`));
		connection.on("data", (chunk: string) => (body += chunk));
		connection.on("timeout", () => connection.destroy(new Error("OpenSec bridge timed out")));
		connection.on("end", () => {
			try {
				resolve(JSON.parse(body));
			} catch {
				reject(new Error("invalid response from OpenSec bridge"));
			}
		});
		connection.on("error", reject);
	});
}

function help(): string {
	return [
		"USAGE",
		"  opensec <group> <command> [options]",
		"",
		"COMMANDS",
		...commands
			.filter((command) => allowed.size === 0 || allowed.has(command.verb))
			.map((command) => `  ${command.usage}\n      ${command.note}`),
		"",
		"Use --help after a command for its syntax. Commands print JSON. Use --input <path|-> for complex payloads.",
	].join("\n");
}

function commandHelp(command: Command): string {
	return `${command.usage}\n\n${command.note}`;
}

function context(): string {
	return JSON.stringify(
		{
			workspace: "/workspace/repo",
			worker: process.env.OPENSEC_WORKER ?? "unknown",
			commands: commands
				.filter((command) => allowed.size === 0 || allowed.has(command.verb))
				.map((command) => command.words.join(" ")),
		},
		null,
		2,
	);
}

function die(message: string, code = 1): never {
	process.stderr.write(`${message}\n`);
	process.exit(code);
}

void main().catch((err) => die((err as Error).message));
