#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { connect } from "node:net";

const socket = process.env.OPENSEC_SOCKET;
const token = process.env.OPENSEC_TOKEN;

async function main(): Promise<void> {
	const [verb, ...rest] = process.argv.slice(2);
	if (!socket || !token) die("this command only works inside an OpenSec container run");
	if (!verb || verb === "--help" || verb === "-h") die(help(), 0);
	const params = readParams(rest);
	const response = await request({ token, verb, params });
	if (!response.ok) die(response.error ?? "OpenSec command failed");
	process.stdout.write(`${response.output}\n`);
}

function readParams(args: string[]): Record<string, unknown> {
	if (args.length === 0) return {};
	if (args.length === 2 && args[0] === "--json") return object(JSON.parse(args[1] ?? ""));
	if (args.length === 2 && args[0] === "--json-file") return object(JSON.parse(readFileSync(args[1] ?? "", "utf8")));
	die(`expected --json <object> or --json-file <path>\n\n${help()}`);
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
		connection.on("connect", () => connection.write(`${JSON.stringify(payload)}\n`));
		connection.on("data", (chunk: string) => (body += chunk));
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
		"  opensec <verb> [--json <object> | --json-file <path>]",
		"",
		"Examples",
		"  opensec work.next",
		"  opensec lead.record --json '{\"text\":\"auth check blocks this path\",\"status\":\"dead_end\"}'",
		"  opensec candidate.create --json-file /tmp/candidate.json",
		"",
		"Use --json-file for findings or rationales that do not fit cleanly in shell quoting.",
	].join("\n");
}

function die(message: string, code = 1): never {
	process.stderr.write(`${message}\n`);
	process.exit(code);
}

void main().catch((err) => die((err as Error).message));
