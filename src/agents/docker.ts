import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";

import { defineTool } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

import type { SandboxBridgeMount } from "./bridge.js";

const DEFAULT_IMAGE = "node:20-bookworm-slim";
const MAX_TIMEOUT_MS = 10 * 60_000;
const SANDBOX_LIFETIME = "2h";
const MAX_CAPTURE_BYTES = 1_000_000;
const MAX_INLINE_OUTPUT_BYTES = 20_000;
const OUTPUT_HEAD_BYTES = 12_000;
const OUTPUT_TAIL_BYTES = 4_000;

type CommandResult = {
	exitCode: number;
	stdout: string;
	stderr: string;
	stdoutTruncated: boolean;
	stderrTruncated: boolean;
	timedOut: boolean;
};

/** A disposable Docker workspace for one agent run. */
export class DockerSandbox {
	private constructor(
		private readonly name: string,
		private readonly user: string,
		readonly repoDir = "/workspace/repo",
	) {}

	static async create(
		repoRoot: string,
		opts: { image?: string; bridge?: SandboxBridgeMount } = {},
	) {
		const image = opts.image ?? process.env.OPENSEC_SANDBOX_IMAGE ?? DEFAULT_IMAGE;
		const name = `opensec-${randomBytes(9).toString("hex")}`;
		const user = process.env.OPENSEC_SANDBOX_USER ?? "node";
		const sandbox = new DockerSandbox(name, user);
		try {
			const available = await command("docker", ["version", "--format", "{{.Server.Version}}"]);
			if (available.exitCode !== 0) {
				throw new Error("Docker is required for --profile container. Start Docker, then try again.");
			}

			const created = await command("docker", [
				"create",
				"--name",
				name,
				"--rm",
				"--label",
				"opensec.sandbox=true",
				"--network",
				"none",
				"--cpus",
				"2",
				"--memory",
				"4g",
				"--pids-limit",
				"512",
				"--cap-drop",
				"ALL",
				"--security-opt",
				"no-new-privileges",
				"--tmpfs",
				"/tmp:rw,noexec,nosuid,size=512m",
				...(opts.bridge
					? [
						"--mount",
						`type=bind,src=${opts.bridge.mountDir},dst=/run/opensec,readonly`,
						"--env",
						"OPENSEC_SOCKET=/run/opensec/opensec.sock",
						"--env",
						`OPENSEC_TOKEN=${opts.bridge.token}`,
						"--env",
						`OPENSEC_VERBS=${opts.bridge.verbs}`,
						"--env",
						`OPENSEC_WORKER=${opts.bridge.worker}`,
					]
					: []),
				image,
				"sh",
				"-c",
				`exec timeout --signal=KILL ${SANDBOX_LIFETIME} sh -c 'while :; do sleep 3600; done'`,
			]);
			if (created.exitCode !== 0) throw new Error(dockerError("create", created));

			const started = await command("docker", ["start", name]);
			if (started.exitCode !== 0) throw new Error(dockerError("start", started));
			const madeWorkspace = await command("docker", ["exec", "--user", "0", name, "mkdir", "-p", "/workspace"]);
			if (madeWorkspace.exitCode !== 0) throw new Error(dockerError("prepare the workspace", madeWorkspace));
			const copied = await command("docker", ["cp", repoRoot, `${name}:/workspace/repo`]);
			if (copied.exitCode !== 0) throw new Error(dockerError("copy the repository", copied));
			// docker cp creates destination files as root. Leave capabilities dropped and
			// make the disposable copy writable instead of chowning it for the agent.
			const permissions = await command("docker", ["exec", "--user", "0", name, "chmod", "-R", "u+rwX,go+rwX", "/workspace/repo"]);
			if (permissions.exitCode !== 0) throw new Error(dockerError("prepare repository permissions", permissions));
			if (opts.bridge) {
				const installed = await command("docker", [
					"exec",
					"--user",
					"0",
					name,
					"sh",
					"-c",
					'printf "#!/bin/sh\\nexec node /run/opensec/opensec-cli.js \\\"$@\\\"\\n" > /usr/local/bin/opensec && chmod 755 /usr/local/bin/opensec',
				]);
				if (installed.exitCode !== 0) throw new Error(dockerError("install the OpenSec CLI", installed));
			}
			return sandbox;
		} catch (err) {
			await sandbox.dispose();
			throw err;
		}
	}

	async exec(commandLine: string, timeoutMs?: number): Promise<CommandResult> {
		const timeout = Math.min(Math.max(1, timeoutMs ?? MAX_TIMEOUT_MS), MAX_TIMEOUT_MS);
		return command(
			"docker",
			[
				"exec",
				"--workdir",
				this.repoDir,
				"--user",
				this.user,
				this.name,
				"sh",
				"-c",
				'exec timeout --signal=KILL --kill-after=5s "$1" sh -lc "$2"',
				"sh",
				`${Math.ceil(timeout / 1000)}s`,
				commandLine,
			],
			timeout + 10_000,
		);
	}

	async writeOutput(toolCallId: string, output: string): Promise<string> {
		const id = toolCallId.replace(/[^A-Za-z0-9_-]/g, "_").slice(0, 100) || "output";
		const path = `${this.repoDir}/.opensec/tool-output/${id}.txt`;
		const saved = await command(
			"docker",
			[
				"exec",
				"-i",
				"--user",
				this.user,
				this.name,
				"sh",
				"-c",
				'mkdir -p "$(dirname \"$1\")" && cat > "$1"',
				"sh",
				path,
			],
			30_000,
			output,
		);
		if (saved.exitCode !== 0) throw new Error(dockerError("save command output", saved));
		return path;
	}

	async dispose(): Promise<void> {
		const removed = await command("docker", ["rm", "--force", this.name], 30_000);
		if (removed.exitCode !== 0 && !/No such container/i.test(removed.stderr)) {
			throw new Error(dockerError("remove sandbox", removed));
		}
	}
}

export type BashSandbox = Pick<DockerSandbox, "exec" | "repoDir" | "writeOutput">;

export function createBashTool(sandbox: BashSandbox) {
	return defineTool({
		name: "bash",
		label: "bash",
		description:
			`Run a shell command in an isolated Docker workspace at ${sandbox.repoDir}. ` +
			"The repository copy is writable only inside this disposable container. " +
			"Commands have no network access and run for at most 10 minutes. " +
			"Large output is saved under .opensec/tool-output; inspect it with bash using sed, tail, or grep.",
		parameters: Type.Object(
			{
				command: Type.String({ description: "Shell command to run" }),
				timeout_ms: Type.Optional(Type.Integer({ minimum: 1, maximum: MAX_TIMEOUT_MS })),
			},
			{ additionalProperties: false },
		),
		async execute(id, params) {
			const { command: line, timeout_ms: timeout } = params as {
				command: string;
				timeout_ms?: number;
			};
			const result = await sandbox.exec(line, timeout);
			const output = await formatOutput(sandbox, id, result);
			return {
				content: [{ type: "text" as const, text: output }],
				details: undefined,
				isError: result.exitCode !== 0 || result.timedOut,
			};
		},
	});
}

async function command(
	program: string,
	args: string[],
	timeoutMs = 30_000,
	input?: string,
): Promise<CommandResult> {
	return new Promise((resolve) => {
		const child = spawn(program, args, { stdio: [input == null ? "ignore" : "pipe", "pipe", "pipe"] });
		let stdout = "";
		let stderr = "";
		let stdoutTruncated = false;
		let stderrTruncated = false;
		let timedOut = false;
		const timer = setTimeout(() => {
			timedOut = true;
			child.kill("SIGKILL");
		}, timeoutMs);
		child.stdout!.on("data", (chunk: Buffer) => {
			const captured = appendBounded(stdout, chunk);
			stdout = captured.text;
			stdoutTruncated ||= captured.truncated;
		});
		child.stderr!.on("data", (chunk: Buffer) => {
			const captured = appendBounded(stderr, chunk);
			stderr = captured.text;
			stderrTruncated ||= captured.truncated;
		});
		child.on("error", (err) => {
			clearTimeout(timer);
			resolve({ exitCode: 1, stdout, stderr: `${stderr}${err.message}`, stdoutTruncated, stderrTruncated, timedOut });
		});
		child.on("close", (code) => {
			clearTimeout(timer);
			resolve({ exitCode: code ?? 1, stdout, stderr, stdoutTruncated, stderrTruncated, timedOut });
		});
		if (input != null) child.stdin!.end(input);
	});
}

function appendBounded(text: string, chunk: Buffer): { text: string; truncated: boolean } {
	const room = MAX_CAPTURE_BYTES - Buffer.byteLength(text);
	if (room <= 0) return { text, truncated: true };
	if (chunk.byteLength <= room) return { text: text + chunk.toString("utf8"), truncated: false };
	return { text: text + chunk.subarray(0, room).toString("utf8"), truncated: true };
}

function dockerError(action: string, result: CommandResult): string {
	const detail = (result.stderr || result.stdout).trim();
	return `Docker could not ${action}${detail ? `: ${detail}` : ""}`;
}

async function formatOutput(sandbox: BashSandbox, toolCallId: string, result: CommandResult): Promise<string> {
	const truncation = [
		...(result.stdoutTruncated ? [`[stdout capture truncated after ${MAX_CAPTURE_BYTES} bytes]`] : []),
		...(result.stderrTruncated ? [`[stderr capture truncated after ${MAX_CAPTURE_BYTES} bytes]`] : []),
	].join("\n");
	const body = `${result.stdout}${result.stderr ? `\n[stderr]\n${result.stderr}` : ""}${truncation ? `\n${truncation}` : ""}`;
	const output = `${result.timedOut ? "ERROR: command timed out" : `exit ${result.exitCode}`}\n${body}`;
	if (Buffer.byteLength(output) <= MAX_INLINE_OUTPUT_BYTES) return output;

	try {
		const path = await sandbox.writeOutput(toolCallId, output);
		const omitted = Math.max(0, Buffer.byteLength(output) - OUTPUT_HEAD_BYTES - OUTPUT_TAIL_BYTES);
		return [
			`[output (${Buffer.byteLength(output)} bytes) saved to ${path}; ${omitted} bytes omitted below. Use bash with sed, tail, or grep to inspect the file.]`,
			clip(output, OUTPUT_HEAD_BYTES),
			`…[${omitted} bytes omitted; see ${path}]`,
			tail(output, OUTPUT_TAIL_BYTES),
		].join("\n");
	} catch {
		return clip(output, MAX_INLINE_OUTPUT_BYTES);
	}
}

function clip(text: string, maxBytes: number): string {
	if (Buffer.byteLength(text) <= maxBytes) return text;
	const head = Buffer.from(text).subarray(0, maxBytes).toString("utf8");
	return `${head}\n…[output truncated]`;
}

function tail(text: string, maxBytes: number): string {
	const bytes = Buffer.from(text);
	return bytes.subarray(Math.max(0, bytes.length - maxBytes)).toString("utf8");
}
