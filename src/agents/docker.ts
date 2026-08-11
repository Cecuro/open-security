import { randomBytes } from "node:crypto";
import { spawn, type SpawnOptions } from "node:child_process";

import { defineTool } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

import type { SandboxBridgeMount } from "./bridge.js";

const DEFAULT_IMAGE = "opensec-agent:node20-rust1.88-bookworm-v1";
export const DEFAULT_IMAGE_DOCKERFILE = `FROM rust:1.88-bookworm AS rust
FROM node:20-bookworm-slim

COPY --from=rust /usr/local/cargo /usr/local/cargo
COPY --from=rust /usr/local/rustup /usr/local/rustup

ENV CARGO_HOME=/home/node/.cargo \\
    RUSTUP_HOME=/usr/local/rustup \\
    PATH=/usr/local/cargo/bin:$PATH

RUN apt-get update \\
 && apt-get install -y --no-install-recommends \\
      build-essential \\
      ca-certificates \\
      curl \\
      git \\
      jq \\
      pkg-config \\
      python3 \\
      ripgrep \\
 && rm -rf /var/lib/apt/lists/* \\
 && for tool in cargo cargo-clippy cargo-fmt clippy-driver rustc rustdoc rustfmt rustup; do \\
      ln -s /usr/local/cargo/bin/$tool /usr/local/bin/$tool; \\
    done
`;
const MAX_TIMEOUT_MS = 10 * 60_000;
const SANDBOX_LIFETIME = "2h";
const RELAY_PORT = 7331;
const MAX_CAPTURE_BYTES = 1_000_000;
const MAX_INLINE_OUTPUT_BYTES = 20_000;
const OUTPUT_HEAD_BYTES = 12_000;
const OUTPUT_TAIL_BYTES = 4_000;

export type CommandResult = {
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
		private readonly relayName?: string,
		private readonly networkName?: string,
		readonly repoDir = "/workspace/repo",
	) {}

	static async create(
		repoRoot: string,
		opts: { image?: string; bridge?: SandboxBridgeMount } = {},
	) {
		const customImage = opts.image ?? process.env.OPENSEC_SANDBOX_IMAGE;
		const image = customImage ?? DEFAULT_IMAGE;
		const id = randomBytes(9).toString("hex");
		const name = `opensec-${id}`;
		const relayName = opts.bridge ? `opensec-relay-${id}` : undefined;
		const networkName = opts.bridge ? `opensec-net-${id}` : undefined;
		const user = process.env.OPENSEC_SANDBOX_USER ?? "node";
		const sandbox = new DockerSandbox(name, user, relayName, networkName);
		try {
			const available = await runCommand("docker", ["version", "--format", "{{.Server.Version}}"]);
			if (available.exitCode !== 0) {
				throw new Error("Docker is required for --profile container. Start Docker, then try again.");
			}
			if (!customImage) await ensureDefaultImage();
			if (opts.bridge) {
				requireIsolatedGateway(available.stdout);
				await sandbox.startRelay(image, opts.bridge);
			}

			const created = await runCommand("docker", [
				"create",
				"--name",
				name,
				"--rm",
				"--label",
				"opensec.sandbox=true",
				"--network",
				networkName ?? "none",
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
						`OPENSEC_ENDPOINT=http://opensec-relay:${RELAY_PORT}/v1/command`,
						"--env",
						`OPENSEC_TOKEN=${sandbox.relayToken}`,
						"--env",
						`OPENSEC_VERBS=${opts.bridge.verbs}`,
					]
					: []),
				image,
				"sh",
				"-c",
				`exec timeout --signal=KILL ${SANDBOX_LIFETIME} sh -c 'while :; do sleep 3600; done'`,
			]);
			if (created.exitCode !== 0) throw new Error(dockerError("create", created));

			const started = await runCommand("docker", ["start", name]);
			if (started.exitCode !== 0) throw new Error(dockerError("start", started));
			const madeWorkspace = await runCommand("docker", ["exec", "--user", "0", name, "mkdir", "-p", "/workspace"]);
			if (madeWorkspace.exitCode !== 0) throw new Error(dockerError("prepare the workspace", madeWorkspace));
			const copied = await runCommand("docker", ["cp", repoRoot, `${name}:/workspace/repo`]);
			if (copied.exitCode !== 0) throw new Error(dockerError("copy the repository", copied));
			// Docker Desktop may preserve the host uid even though docker cp commonly
			// creates root-owned files. With all capabilities dropped, container root
			// cannot chmod a file owned by that host uid. Run chmod as the copied tree's
			// actual owner, then make the disposable copy writable by the agent user.
			const owner = await runCommand("docker", [
				"exec",
				"--user",
				"0",
				name,
				"stat",
				"-c",
				"%u:%g",
				"/workspace/repo",
			]);
			if (owner.exitCode !== 0) throw new Error(dockerError("inspect repository ownership", owner));
			const permissions = await runCommand("docker", [
				"exec",
				"--user",
				owner.stdout.trim(),
				name,
				"chmod",
				"-R",
				"u+rwX,go+rwX",
				"/workspace/repo",
			]);
			if (permissions.exitCode !== 0) throw new Error(dockerError("prepare repository permissions", permissions));
			if (opts.bridge) {
				const installed = await runCommand("docker", [
					"exec",
					"--user",
					"0",
					name,
					"sh",
					"-c",
					'printf "#!/bin/sh\\nexec node /run/opensec/opensec-cli.mjs \\\"\\$@\\\"\\n" > /usr/local/bin/opensec && chmod 755 /usr/local/bin/opensec',
				]);
				if (installed.exitCode !== 0) throw new Error(dockerError("install the OpenSec CLI", installed));
				const checked = await retry(() => runCommand("docker", [
					"exec", "--user", user, name, "bash", "-lc", "opensec context",
				]));
				if (checked.exitCode !== 0) throw new Error(dockerError("check Bash and the OpenSec CLI", checked));
			}
			return sandbox;
		} catch (err) {
			try {
				await sandbox.dispose();
			} catch {
				// Keep the setup error, which tells the user what failed.
			}
			throw err;
		}
	}

	private readonly relayToken = randomBytes(32).toString("base64url");

	private async startRelay(image: string, bridge: SandboxBridgeMount): Promise<void> {
		const network = this.networkName!;
		const relay = this.relayName!;
		const madeNetwork = await runCommand("docker", [
			"network", "create", "--driver", "bridge", "--internal",
			"--opt", "com.docker.network.bridge.gateway_mode_ipv4=isolated",
			"--label", "opensec.sandbox=true", network,
		]);
		if (madeNetwork.exitCode !== 0) throw new Error(dockerError("create the isolated network", madeNetwork));

		const created = await runCommand("docker", [
			"create", "--name", relay, "--rm", "--label", "opensec.sandbox=true",
			"--network", network, "--network-alias", "opensec-relay",
			"--add-host", "host.docker.internal:host-gateway",
			"--cpus", "0.25", "--memory", "128m", "--pids-limit", "64", "--cap-drop", "ALL",
			"--security-opt", "no-new-privileges", "--read-only",
			"--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
			"--mount", `type=bind,src=${bridge.mountDir},dst=/run/opensec,readonly`,
			"--env", "OPENSEC_RELAY=1",
			"--env", `OPENSEC_RELAY_PORT=${RELAY_PORT}`,
			"--env", `OPENSEC_RELAY_TOKEN=${this.relayToken}`,
			"--env", `OPENSEC_UPSTREAM_ENDPOINT=${containerEndpoint(bridge.endpoint)}`,
			"--env", `OPENSEC_UPSTREAM_TOKEN=${bridge.token}`,
			image, "sh", "-c",
			`exec timeout --signal=KILL ${SANDBOX_LIFETIME} node /run/opensec/opensec-relay.mjs`,
		]);
		if (created.exitCode !== 0) throw new Error(dockerError("create the command relay", created));
		const connected = await runCommand("docker", ["network", "connect", "bridge", relay]);
		if (connected.exitCode !== 0) throw new Error(dockerError("connect the command relay", connected));
		const started = await runCommand("docker", ["start", relay]);
		if (started.exitCode !== 0) throw new Error(dockerError("start the command relay", started));
	}

	async exec(commandLine: string, timeoutMs?: number): Promise<CommandResult> {
		const timeout = Math.min(Math.max(1, timeoutMs ?? MAX_TIMEOUT_MS), MAX_TIMEOUT_MS);
		return runCommand(
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
				'exec timeout --signal=KILL --kill-after=5s "$1" bash -lc "$2"',
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
		const saved = await runCommand(
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
		const errors: Error[] = [];
		for (const [name, action] of [[this.name, "remove sandbox"], [this.relayName, "remove command relay"]] as const) {
			if (!name) continue;
			const removed = await runCommand("docker", ["rm", "--force", name], 30_000);
			if (removed.exitCode !== 0 && !/No such container/i.test(removed.stderr)) {
				errors.push(new Error(dockerError(action, removed)));
			}
		}
		if (this.networkName) {
			const removed = await runCommand("docker", ["network", "rm", this.networkName], 30_000);
			if (removed.exitCode !== 0 && !/No such network/i.test(removed.stderr)) {
				errors.push(new Error(dockerError("remove isolated network", removed)));
			}
		}
		if (errors[0]) throw errors[0];
	}
}

function requireIsolatedGateway(version: string): void {
	const major = Number(version.trim().split(".")[0]);
	if (!Number.isInteger(major) || major < 28) {
		throw new Error("Docker Engine 28 or newer is required for an isolated container network.");
	}
}

async function retry(run: () => Promise<CommandResult>): Promise<CommandResult> {
	let result = await run();
	for (let attempt = 1; attempt < 20 && result.exitCode !== 0; attempt++) {
		await new Promise<void>((resolve) => setTimeout(resolve, 100));
		result = await run();
	}
	return result;
}

function containerEndpoint(endpoint: string): string {
	const url = new URL(endpoint);
	url.hostname = "host.docker.internal";
	return url.toString();
}

async function ensureDefaultImage(): Promise<void> {
	const existing = await runCommand("docker", ["image", "inspect", DEFAULT_IMAGE]);
	if (existing.exitCode === 0) return;
	const built = await runCommand(
		"docker",
		["build", "--tag", DEFAULT_IMAGE, "-"],
		10 * 60_000,
		DEFAULT_IMAGE_DOCKERFILE,
	);
	if (built.exitCode !== 0) throw new Error(dockerError("build the default agent image", built));
}

export type BashSandbox = Pick<DockerSandbox, "exec" | "repoDir" | "writeOutput">;

export function createBashTool(
	sandbox: BashSandbox,
	description = `Run a Bash command in the workspace at ${sandbox.repoDir}. Commands run for at most 10 minutes.`,
) {
	return defineTool({
		name: "bash",
		label: "bash",
		description,
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

export async function runCommand(
	program: string,
	args: string[],
	timeoutMs = 30_000,
	input?: string,
	options: Pick<SpawnOptions, "cwd" | "env"> & { killProcessGroup?: boolean } = {},
): Promise<CommandResult> {
	return new Promise((resolve) => {
		const child = spawn(program, args, {
			cwd: options.cwd,
			env: options.env,
			detached: options.killProcessGroup,
			stdio: [input == null ? "ignore" : "pipe", "pipe", "pipe"],
		});
		let stdout = "";
		let stderr = "";
		let stdoutTruncated = false;
		let stderrTruncated = false;
		let timedOut = false;
		const timer = setTimeout(() => {
			timedOut = true;
			try {
				if (options.killProcessGroup && child.pid) process.kill(-child.pid, "SIGKILL");
				else child.kill("SIGKILL");
			} catch {
				// The command finished between the timeout and the kill.
			}
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
