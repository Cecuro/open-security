import { mkdirSync, writeFileSync } from "node:fs";
import { delimiter, join } from "node:path";

import type { SandboxBridgeMount } from "./bridge.js";
import { runCommand, type BashSandbox, type CommandResult } from "./docker.js";

const MAX_TIMEOUT_MS = 10 * 60_000;

/** Bash running directly in the repository the user passed to OpenSec. */
export class LocalSandbox implements BashSandbox {
	private constructor(
		readonly repoDir: string,
		private readonly bridge: SandboxBridgeMount,
	) {}

	static async create(repoRoot: string, bridge: SandboxBridgeMount): Promise<LocalSandbox> {
		const sandbox = new LocalSandbox(repoRoot, bridge);
		const checked = await sandbox.exec("opensec context", 30_000);
		if (checked.exitCode !== 0) {
			const detail = (checked.stderr || checked.stdout).trim();
			throw new Error(`Local Bash or the OpenSec CLI is unavailable${detail ? `: ${detail}` : ""}`);
		}
		return sandbox;
	}

	exec(commandLine: string, timeoutMs?: number): Promise<CommandResult> {
		const timeout = Math.min(Math.max(1, timeoutMs ?? MAX_TIMEOUT_MS), MAX_TIMEOUT_MS);
		return runCommand("bash", ["-c", commandLine], timeout, undefined, {
			cwd: this.repoDir,
			env: {
				...process.env,
				PATH: `${this.bridge.mountDir}${delimiter}${process.env.PATH ?? ""}`,
				OPENSEC_SOCKET: join(this.bridge.mountDir, "opensec.sock"),
				OPENSEC_TOKEN: this.bridge.token,
				OPENSEC_VERBS: this.bridge.verbs,
			},
			killProcessGroup: true,
		});
	}

	async writeOutput(toolCallId: string, output: string): Promise<string> {
		const id = toolCallId.replace(/[^A-Za-z0-9_-]/g, "_").slice(0, 100) || "output";
		const dir = join(this.bridge.mountDir, "tool-output");
		const path = join(dir, `${id}.txt`);
		mkdirSync(dir, { recursive: true, mode: 0o700 });
		writeFileSync(path, output, { mode: 0o600 });
		return path;
	}

	async dispose(): Promise<void> {}
}
