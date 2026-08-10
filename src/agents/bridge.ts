import { randomBytes } from "node:crypto";
import { chmodSync, copyFileSync, existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer, type Server, type Socket } from "node:net";

import { runOpensec, type RunContext, type Verb } from "./tool.js";

const MAX_REQUEST_BYTES = 1_000_000;
const CONNECTION_TIMEOUT_MS = 10_000;
const MAX_CONNECTIONS = 32;

export interface SandboxBridgeMount {
	mountDir: string;
	token: string;
	verbs: string;
}

export interface BridgeOptions {
	cliPath?: string;
	workspace?: string;
}

type Request = { token?: unknown; verb?: unknown; params?: unknown };

/** A run-scoped, token-gated socket that exposes ledger commands to one sandbox. */
export class OpensecBridge {
	readonly mount: SandboxBridgeMount;
	private constructor(
		private readonly server: Server,
		private readonly connections: Set<Socket>,
		private readonly dir: string,
		token: string,
		verbs: readonly Verb[],
	) {
		this.mount = { mountDir: dir, token, verbs: verbs.join(",") };
	}

	static async create(ctx: RunContext, opts: BridgeOptions = {}): Promise<OpensecBridge> {
		const dir = mkdtempSync(join(tmpdir(), "opensec-bridge-"));
		const socket = join(dir, "opensec.sock");
		const token = randomBytes(32).toString("base64url");
		const connections = new Set<Socket>();
		let server: Server | undefined;

		try {
			copyFileSync(opts.cliPath ?? compiledCliPath(), join(dir, "opensec-cli.mjs"));
			writeFileSync(
				join(dir, "opensec"),
				'#!/bin/sh\nexec node "$(dirname "$0")/opensec-cli.mjs" "$@"\n',
				{ mode: 0o755 },
			);
			chmodSync(dir, 0o755);

			server = createServer((connection) => {
				if (connections.size >= MAX_CONNECTIONS) {
					connection.destroy();
					return;
				}
				connections.add(connection);
				connection.once("close", () => connections.delete(connection));
				connection.on("error", () => connection.destroy());
				connection.setTimeout(CONNECTION_TIMEOUT_MS, () => connection.destroy());
				connection.setEncoding("utf8");
				let body = "";
				let answered = false;
				connection.on("data", (chunk: string) => {
					if (answered) return;
					body += chunk;
					if (Buffer.byteLength(body) > MAX_REQUEST_BYTES) {
						answered = true;
						connection.end(JSON.stringify({ ok: false, error: "request exceeds 1 MB" }) + "\n");
						return;
					}
					const newline = body.indexOf("\n");
					if (newline === -1) return;
					answered = true;
					connection.end(reply(ctx, token, opts.workspace ?? "/workspace/repo", body.slice(0, newline)) + "\n");
				});
			});
			server.maxConnections = MAX_CONNECTIONS;
			await new Promise<void>((resolve, reject) => {
				server!.once("error", reject);
				server!.listen(socket, () => {
					server!.off("error", reject);
					resolve();
				});
			});
			chmodSync(socket, 0o666);
			return new OpensecBridge(server, connections, dir, token, ctx.verbs ?? []);
		} catch (err) {
			for (const connection of connections) connection.destroy();
			if (server?.listening) {
				await new Promise<void>((resolve) => server!.close(() => resolve()));
			}
			rmSync(dir, { recursive: true, force: true });
			throw err;
		}
	}

	async dispose(): Promise<void> {
		for (const connection of this.connections) connection.destroy();
		try {
			await new Promise<void>((resolve, reject) => this.server.close((err) => (err ? reject(err) : resolve())));
		} finally {
			rmSync(this.dir, { recursive: true, force: true });
		}
	}
}

function compiledCliPath(): string {
	const compiled = fileURLToPath(new URL("../cli/agent.js", import.meta.url));
	if (!existsSync(compiled)) throw new Error("compiled OpenSec CLI is missing; run npm run build first");
	return compiled;
}

function reply(ctx: RunContext, token: string, workspace: string, raw: string): string {
	try {
		const request = JSON.parse(raw) as Request;
		if (request.token !== token) return JSON.stringify({ ok: false, error: "unauthorized" });
		if (typeof request.verb !== "string") return JSON.stringify({ ok: false, error: "verb is required" });
		if (request.verb === "context") {
			return JSON.stringify({
				ok: true,
				output: JSON.stringify({ workspace, worker: ctx.workerId, verbs: ctx.verbs ?? [] }, null, 2),
			});
		}
		if (request.params !== undefined && (typeof request.params !== "object" || request.params === null || Array.isArray(request.params))) {
			return JSON.stringify({ ok: false, error: "params must be a JSON object" });
		}
		const output = runOpensec(ctx, { ...(request.params as object | undefined), verb: request.verb as Verb });
		return JSON.stringify({ ok: true, output });
	} catch (err) {
		return JSON.stringify({ ok: false, error: (err as Error).message });
	}
}
