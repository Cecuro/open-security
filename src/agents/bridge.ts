import { randomBytes } from "node:crypto";
import { chmodSync, copyFileSync, existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo, Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { runOpensec, type RunContext, type Verb } from "./tool.js";

const COMMAND_PATH = "/v1/command";
const MAX_REQUEST_BYTES = 1_000_000;
const CONNECTION_TIMEOUT_MS = 10_000;
const MAX_CONNECTIONS = 32;

export interface SandboxBridgeMount {
	mountDir: string;
	endpoint: string;
	token: string;
	verbs: string;
}

export interface BridgeOptions {
	cliPath?: string;
	workspace?: string;
}

type Request = { verb?: unknown; params?: unknown };

/** A run-scoped, token-gated HTTP endpoint that exposes ledger commands to one sandbox. */
export class OpensecBridge {
	readonly mount: SandboxBridgeMount;
	private constructor(
		private readonly server: Server,
		private readonly connections: Set<Socket>,
		private readonly dir: string,
		token: string,
		verbs: readonly Verb[],
		endpoint: string,
	) {
		this.mount = { mountDir: dir, endpoint, token, verbs: verbs.join(",") };
	}

	static async create(ctx: RunContext, opts: BridgeOptions = {}): Promise<OpensecBridge> {
		const dir = mkdtempSync(join(tmpdir(), "opensec-bridge-"));
		const token = randomBytes(32).toString("base64url");
		const connections = new Set<Socket>();
		const listenHost = ctx.profile === "container" ? "0.0.0.0" : "127.0.0.1";
		let server: Server | undefined;

		try {
			copyFileSync(opts.cliPath ?? compiledCliPath(), join(dir, "opensec-cli.mjs"));
			writeFileSync(
				join(dir, "opensec"),
				'#!/bin/sh\nexec node "$(dirname "$0")/opensec-cli.mjs" "$@"\n',
				{ mode: 0o755 },
			);
			chmodSync(dir, 0o755);

			server = createServer((request, response) => {
				void handleRequest(ctx, token, opts.workspace ?? "/workspace/repo", request, response);
			});
			server.on("connection", (connection) => {
				connections.add(connection);
				connection.once("close", () => connections.delete(connection));
			});
			server.maxConnections = MAX_CONNECTIONS;
			server.requestTimeout = CONNECTION_TIMEOUT_MS;
			server.headersTimeout = CONNECTION_TIMEOUT_MS;
			server.keepAliveTimeout = CONNECTION_TIMEOUT_MS;
			await new Promise<void>((resolve, reject) => {
				server!.once("error", reject);
				server!.listen(0, listenHost, () => {
					server!.off("error", reject);
					resolve();
				});
			});
			const port = (server.address() as AddressInfo).port;
			const endpoint = `http://127.0.0.1:${port}${COMMAND_PATH}`;
			return new OpensecBridge(server, connections, dir, token, ctx.verbs ?? [], endpoint);
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

async function handleRequest(
	ctx: RunContext,
	token: string,
	workspace: string,
	request: IncomingMessage,
	response: ServerResponse,
): Promise<void> {
	response.setHeader("content-type", "application/json");
	try {
		if (request.method !== "POST" || request.url !== COMMAND_PATH) {
			return send(response, 404, { ok: false, error: "not found" });
		}
		if (request.headers.authorization !== `Bearer ${token}`) {
			return send(response, 401, { ok: false, error: "unauthorized" });
		}
		const raw = await readBody(request);
		send(response, 200, reply(ctx, workspace, raw));
	} catch (err) {
		const message = (err as Error).message;
		send(response, message === "request exceeds 1 MB" ? 413 : 400, { ok: false, error: message });
	}
}

async function readBody(request: IncomingMessage): Promise<string> {
	let bytes = 0;
	const chunks: Buffer[] = [];
	for await (const chunk of request) {
		const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
		bytes += buffer.length;
		if (bytes > MAX_REQUEST_BYTES) throw new Error("request exceeds 1 MB");
		chunks.push(buffer);
	}
	return Buffer.concat(chunks).toString("utf8");
}

function send(response: ServerResponse, status: number, body: object): void {
	if (response.writableEnded) return;
	response.statusCode = status;
	response.end(JSON.stringify(body) + "\n");
}

function reply(ctx: RunContext, workspace: string, raw: string): object {
	try {
		const request = JSON.parse(raw) as Request;
		if (typeof request.verb !== "string") return { ok: false, error: "verb is required" };
		if (request.verb === "context") {
			return {
				ok: true,
				output: JSON.stringify({ workspace, worker: ctx.workerId, verbs: ctx.verbs ?? [] }, null, 2),
			};
		}
		if (request.params !== undefined && (typeof request.params !== "object" || request.params === null || Array.isArray(request.params))) {
			return { ok: false, error: "params must be a JSON object" };
		}
		const output = runOpensec(ctx, { ...(request.params as object | undefined), verb: request.verb as Verb });
		return { ok: true, output };
	} catch (err) {
		return { ok: false, error: (err as Error).message };
	}
}
