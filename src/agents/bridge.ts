import { randomBytes } from "node:crypto";
import { chmodSync, copyFileSync, existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer, type Server } from "node:net";

import { runOpensec, type RunContext, type Verb } from "./tool.js";

const MAX_REQUEST_BYTES = 128_000;

export interface SandboxBridgeMount {
	mountDir: string;
	token: string;
}

type Request = { token?: unknown; verb?: unknown; params?: unknown };

/** A run-scoped, token-gated socket that exposes ledger commands to one sandbox. */
export class OpensecBridge {
	readonly mount: SandboxBridgeMount;
	private constructor(
		private readonly server: Server,
		private readonly dir: string,
		token: string,
	) {
		this.mount = { mountDir: dir, token };
	}

	static async create(ctx: RunContext): Promise<OpensecBridge> {
		const dir = mkdtempSync(join(tmpdir(), "opensec-bridge-"));
		const socket = join(dir, "opensec.sock");
		const token = randomBytes(32).toString("base64url");
		copyFileSync(cliPath(), join(dir, "opensec-cli.js"));
		chmodSync(dir, 0o755);

		const server = createServer((connection) => {
			let body = "";
			connection.setEncoding("utf8");
			connection.on("data", (chunk: string) => {
				body += chunk;
				if (Buffer.byteLength(body) > MAX_REQUEST_BYTES) {
					connection.end(JSON.stringify({ ok: false, error: "request exceeds 128 KB" }) + "\n");
					return;
				}
				const newline = body.indexOf("\n");
				if (newline === -1) return;
				connection.end(reply(ctx, token, body.slice(0, newline)) + "\n");
			});
		});

		await new Promise<void>((resolve, reject) => {
			server.once("error", reject);
			server.listen(socket, () => {
				server.off("error", reject);
				resolve();
			});
		});
		chmodSync(socket, 0o666);
		return new OpensecBridge(server, dir, token);
	}

	async dispose(): Promise<void> {
		await new Promise<void>((resolve, reject) => this.server.close((err) => (err ? reject(err) : resolve())));
		rmSync(this.dir, { recursive: true, force: true });
	}
}

function cliPath(): string {
	const compiled = fileURLToPath(new URL("./opensec-cli.js", import.meta.url));
	return existsSync(compiled) ? compiled : fileURLToPath(new URL("./opensec-cli.ts", import.meta.url));
}

function reply(ctx: RunContext, token: string, raw: string): string {
	try {
		const request = JSON.parse(raw) as Request;
		if (request.token !== token) return JSON.stringify({ ok: false, error: "unauthorized" });
		if (typeof request.verb !== "string") return JSON.stringify({ ok: false, error: "verb is required" });
		if (request.params !== undefined && (typeof request.params !== "object" || request.params === null || Array.isArray(request.params))) {
			return JSON.stringify({ ok: false, error: "params must be a JSON object" });
		}
		const output = runOpensec(ctx, { verb: request.verb as Verb, ...(request.params as object | undefined) });
		return JSON.stringify({ ok: true, output });
	} catch (err) {
		return JSON.stringify({ ok: false, error: (err as Error).message });
	}
}
