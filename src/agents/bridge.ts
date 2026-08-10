import { randomBytes } from "node:crypto";
import { chmodSync, copyFileSync, existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer, type Server } from "node:net";

import { runOpensec, type RunContext, type Verb } from "./tool.js";

const MAX_REQUEST_BYTES = 1_000_000;

export interface SandboxBridgeMount {
	mountDir: string;
	token: string;
	verbs: string;
	worker: string;
}

export interface BridgeOptions {
	cliPath?: string;
}

type Request = { token?: unknown; verb?: unknown; params?: unknown };

/** A run-scoped, token-gated socket that exposes ledger commands to one sandbox. */
export class OpensecBridge {
	readonly mount: SandboxBridgeMount;
	private constructor(
		private readonly server: Server,
		private readonly dir: string,
		token: string,
		verbs: readonly Verb[],
		worker: string,
	) {
		this.mount = { mountDir: dir, token, verbs: verbs.join(","), worker };
	}

	static async create(ctx: RunContext, opts: BridgeOptions = {}): Promise<OpensecBridge> {
		const dir = mkdtempSync(join(tmpdir(), "opensec-bridge-"));
		const socket = join(dir, "opensec.sock");
		const token = randomBytes(32).toString("base64url");
		copyFileSync(opts.cliPath ?? compiledCliPath(), join(dir, "opensec-cli.js"));
		chmodSync(dir, 0o755);

		const server = createServer((connection) => {
			let body = "";
			connection.setEncoding("utf8");
			connection.on("data", (chunk: string) => {
				body += chunk;
				if (Buffer.byteLength(body) > MAX_REQUEST_BYTES) {
					connection.end(JSON.stringify({ ok: false, error: "request exceeds 1 MB" }) + "\n");
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
		return new OpensecBridge(server, dir, token, ctx.verbs ?? [], ctx.workerId);
	}

	async dispose(): Promise<void> {
		await new Promise<void>((resolve, reject) => this.server.close((err) => (err ? reject(err) : resolve())));
		rmSync(this.dir, { recursive: true, force: true });
	}
}

function compiledCliPath(): string {
	const compiled = fileURLToPath(new URL("./opensec-cli.js", import.meta.url));
	if (!existsSync(compiled)) throw new Error("compiled OpenSec CLI is missing; run npm run build first");
	return compiled;
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
