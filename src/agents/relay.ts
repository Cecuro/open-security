import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

const COMMAND_PATH = "/v1/command";
const MAX_BODY_BYTES = 1_000_000;
const TIMEOUT_MS = 10_000;

export interface RelayOptions {
	upstreamEndpoint: string;
	upstreamToken: string;
	clientToken: string;
}

/** A fixed-destination relay between the isolated worker and the host bridge. */
export function createRelayServer(opts: RelayOptions): Server {
	const server = createServer((request, response) => {
		void handleRequest(opts, request, response);
	});
	server.maxConnections = 32;
	server.requestTimeout = TIMEOUT_MS;
	server.headersTimeout = TIMEOUT_MS;
	server.keepAliveTimeout = TIMEOUT_MS;
	return server;
}

async function handleRequest(
	opts: RelayOptions,
	request: IncomingMessage,
	response: ServerResponse,
): Promise<void> {
	response.setHeader("content-type", "application/json");
	try {
		if (request.method !== "POST" || request.url !== COMMAND_PATH) {
			return send(response, 404, { ok: false, error: "not found" });
		}
		if (request.headers.authorization !== `Bearer ${opts.clientToken}`) {
			return send(response, 401, { ok: false, error: "unauthorized" });
		}
		const body = await readRequestBody(request);
		const upstream = await fetch(opts.upstreamEndpoint, {
			method: "POST",
			headers: {
				authorization: `Bearer ${opts.upstreamToken}`,
				"content-type": "application/json",
			},
			body: body.toString("utf8"),
			redirect: "error",
			signal: AbortSignal.timeout(TIMEOUT_MS),
		});
		const reply = await readResponseBody(upstream);
		response.statusCode = upstream.status;
		response.end(reply);
	} catch (err) {
		const message = (err as Error).message;
		const status = message === "request exceeds 1 MB" ? 413 : 502;
		send(response, status, { ok: false, error: message });
	}
}

async function readRequestBody(request: IncomingMessage): Promise<Buffer> {
	let bytes = 0;
	const chunks: Buffer[] = [];
	for await (const chunk of request) {
		const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
		bytes += buffer.length;
		if (bytes > MAX_BODY_BYTES) throw new Error("request exceeds 1 MB");
		chunks.push(buffer);
	}
	return Buffer.concat(chunks);
}

async function readResponseBody(response: Response): Promise<Buffer> {
	const reader = response.body?.getReader();
	if (!reader) return Buffer.alloc(0);
	let bytes = 0;
	const chunks: Buffer[] = [];
	while (true) {
		const { done, value } = await reader.read();
		if (done) return Buffer.concat(chunks);
		bytes += value.byteLength;
		if (bytes > MAX_BODY_BYTES) {
			await reader.cancel();
			throw new Error("response exceeds 1 MB");
		}
		chunks.push(Buffer.from(value));
	}
}

function send(response: ServerResponse, status: number, body: object): void {
	if (response.writableEnded) return;
	response.statusCode = status;
	response.end(JSON.stringify(body) + "\n");
}

if (process.env.OPENSEC_RELAY === "1") {
	const upstreamEndpoint = requiredEnv("OPENSEC_UPSTREAM_ENDPOINT");
	const upstreamToken = requiredEnv("OPENSEC_UPSTREAM_TOKEN");
	const clientToken = requiredEnv("OPENSEC_RELAY_TOKEN");
	const port = Number(process.env.OPENSEC_RELAY_PORT ?? "7331");
	if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new Error("invalid relay port");
	createRelayServer({ upstreamEndpoint, upstreamToken, clientToken }).listen(port, "0.0.0.0");
}

function requiredEnv(name: string): string {
	const value = process.env[name];
	if (!value) throw new Error(`${name} is required`);
	return value;
}
