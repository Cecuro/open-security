import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";

import { createRelayServer } from "../src/agents/relay.js";

const servers: Server[] = [];

afterEach(async () => {
	await Promise.all(servers.splice(0).map((server) => close(server)));
});

describe("isolated command relay", () => {
	it("forwards only authenticated commands to its fixed upstream", async () => {
		let upstreamAuth: string | undefined;
		let upstreamCalls = 0;
		const upstream = createServer((request, response) => {
			upstreamCalls++;
			upstreamAuth = request.headers.authorization;
			response.setHeader("content-type", "application/json");
			response.end('{"ok":true,"output":"done"}\n');
		});
		const upstreamPort = await listen(upstream);

		const relay = createRelayServer({
			upstreamEndpoint: `http://127.0.0.1:${upstreamPort}/v1/command`,
			upstreamToken: "host-secret",
			clientToken: "worker-secret",
		});
		const relayPort = await listen(relay);

		const wrong = await fetch(`http://127.0.0.1:${relayPort}/v1/command`, {
			method: "POST",
			headers: { authorization: "Bearer wrong" },
			body: "{}",
		});
		expect(wrong.status).toBe(401);
		expect(upstreamCalls).toBe(0);

		const response = await fetch(`http://127.0.0.1:${relayPort}/v1/command`, {
			method: "POST",
			headers: { authorization: "Bearer worker-secret", "content-type": "application/json" },
			body: '{"verb":"context"}',
		});
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true, output: "done" });
		expect(upstreamAuth).toBe("Bearer host-secret");
		expect(upstreamCalls).toBe(1);
	});
});

async function listen(server: Server): Promise<number> {
	await new Promise<void>((resolve, reject) => {
		server.once("error", reject);
		server.listen(0, "127.0.0.1", () => {
			server.off("error", reject);
			resolve();
		});
	});
	servers.push(server);
	return (server.address() as AddressInfo).port;
}

function close(server: Server): Promise<void> {
	return new Promise((resolve, reject) => server.close((err) => err ? reject(err) : resolve()));
}
