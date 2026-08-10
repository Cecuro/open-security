import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connect } from "node:net";
import { afterEach, describe, expect, it } from "vitest";

import { OpensecBridge } from "../src/agents/bridge.js";
import type { RunContext } from "../src/agents/tool.js";
import { Ledger } from "../src/db/db.js";

const bridges: OpensecBridge[] = [];

afterEach(async () => {
	await Promise.all(bridges.splice(0).map((bridge) => bridge.dispose()));
});

function setup(): RunContext {
	const root = mkdtempSync(join(tmpdir(), "opensec-bridge-"));
	writeFileSync(join(root, "app.js"), "one\ntwo\n");
	const ledger = Ledger.open(join(root, "ledger.db"));
	const repoId = ledger.upsertRepo(root, "fixture", null);
	ledger.createScan({ id: "scan", repoId, revision: null, profile: "container", configHash: "h" });
	ledger.insertFiles("scan", [{ path: "app.js", sha: "x", bytes: 8, excludedReason: null }]);
	return { scanId: "scan", workerId: "probe", repoRoot: root, profile: "container", ledger, nonce: "nonce" };
}

function cliFixture(): string {
	const file = join(mkdtempSync(join(tmpdir(), "opensec-cli-")), "opensec-cli.js");
	writeFileSync(file, "process.exit(0);\n");
	return file;
}

function request(socket: string, payload: object): Promise<{ ok: boolean; output?: string; error?: string }> {
	return new Promise((resolve, reject) => {
		const client = connect(socket);
		let body = "";
		client.setEncoding("utf8");
		client.on("connect", () => client.write(`${JSON.stringify(payload)}\n`));
		client.on("data", (chunk: string) => (body += chunk));
		client.on("end", () => resolve(JSON.parse(body)));
		client.on("error", reject);
	});
}

describe("OpenSec sandbox bridge", () => {
	it("only accepts its run token and applies the existing worklist rules", async () => {
		const bridge = await OpensecBridge.create(setup(), { cliPath: cliFixture() });
		bridges.push(bridge);
		expect(bridge.mount).toMatchObject({ verbs: "", worker: "probe" });
		const socket = join(bridge.mount.mountDir, "opensec.sock");

		await expect(request(socket, { token: "wrong", verb: "work.next" })).resolves.toEqual({
			ok: false,
			error: "unauthorized",
		});
		const response = await request(socket, { token: bridge.mount.token, verb: "work.next", params: { limit: 1 } });
		expect(response.ok).toBe(true);
		expect(JSON.parse(response.output ?? "{}").files.join(" ")).toContain("app.js");
		await expect(request(socket, { token: bridge.mount.token, verb: "work.next", params: { limti: 1 } })).resolves.toEqual({
			ok: false,
			error: "work.next does not accept: limti",
		});
	});
});
