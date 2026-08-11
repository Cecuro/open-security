import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connect } from "node:net";
import { once } from "node:events";
import { afterEach, describe, expect, it, vi } from "vitest";

import { OpensecBridge } from "../src/agents/bridge.js";
import { runAgentCli } from "../src/cli/agent.js";
import type { RunContext } from "../src/agents/tool.js";
import { Ledger } from "../src/db/db.js";
import { testScanConfig } from "./config.js";

const bridges: OpensecBridge[] = [];

afterEach(async () => {
	await Promise.all(bridges.splice(0).map((bridge) => bridge.dispose()));
});

function setup(): RunContext {
	const root = mkdtempSync(join(tmpdir(), "opensec-bridge-"));
	writeFileSync(join(root, "app.js"), "one\ntwo\n");
	const ledger = Ledger.open(join(root, "ledger.db"));
	const repoId = ledger.upsertRepo(root, "fixture", null);
	ledger.createScan({ id: "scan", repoId, revision: null, config: testScanConfig("container") });
	ledger.insertFiles("scan", [{ path: "app.js", sha: "x", bytes: 8, excludedReason: null }]);
	return { scanId: "scan", workerId: "probe", repoRoot: root, profile: "container", ledger, nonce: "nonce" };
}

function bridgeFiles(): { cliPath: string; relayPath: string } {
	const dir = mkdtempSync(join(tmpdir(), "opensec-cli-"));
	const cliPath = join(dir, "opensec-cli.js");
	const relayPath = join(dir, "opensec-relay.js");
	writeFileSync(cliPath, "process.exit(0);\n");
	writeFileSync(relayPath, "process.exit(0);\n");
	return { cliPath, relayPath };
}

async function request(endpoint: string, token: string, payload: object): Promise<{ ok: boolean; output?: string; error?: string }> {
	const response = await fetch(endpoint, {
		method: "POST",
		headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
		body: JSON.stringify(payload),
	});
	return response.json() as Promise<{ ok: boolean; output?: string; error?: string }>;
}

describe("OpenSec sandbox bridge", () => {
	it("only accepts its run token and applies the existing worklist rules", async () => {
		const bridge = await OpensecBridge.create(setup(), bridgeFiles());
		bridges.push(bridge);
		expect(bridge.mount).toMatchObject({ verbs: "" });
		expect(existsSync(join(bridge.mount.mountDir, "opensec-cli.mjs"))).toBe(true);
		expect(existsSync(join(bridge.mount.mountDir, "opensec-relay.mjs"))).toBe(true);
		expect(existsSync(join(bridge.mount.mountDir, "opensec"))).toBe(true);

		await expect(request(bridge.mount.endpoint, "wrong", { verb: "work.next" })).resolves.toEqual({
			ok: false,
			error: "unauthorized",
		});
		const response = await request(bridge.mount.endpoint, bridge.mount.token, { verb: "work.next", params: { limit: 1 } });
		expect(response.ok).toBe(true);
		expect(JSON.parse(response.output ?? "{}").files.join(" ")).toContain("app.js");
		await expect(request(bridge.mount.endpoint, bridge.mount.token, { verb: "work.next", params: { limti: 1 } })).resolves.toEqual({
			ok: false,
			error: "work.next does not accept: limti",
		});
		const context = await request(bridge.mount.endpoint, bridge.mount.token, { verb: "context" });
		expect(context.ok).toBe(true);
		expect(JSON.parse(context.output ?? "{}")).toMatchObject({
			workspace: "/workspace/repo",
			worker: "probe",
		});
	});

	it("does not let params replace the authenticated top-level verb", async () => {
		const bridge = await OpensecBridge.create(setup(), bridgeFiles());
		bridges.push(bridge);

		await expect(
			request(bridge.mount.endpoint, bridge.mount.token, {
				verb: "work.next",
				params: { verb: "lead.record", text: "should not be recorded" },
			}),
		).resolves.toEqual({ ok: false, error: "work.next does not accept: text" });
	});

	it("serves CLI context through the real bridge", async () => {
		const ctx = setup();
		ctx.verbs = ["work.next"];
		const bridge = await OpensecBridge.create(ctx, { ...bridgeFiles(), workspace: ctx.repoRoot });
		bridges.push(bridge);
		const oldEndpoint = process.env.OPENSEC_ENDPOINT;
		const oldToken = process.env.OPENSEC_TOKEN;
		const oldVerbs = process.env.OPENSEC_VERBS;
		process.env.OPENSEC_ENDPOINT = bridge.mount.endpoint;
		process.env.OPENSEC_TOKEN = bridge.mount.token;
		process.env.OPENSEC_VERBS = bridge.mount.verbs;
		const output: string[] = [];
		const write = vi.spyOn(process.stdout, "write").mockImplementation((chunk) => {
			output.push(String(chunk));
			return true;
		});

		try {
			expect(await runAgentCli(["context"])).toBe(0);
			expect(JSON.parse(output.join("").trim())).toMatchObject({
				workspace: ctx.repoRoot,
				worker: "probe",
				commands: ["work next"],
			});
		} finally {
			write.mockRestore();
			restoreEnv("OPENSEC_ENDPOINT", oldEndpoint);
			restoreEnv("OPENSEC_TOKEN", oldToken);
			restoreEnv("OPENSEC_VERBS", oldVerbs);
		}
	});

	it("round-trips finding text through JSON without treating it as shell syntax", async () => {
		const ctx = setup();
		ctx.verbs = ["candidate.validate"];
		ctx.resolvableIds = ["c1"];
		ctx.dispositions = ["confirmed", "not_applicable", "needs_follow_up"];
		ctx.ledger.upsertCandidate({
			scanId: "scan",
			workerId: "probe",
			title: "finding",
			cweIds: [],
			locations: [{ path: "app.js", start_line: 1, end_line: 1 }],
			description: "description",
		});
		const bridge = await OpensecBridge.create(ctx, { ...bridgeFiles(), workspace: ctx.repoRoot });
		bridges.push(bridge);
		const oldEndpoint = process.env.OPENSEC_ENDPOINT;
		const oldToken = process.env.OPENSEC_TOKEN;
		const oldVerbs = process.env.OPENSEC_VERBS;
		process.env.OPENSEC_ENDPOINT = bridge.mount.endpoint;
		process.env.OPENSEC_TOKEN = bridge.mount.token;
		process.env.OPENSEC_VERBS = bridge.mount.verbs;
		const rationale = 'literal $(whoami), `uname`, "$HOME", and a single quote\'';
		const input = join(ctx.repoRoot, "validation.json");
		writeFileSync(input, JSON.stringify({ id: "c1", disposition: "confirmed", rationale }));
		const write = vi.spyOn(process.stdout, "write").mockImplementation(() => true);

		try {
			expect(
				await runAgentCli([
					"candidate",
					"validate",
					"--input",
					input,
				]),
			).toBe(0);
			expect(ctx.ledger.getCandidate("scan", "c1")?.activities[0]?.body).toBe(rationale);
		} finally {
			write.mockRestore();
			restoreEnv("OPENSEC_ENDPOINT", oldEndpoint);
			restoreEnv("OPENSEC_TOKEN", oldToken);
			restoreEnv("OPENSEC_VERBS", oldVerbs);
		}
	});

	it("closes idle clients during cleanup", async () => {
		const bridge = await OpensecBridge.create(setup(), bridgeFiles());
		const endpoint = new URL(bridge.mount.endpoint);
		const client = connect(Number(endpoint.port), endpoint.hostname);
		client.on("error", () => {});
		await once(client, "connect");

		await bridge.dispose();
		expect(existsSync(bridge.mount.mountDir)).toBe(false);
		client.destroy();
	});
});

function restoreEnv(name: string, value: string | undefined): void {
	if (value === undefined) delete process.env[name];
	else process.env[name] = value;
}
