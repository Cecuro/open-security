import { chmodSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { LocalSandbox } from "../src/agents/local.js";

function setup() {
	const repo = mkdtempSync(join(tmpdir(), "opensec-local-repo-"));
	const mountDir = mkdtempSync(join(tmpdir(), "opensec-local-bridge-"));
	const cli = join(mountDir, "opensec");
	writeFileSync(cli, '#!/bin/sh\nprintf "context:%s" "$OPENSEC_TOKEN"\n');
	chmodSync(cli, 0o755);
	return { repo, bridge: { mountDir, token: "secret", verbs: "work.next" } };
}

describe("local Bash backend", () => {
	it("runs in the user checkout with the run-scoped CLI environment", async () => {
		const { repo, bridge } = setup();
		const sandbox = await LocalSandbox.create(repo, bridge);

		const result = await sandbox.exec('printf "changed" > local-proof.txt; opensec context');

		expect(result.exitCode).toBe(0);
		expect(result.stdout).toBe("context:secret");
		expect(readFileSync(join(repo, "local-proof.txt"), "utf8")).toBe("changed");
	});

	it("stores large tool output outside the user's repository", async () => {
		const { repo, bridge } = setup();
		const sandbox = await LocalSandbox.create(repo, bridge);

		const path = await sandbox.writeOutput("call/1", "large output");

		expect(path.startsWith(bridge.mountDir)).toBe(true);
		expect(existsSync(join(repo, ".opensec"))).toBe(false);
		expect(readFileSync(path, "utf8")).toBe("large output");
	});

	it("kills a timed-out Bash process group", async () => {
		const { repo, bridge } = setup();
		const sandbox = await LocalSandbox.create(repo, bridge);

		const result = await sandbox.exec("sleep 2", 10);

		expect(result.timedOut).toBe(true);
		expect(result.exitCode).not.toBe(0);
	});
});
