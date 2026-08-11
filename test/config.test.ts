import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { Ledger } from "../src/db/db.js";
import { normalizeScanConfig, scanConfigHash } from "../src/scan/config.js";

describe("normalized scan configuration", () => {
	it("applies every default and canonicalizes exclusions", () => {
		const config = normalizeScanConfig({
			modelRef: " provider/model ",
			promptHash: " prompts ",
			exclude: [" vendor/** ", "src/generated/**", "vendor/**", ""],
		});

		expect(config).toEqual({
			modelRef: "provider/model",
			profile: "container",
			scope: { kind: "repository" },
			promptHash: "prompts",
			passes: 1,
			concurrency: 4,
			maxTurns: 80,
			maxFiles: null,
			exclude: ["src/generated/**", "vendor/**"],
			maxCostUsd: null,
			refreshThreatModel: false,
		});
	});

	it("persists the exact normalized object and hashes the same value", () => {
		const ledger = Ledger.open(join(mkdtempSync(join(tmpdir(), "opensec-config-")), "l.db"));
		const repoId = ledger.upsertRepo("/tmp/config-repo", "config-repo", null);
		const config = normalizeScanConfig({
			modelRef: "provider/model",
			promptHash: "prompt-hash",
			profile: "local",
			scope: { kind: "diff", base: "main" },
			passes: 3,
			concurrency: 2,
			maxTurns: 40,
			maxFiles: 500,
			exclude: ["vendor/**"],
			maxCostUsd: 12.5,
			refreshThreatModel: true,
		});

		ledger.createScan({ id: "s", repoId, revision: "abc", config });
		const stored = ledger.getScan("s");
		expect(stored?.config).toEqual(config);
		expect(stored?.config_hash).toBe(scanConfigHash(config));
		expect(stored?.passes).toBe(3);
		expect(stored?.scope_kind).toBe("diff");
		expect(stored?.scope_base).toBe("main");
		ledger.close();
	});
});
