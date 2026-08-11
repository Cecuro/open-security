import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { Ledger } from "../src/db/db.js";
import { renderMarkdown } from "../src/scan/render.js";
import { testScanConfig } from "./config.js";

describe("cache usage", () => {
	it("persists cache buckets and renders their hit rate and economics", () => {
		const dir = mkdtempSync(join(tmpdir(), "opensec-cache-"));
		const file = join(dir, "ledger.db");
		const ledger = Ledger.open(file);
		try {
			const repoId = ledger.upsertRepo("/tmp/cache-repo", "cache-repo", null);
			ledger.createScan({
				id: "s",
				repoId,
				revision: null,
				config: testScanConfig(),
			});
			ledger.addUsage("s", {
				inputTokens: 750,
				cacheReadTokens: 250,
				cacheWriteTokens: 50,
				tokensIn: 1050,
				tokensOut: 100,
				costUsd: 0.012,
				cacheCostUsd: 0.0005,
				cacheSavingsUsd: 0.002,
			});

			const scan = ledger.getScan("s")!;
			expect(scan).toMatchObject({
				input_tokens: 750,
				cache_read_tokens: 250,
				cache_write_tokens: 50,
				tokens_in: 1050,
				cache_cost_usd: 0.0005,
				cache_savings_usd: 0.002,
			});
			const report = renderMarkdown({
				scan,
				repoName: "cache-repo",
				repoPath: "/tmp/cache-repo",
				candidates: [],
				coverage: { files_in_scope: 0, files_touched: 0, bytes_in_scope: 0, bytes_read: 0 },
				extensions: [],
				excludedFiles: 0,
				modelRef: "provider/model",
				promptHash: "h",
			});
			expect(report).toContain("750 input / 250 cache read / 50 cache write / 100 out");
			expect(report).toContain("| cache hit rate | 25.0% |");
			expect(report).toContain("| cache cost | $0.0005 |");
			expect(report).toContain("| cache savings | $0.0020 |");
		} finally {
			ledger.close();
			rmSync(dir, { recursive: true, force: true });
		}
	});
});
