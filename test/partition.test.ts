import { describe, expect, it } from "vitest";

import {
	DEFAULT_PARTITION_MAX_FILES,
	describeDistribution,
	mapConcurrent,
	partition,
} from "../src/scan/partition.js";

const files = (n: number, prefix = "src") =>
	Array.from({ length: n }, (_, i) => ({
		path: `${prefix}/f${String(i).padStart(3, "0")}.ts`,
		bytes: 100,
	}));

describe("partitioning splits ownership, and only ownership", () => {
	it("keeps a small repo on one probe", () => {
		const parts = partition(files(10));
		expect(parts).toHaveLength(1);
		expect(parts[0]?.paths).toHaveLength(10);
	});

	it("splits once the cap is exceeded, and balances rather than filling to the cap", () => {
		// 100 files at 15 each needs 7 probes, under the 8-probe ceiling, so the
		// file cap is what binds here.
		const parts = partition(files(100), { maxFiles: DEFAULT_PARTITION_MAX_FILES });
		expect(parts.length).toBeGreaterThan(1);
		const sizes = parts.map((p) => p.paths.length);
		expect(Math.max(...sizes)).toBeLessThanOrEqual(DEFAULT_PARTITION_MAX_FILES);
		// Balanced: no partition is more than one file bigger than another.
		expect(Math.max(...sizes) - Math.min(...sizes)).toBeLessThanOrEqual(1);
	});

	it("lets the probe ceiling override the file cap, rather than the reverse", () => {
		// A monorepo cannot buy unlimited concurrency by being large. maxFiles is
		// the target; maxPartitions is the limit, and the limit wins.
		const parts = partition(files(400), { maxFiles: 15, maxPartitions: 8 });
		expect(parts).toHaveLength(8);
		expect(Math.max(...parts.map((p) => p.paths.length))).toBe(50);
	});

	it("puts a repo the size of opensec on four probes, not one", () => {
		// Measured: 48 files under one probe read 53% of the bytes; the same files
		// on four probes read 100%, for less money.
		expect(partition(files(48)).length).toBe(4);
	});

	it("puts a handful of files on one probe by default", () => {
		expect(partition(files(12))).toHaveLength(1);
	});

	it("honors an explicit small maxFiles instead of second-guessing it", () => {
		// minFiles used to override this to one partition. If the operator asks
		// for two-file partitions, the cost of that choice is theirs to make.
		expect(partition(files(12), { maxFiles: 2 })).toHaveLength(6);
	});

	it("respects the concurrency ceiling", () => {
		const parts = partition(files(5000), { maxFiles: 10, maxPartitions: 8 });
		expect(parts).toHaveLength(8);
	});

	it("covers every file exactly once", () => {
		const input = files(137);
		const parts = partition(input, { maxFiles: 20 });
		const all = parts.flatMap((p) => p.paths);
		expect(all).toHaveLength(input.length);
		expect(new Set(all).size).toBe(input.length);
	});

	it("is byte-identical across runs regardless of input order", () => {
		const input = files(50);
		const shuffled = [...input].reverse();
		expect(JSON.stringify(partition(input, { maxFiles: 10 }))).toBe(
			JSON.stringify(partition(shuffled, { maxFiles: 10 })),
		);
	});

	it("keeps a directory together where it can, since sorted paths cluster", () => {
		const input = [...files(20, "auth"), ...files(20, "billing")];
		const parts = partition(input, { maxFiles: 20 });
		// Each partition should be dominated by one top-level directory.
		for (const p of parts) {
			const dirs = new Set(p.paths.map((x) => x.split("/")[0]));
			expect(dirs.size).toBe(1);
		}
	});

	it("handles an empty repo without inventing a partition", () => {
		expect(partition([])).toEqual([]);
	});

	it("reports the distribution, so an unbalanced split is visible", () => {
		expect(describeDistribution(partition(files(100), { maxFiles: 50 }))).toContain("2 partition");
		expect(describeDistribution([])).toBe("no partitions");
	});
});

describe("mapConcurrent", () => {
	it("never exceeds the limit and preserves input order", async () => {
		let inFlight = 0;
		let peak = 0;
		const out = await mapConcurrent([1, 2, 3, 4, 5, 6, 7, 8], 3, async (n) => {
			inFlight++;
			peak = Math.max(peak, inFlight);
			await new Promise((r) => setTimeout(r, 5));
			inFlight--;
			return n * 2;
		});
		expect(peak).toBeLessThanOrEqual(3);
		expect(out).toEqual([2, 4, 6, 8, 10, 12, 14, 16]);
	});

	it("propagates a failure rather than half-running a phase", async () => {
		await expect(
			mapConcurrent([1, 2, 3], 2, async (n) => {
				if (n === 2) throw new Error("agent run failed");
				return n;
			}),
		).rejects.toThrow(/agent run failed/);
	});

	it("does nothing on an empty list", async () => {
		expect(await mapConcurrent([], 4, async () => 1)).toEqual([]);
	});

	it("stops dispatching new items after a failure, but lets in-flight work finish", async () => {
		// Each item is a full agent run. Before this held, one probe's provider
		// error meant the surviving workers kept launching agents for the rest of
		// the worklist while the caller had already marked the scan failed and
		// moved on to closing the ledger.
		const started: number[] = [];
		let inFlightFinished = false;
		await expect(
			mapConcurrent([1, 2, 3, 4], 2, async (n) => {
				started.push(n);
				if (n === 1) throw new Error("agent run failed");
				await new Promise((r) => setTimeout(r, 20));
				inFlightFinished = true;
				return n;
			}),
		).rejects.toThrow(/agent run failed/);
		expect(started).toEqual([1, 2]);
		expect(inFlightFinished).toBe(true);
	});
});
