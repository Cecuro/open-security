import { describe, expect, it } from "vitest";

import { mapConcurrent } from "../src/scan/concurrency.js";

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
