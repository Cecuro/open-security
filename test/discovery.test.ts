import { describe, expect, it } from "vitest";

import { AgentRunFailedError } from "../src/agents/session.js";
import {
	discoveryPlan,
	requireDiscoveryProgress,
	runDiscoveryProbes,
} from "../src/sdk/scanner.js";

describe("discovery probe resilience", () => {
	it("skips probes already completed before resume", () => {
		expect(discoveryPlan(3, ({ workerId }) => workerId === "probe-2")).toEqual([
			{ workerId: "probe-1", readGroup: "pass-1" },
			{ workerId: "probe-3", readGroup: "pass-3" },
		]);
	});

	it("continues other probes after an exhausted provider failure", async () => {
		const ran: number[] = [];
		const failed: number[] = [];
		await runDiscoveryProbes(
			[1, 2],
			2,
			async (probe) => {
				ran.push(probe);
				if (probe === 1) throw new AgentRunFailedError("provider failed");
			},
			(probe) => failed.push(probe),
		);

		expect(ran.sort()).toEqual([1, 2]);
		expect(failed).toEqual([1]);
		expect(() => requireDiscoveryProgress(1, ["provider failed"])).not.toThrow();
	});

	it("fails when every probe fails and propagates non-provider errors", async () => {
		const failed: number[] = [];
		await runDiscoveryProbes(
			[1, 2],
			2,
			async () => {
				throw new AgentRunFailedError("provider failed");
			},
			(probe) => failed.push(probe),
		);
		expect(failed.sort()).toEqual([1, 2]);
		expect(() => requireDiscoveryProgress(0, ["first", "second"])).toThrow(
			"no probe completed; first error: first",
		);

		await expect(
			runDiscoveryProbes(
				[1],
				1,
				async () => {
					throw new Error("budget failed");
				},
				() => {},
			),
		).rejects.toThrow("budget failed");
	});
});
