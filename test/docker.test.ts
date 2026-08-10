import { describe, expect, it, vi } from "vitest";

import { createBashTool, type BashSandbox } from "../src/agents/docker.js";

const call = (tool: ReturnType<typeof createBashTool>, params: object) =>
	tool.execute("call", params as never, undefined, undefined, {} as never);

describe("Docker bash tool", () => {
	it("runs commands inside the supplied sandbox and returns stderr", async () => {
		const exec = vi.fn().mockResolvedValue({
			exitCode: 0,
			stdout: "proof passed\n",
			stderr: "warning\n",
			stdoutTruncated: false,
			stderrTruncated: false,
			timedOut: false,
		});
		const sandbox: BashSandbox = { repoDir: "/workspace/repo", exec, writeOutput: vi.fn() };

		const result = await call(createBashTool(sandbox), { command: "npm test", timeout_ms: 30_000 });
		const output = result.content.map((c) => ("text" in c ? c.text : "")).join("");

		expect(exec).toHaveBeenCalledWith("npm test", 30_000);
		expect(output).toBe("exit 0\nproof passed\n\n[stderr]\nwarning\n");
		expect(result.isError).toBe(false);
	});

	it("marks a non-zero command result as an error without discarding its output", async () => {
		const sandbox: BashSandbox = {
			repoDir: "/workspace/repo",
			exec: vi.fn().mockResolvedValue({
				exitCode: 1,
				stdout: "",
				stderr: "test failed",
				stdoutTruncated: false,
				stderrTruncated: false,
				timedOut: false,
			}),
			writeOutput: vi.fn(),
		};

		const result = await call(createBashTool(sandbox), { command: "npm test" });
		const output = result.content.map((c) => ("text" in c ? c.text : "")).join("");

		expect(output).toContain("exit 1");
		expect(output).toContain("test failed");
		expect(result.isError).toBe(true);
	});

	it("saves oversized command output in the sandbox and returns a useful preview", async () => {
		const writeOutput = vi.fn().mockResolvedValue("/workspace/repo/.opensec/tool-output/call.txt");
		const sandbox: BashSandbox = {
			repoDir: "/workspace/repo",
			exec: vi.fn().mockResolvedValue({
				exitCode: 0,
				stdout: "x".repeat(20_001),
				stderr: "",
				stdoutTruncated: false,
				stderrTruncated: false,
				timedOut: false,
			}),
			writeOutput,
		};

		const result = await call(createBashTool(sandbox), { command: "npm test" });
		const output = result.content.map((c) => ("text" in c ? c.text : "")).join("");

		expect(writeOutput).toHaveBeenCalledWith("call", expect.stringContaining("exit 0"));
		expect(output).toContain("saved to /workspace/repo/.opensec/tool-output/call.txt");
		expect(output).toContain("bytes omitted");
	});
});
