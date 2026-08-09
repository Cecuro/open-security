import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { scopedPaths } from "../src/scan/target.js";

function git(root: string, args: string[]): void {
	execFileSync("git", args, { cwd: root, stdio: "ignore" });
}

function repository(): string {
	const root = mkdtempSync(join(tmpdir(), "opensec-target-"));
	git(root, ["init", "-q"]);
	git(root, ["config", "user.email", "test@example.com"]);
	git(root, ["config", "user.name", "Test"]);
	writeFileSync(join(root, "same.ts"), "export const same = true;\n");
	writeFileSync(join(root, "changed.ts"), "export const value = 1;\n");
	git(root, ["add", "."]);
	git(root, ["commit", "-qm", "initial"]);
	return root;
}

describe("Git scan scopes", () => {
	it("diff scope includes only files changed since the merge base", async () => {
		const root = repository();
		writeFileSync(join(root, "changed.ts"), "export const value = 2;\n");
		git(root, ["add", "changed.ts"]);
		git(root, ["commit", "-qm", "change"]);
		const initial = execFileSync("git", ["rev-parse", "HEAD^"], { cwd: root, encoding: "utf8" }).trim();
		expect(await scopedPaths(root, { kind: "diff", base: initial })).toEqual(["changed.ts"]);
	});

	it("working-tree scope includes staged, unstaged, and untracked files", async () => {
		const root = repository();
		writeFileSync(join(root, "changed.ts"), "export const value = 2;\n");
		writeFileSync(join(root, "new.ts"), "export const fresh = true;\n");
		writeFileSync(join(root, "staged.ts"), "export const staged = true;\n");
		git(root, ["add", "staged.ts"]);
		const paths = await scopedPaths(root, { kind: "working_tree" });
		expect(paths).toEqual(["changed.ts", "new.ts", "staged.ts"]);
	});
});
