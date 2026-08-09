import { execFile } from "node:child_process";
import { promisify } from "node:util";

import type { ScanScope } from "../types.js";

const execFileAsync = promisify(execFile);

/** Resolve the source files a scoped scan may file findings against. */
export async function scopedPaths(repoRoot: string, scope: ScanScope): Promise<string[] | undefined> {
	if (scope.kind === "repository") return undefined;

	if (scope.kind === "diff") {
		return await gitPaths(repoRoot, ["diff", "--name-only", "-z", `${scope.base}...HEAD`], `--diff ${scope.base}`);
	}

	const [changed, untracked] = await Promise.all([
		gitPaths(repoRoot, ["diff", "--name-only", "-z", "HEAD"], "--working-tree"),
		gitPaths(repoRoot, ["ls-files", "--others", "--exclude-standard", "-z"], "--working-tree"),
	]);
	return [...new Set([...changed, ...untracked])].sort();
}

async function gitPaths(repoRoot: string, args: string[], label: string): Promise<string[]> {
	try {
		const { stdout } = await execFileAsync("git", args, {
			cwd: repoRoot,
			maxBuffer: 64 * 1024 * 1024,
		});
		return stdout
			.split("\0")
			.filter(Boolean)
			.sort();
	} catch (err) {
		const e = err as { stderr?: Buffer | string; code?: number | string };
		const detail = Buffer.isBuffer(e.stderr) ? e.stderr.toString("utf8") : e.stderr;
		throw new Error(
			`${label} needs a Git repository and a resolvable base revision: ${detail?.trim() || `git exited ${String(e.code)}`}`,
		);
	}
}
