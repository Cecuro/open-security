import { execFile } from "node:child_process";
import { lstat, readFile } from "node:fs/promises";
import { isAbsolute, relative, resolve } from "node:path";
import { promisify } from "node:util";

import type { ScanScope } from "../types.js";

const execFileAsync = promisify(execFile);

/** Resolve the source files a scoped scan may file findings against. */
export async function scopedPaths(repoRoot: string, scope: ScanScope): Promise<string[] | undefined> {
	if (scope.kind === "repository") return undefined;

	if (scope.kind === "diff") {
		return await gitPaths(repoRoot, ["diff", "--name-only", "-z", `${scope.base}...HEAD`], `--diff ${scope.base}`);
	}
	if (scope.kind === "scope_file") return await scopeFilePaths(repoRoot, scope.path);

	const [changed, untracked] = await Promise.all([
		gitPaths(repoRoot, ["diff", "--name-only", "-z", "HEAD"], "--working-tree"),
		gitPaths(repoRoot, ["ls-files", "--others", "--exclude-standard", "-z"], "--working-tree"),
	]);
	return [...new Set([...changed, ...untracked])].sort();
}

async function scopeFilePaths(repoRoot: string, scopeFile: string): Promise<string[]> {
	let text: string;
	try {
		text = await readFile(scopeFile, "utf8");
	} catch (err) {
		throw new Error(`--scope-file could not read '${scopeFile}': ${(err as Error).message}`);
	}

	const paths = [...new Set(
		text
			.replace(/^\uFEFF/, "")
			.split(/\r?\n/)
			.map((line) => line.trim())
			.filter((line) => line.length > 0 && !line.startsWith("#"))
			.map((line) => line.replaceAll("\\", "/").replace(/^\.\//, "")),
	)].sort();
	if (paths.length === 0) throw new Error(`--scope-file '${scopeFile}' contains no paths`);

	const root = resolve(repoRoot);
	for (const path of paths) {
		const absolute = resolve(root, path);
		const fromRoot = relative(root, absolute);
		if (isAbsolute(path) || fromRoot === ".." || fromRoot.startsWith("../") || isAbsolute(fromRoot)) {
			throw new Error(`--scope-file path must be repository-relative: '${path}'`);
		}
		try {
			const entry = await lstat(absolute);
			if (entry.isSymbolicLink()) throw new Error("symbolic links are not supported");
			if (!entry.isFile()) throw new Error("not a file");
		} catch (err) {
			throw new Error(`--scope-file path not found in repository: '${path}' (${(err as Error).message})`);
		}
	}
	return paths;
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
