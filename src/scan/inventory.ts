/**
 * Phase 0: inventory. No LLM.
 *
 * `rg --files --hidden --no-ignore` rather than `git ls-files`, because
 * untracked and hidden files are real surface: CI configs, .env.example, a
 * dropped script (plan §4). Sorted LC_ALL=C so the list is byte-identical
 * across runs. Filtering happens after, and every excluded file keeps its
 * exclusion reason rather than vanishing from the denominator.
 */

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export interface InventoryEntry {
	path: string;
	sha: string;
	bytes: number;
	excludedReason: string | null;
}

export interface InventoryResult {
	entries: InventoryEntry[];
	inScope: InventoryEntry[];
	/** Extensions seen in scope, so the report can say which languages it recognized. */
	languages: string[];
}

/** Directories that are never the code under review. */
const EXCLUDED_DIRS = [
	"node_modules",
	".git",
	"dist",
	"build",
	"out",
	"vendor",
	".venv",
	"venv",
	"target",
	"__pycache__",
	".next",
	".nuxt",
	".cache",
	"coverage",
	".opensec",
];

/** Extensions with no reviewable source. */
const BINARY_EXT = new Set([
	"png", "jpg", "jpeg", "gif", "webp", "ico", "bmp", "tiff", "svg",
	"pdf", "zip", "gz", "tar", "bz2", "xz", "7z", "rar",
	"mp3", "mp4", "wav", "mov", "avi", "webm", "ogg",
	"woff", "woff2", "ttf", "otf", "eot",
	"so", "dylib", "dll", "exe", "bin", "o", "a", "class", "jar", "wasm",
	"pyc", "pyo", "db", "sqlite", "sqlite3",
]);

const LOCKFILES = new Set([
	"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb",
	"Cargo.lock", "poetry.lock", "Gemfile.lock", "composer.lock", "go.sum",
]);

const MAX_FILE_BYTES = 512 * 1024;

export async function inventory(
	repoRoot: string,
	opts: { maxFiles?: number } = {},
): Promise<InventoryResult> {
	const root = resolve(repoRoot);
	const paths = await listFiles(root);

	const entries: InventoryEntry[] = [];
	for (const rel of paths) {
		entries.push(classify(root, rel));
	}

	const inScope = entries.filter((e) => e.excludedReason === null);

	if (opts.maxFiles && inScope.length > opts.maxFiles) {
		// Refuse rather than run away on a monorepo (plan §10).
		throw new Error(
			`${inScope.length} files in scope exceeds max_files=${opts.maxFiles}. ` +
				`Scope the scan to a subdirectory, or raise --max-files.`,
		);
	}

	const languages = [...new Set(inScope.map((e) => ext(e.path)).filter(Boolean))].sort();
	return { entries, inScope, languages };
}

async function listFiles(root: string): Promise<string[]> {
	const args = ["--files", "--hidden", "--no-ignore", "--glob", "!.git/**"];
	let stdout: string;
	try {
		const res = await execFileAsync("rg", args, {
			cwd: root,
			maxBuffer: 64 * 1024 * 1024,
			env: { ...process.env, LC_ALL: "C" },
		});
		stdout = res.stdout;
	} catch (err) {
		// execFile sets `code` to the spawn error string (ENOENT) or, when the
		// process ran and failed, to its numeric exit status.
		const e = err as { code?: string | number; stdout?: string; stderr?: string };
		if (e.code === "ENOENT") {
			throw new Error("ripgrep (rg) not found on PATH — opensec needs it for inventory.");
		}
		// Exit 1 means "no matches", which is a real (empty) answer. Every other
		// non-zero exit means rg gave up partway — typically an unreadable
		// directory, where it prints what it could reach and exits 2. Accepting
		// that truncated list would silently shrink the denominator every coverage
		// number is computed against, so the scan would claim high coverage of a
		// repo it never finished enumerating.
		if (e.code !== 1) {
			throw new Error(
				`ripgrep failed to enumerate the repository (exit ${String(e.code)}): ` +
					`${(e.stderr ?? "").trim() || "no stderr"}. ` +
					`The file list would be incomplete, and every coverage number derives from it.`,
			);
		}
		stdout = typeof e.stdout === "string" ? e.stdout : "";
	}
	return stdout
		.split("\n")
		.map((l) => l.trim())
		.filter((l) => l.length > 0)
		.sort();
}

function classify(root: string, rel: string): InventoryEntry {
	const abs = join(root, rel);
	const segments = rel.split("/");

	const dirHit = segments.slice(0, -1).find((s) => EXCLUDED_DIRS.includes(s));
	if (dirHit) return { path: rel, sha: "", bytes: 0, excludedReason: `in ${dirHit}/` };

	const base = segments[segments.length - 1] ?? rel;
	if (LOCKFILES.has(base)) return { path: rel, sha: "", bytes: 0, excludedReason: "lockfile" };

	const e = ext(rel);
	if (BINARY_EXT.has(e)) {
		// Recorded, not dropped: binaries we could not review still count against us.
		return { path: rel, sha: "", bytes: 0, excludedReason: `binary (.${e})` };
	}
	if (rel.endsWith(".min.js") || rel.endsWith(".min.css")) {
		return { path: rel, sha: "", bytes: 0, excludedReason: "minified" };
	}

	let bytes: number;
	try {
		bytes = statSync(abs).size;
	} catch {
		return { path: rel, sha: "", bytes: 0, excludedReason: "unreadable" };
	}
	if (bytes > MAX_FILE_BYTES) {
		return { path: rel, sha: "", bytes, excludedReason: `larger than ${MAX_FILE_BYTES} bytes` };
	}
	if (bytes === 0) return { path: rel, sha: "", bytes: 0, excludedReason: "empty" };

	let buf: Buffer;
	try {
		buf = readFileSync(abs);
	} catch {
		return { path: rel, sha: "", bytes, excludedReason: "unreadable" };
	}
	if (buf.subarray(0, 8192).includes(0)) {
		return { path: rel, sha: "", bytes, excludedReason: "binary (null byte)" };
	}

	return {
		path: rel,
		sha: createHash("sha256").update(buf).digest("hex").slice(0, 16),
		bytes,
		excludedReason: null,
	};
}

function ext(p: string): string {
	const base = p.split("/").pop() ?? p;
	const i = base.lastIndexOf(".");
	return i <= 0 ? "" : base.slice(i + 1).toLowerCase();
}
