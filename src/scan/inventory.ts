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
	/** File extensions in scope, without the dot. Not language detection. */
	extensions: string[];
	/**
	 * `--exclude` globs that matched no file. An exclusion that excluded nothing
	 * is indistinguishable from one that worked, and the user has already paid
	 * for the wider scan by the time the findings say otherwise.
	 */
	unusedExcludes: string[];
}

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
	opts: { maxFiles?: number; exclude?: readonly string[]; include?: readonly string[] } = {},
): Promise<InventoryResult> {
	const root = resolve(repoRoot);
	const included = opts.include ? new Set(opts.include) : null;
	const paths = (await listFiles(root)).filter((path) => included === null || included.has(path));

	const excluders = (opts.exclude ?? []).map((g) => ({ glob: g, re: globToRegExp(g), hits: 0 }));

	const entries: InventoryEntry[] = [];
	for (const rel of paths) {
		// User exclusions win over everything else, and are recorded with the glob
		// that did it. A file dropped without a reason is indistinguishable from a
		// file nobody thought about — the excluded count is part of the report for
		// the same reason coverage is.
		const hit = excluders.find((e) => e.re.test(rel));
		if (hit) {
			hit.hits++;
			entries.push({
				path: rel,
				sha: "",
				bytes: 0,
				excludedReason: `excluded by --exclude '${hit.glob}'`,
			});
			continue;
		}
		entries.push(classify(root, rel));
	}

	const inScope = entries.filter((e) => e.excludedReason === null);

	if (opts.maxFiles && inScope.length > opts.maxFiles) {
		throw new Error(
			`${inScope.length} files in scope exceeds max_files=${opts.maxFiles}. ` +
				`Scope the scan to a subdirectory, or raise --max-files.`,
		);
	}

	const extensions = [...new Set(inScope.map((e) => ext(e.path)).filter(Boolean))].sort();
	return {
		entries,
		inScope,
		extensions,
		unusedExcludes: excluders.filter((e) => e.hits === 0).map((e) => e.glob),
	};
}

/**
 * `*` stops at a path separator, `**` does not. Small on purpose: this reads a
 * pattern the user typed on their own command line, not a shell dialect.
 */
export function globToRegExp(glob: string): RegExp {
	let out = "";
	for (let i = 0; i < glob.length; i++) {
		const c = glob[i] as string;
		if (c === "*") {
			if (glob[i + 1] === "*") {
				out += ".*";
				i++;
				if (glob[i + 1] === "/") i++;
			} else {
				out += "[^/]*";
			}
			continue;
		}
		if (c === "?") {
			out += "[^/]";
			continue;
		}
		out += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
	}
	return new RegExp(`^${out}$`);
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
		const e = err as { code?: string | number; stdout?: string; stderr?: string };
		if (e.code === "ENOENT") {
			throw new Error("ripgrep (rg) not found on PATH — opensec needs it for inventory.");
		}
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

export function ext(p: string): string {
	const base = p.split("/").pop() ?? p;
	const i = base.lastIndexOf(".");
	return i <= 0 ? "" : base.slice(i + 1).toLowerCase();
}
