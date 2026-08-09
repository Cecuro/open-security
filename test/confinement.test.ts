/**
 * The repo-confinement boundary, and the coverage attribution that rides on the
 * same path handling.
 *
 * These exist because the gate and the tool it guards used to answer different
 * questions. `confine()` checked the raw string with `resolve()`; pi's file
 * tools resolve through `normalizePath`, which expands `~`, strips a leading
 * `@`, and converts `file://`. `~/.ssh/id_rsa` resolved to `<repo>/~/.ssh/...`,
 * which is lexically inside the repo and does not exist, so the gate passed it
 * and pi then read the real key.
 *
 * `normalizeLikePi` mirrors pi's `utils/paths.ts`, which the package does not
 * export. That coupling is the point of the second block below: if pi learns a
 * new expansion, the assertions about what pi actually does are what should
 * fail, rather than a scan quietly reading outside the repository again.
 */

import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";

import {
	createFindToolDefinition,
	createGrepToolDefinition,
	createLsToolDefinition,
	createReadToolDefinition,
} from "@earendil-works/pi-coding-agent";
import { describe, expect, it } from "vitest";

import {
	normalizeLikePi,
	resolveToolPath,
	rootRelativeResults,
	withinRepo,
} from "../src/agents/session.js";

const repo = realpathSync(mkdtempSync(join(tmpdir(), "opensec-confine-")));
mkdirSync(join(repo, "src", "handlers"), { recursive: true });
writeFileSync(join(repo, "src", "handlers", "upload.ts"), "const token = 'abc';\n");

async function runTool(def: unknown, params: unknown): Promise<string> {
	const result = await (
		def as {
			execute: (
				id: string,
				p: unknown,
				s?: unknown,
				u?: unknown,
				c?: unknown,
			) => Promise<{ content?: Array<{ text?: string }> }>;
		}
	).execute("t", params, undefined, undefined, undefined);
	return (result.content ?? []).map((c) => c.text ?? "").join("\n");
}

describe("normalizeLikePi resolves paths the way pi will", () => {
	it("expands a leading ~ so the check is made against the real target", () => {
		expect(normalizeLikePi("~/.ssh/id_rsa")).toBe(join(homedir(), ".ssh/id_rsa"));
		expect(normalizeLikePi("~")).toBe(homedir());
	});

	it("strips a leading @, which pi treats as a file-reference prefix", () => {
		expect(normalizeLikePi("@/etc/passwd")).toBe("/etc/passwd");
	});

	it("converts a file:// URL", () => {
		expect(normalizeLikePi("file:///etc/passwd")).toBe("/etc/passwd");
	});

	it("leaves an ordinary repo-relative path alone", () => {
		expect(normalizeLikePi("src/handlers/upload.ts")).toBe("src/handlers/upload.ts");
	});

	it("does not throw on a malformed file: URL", () => {
		expect(() => normalizeLikePi("file://")).not.toThrow();
	});
});

describe("withinRepo — the gate confine() gives the file tools", () => {
	// The regression itself. Each of these used to return true: resolve() alone
	// places them inside the repo, they do not exist there, and the "does not
	// exist yet, let the tool report it" branch let them through.
	for (const evil of ["~/.ssh/id_rsa", "~", "file:///etc/passwd", "@/etc/passwd"]) {
		it(`refuses '${evil}'`, () => {
			expect(withinRepo(repo, evil)).toBe(false);
		});
	}

	it("still allows ordinary paths inside the repo", () => {
		expect(withinRepo(repo, "src/handlers/upload.ts")).toBe(true);
		expect(withinRepo(repo, "./src")).toBe(true);
		expect(withinRepo(repo, join(repo, "src/handlers/upload.ts"))).toBe(true);
	});

	it("still allows a path that does not exist yet, so the tool reports it", () => {
		expect(withinRepo(repo, "src/does-not-exist.ts")).toBe(true);
	});

	it("still refuses plain traversal and absolute paths outside", () => {
		expect(withinRepo(repo, "../../etc/passwd")).toBe(false);
		expect(withinRepo(repo, "/etc/passwd")).toBe(false);
	});
});

describe("resolveToolPath", () => {
	it("makes ordinary repo-relative paths unambiguous to PI", () => {
		expect(resolveToolPath({ repoRoot: repo }, "src/handlers/upload.ts")).toBe(
			join(repo, "src/handlers/upload.ts"),
		);
	});

	it("leaves absolute paths for the confinement gate to decide", () => {
		const repoFile = join(repo, "src", "handlers", "upload.ts");
		expect(resolveToolPath({ repoRoot: repo }, repoFile)).toBe(repoFile);
		expect(resolveToolPath({ repoRoot: repo }, "/etc/passwd")).toBe("/etc/passwd");
	});
});

describe("the escapes these normalizations close", () => {
	// Guards the coupling: each of these is a path that resolve() alone places
	// inside the repo while pi opens something else entirely.
	for (const evil of ["~/.ssh/id_rsa", "file:///etc/passwd", "@/etc/passwd"]) {
		it(`'${evil}' does not resolve inside the repo once normalized`, () => {
			const normalized = normalizeLikePi(evil);
			expect(normalized.startsWith("/")).toBe(true);
			expect(normalized.startsWith(repo)).toBe(false);
		});
	}

	it("pi's read tool really does follow ~ outside the repo", async () => {
		// The behaviour the gate has to account for. If this ever stops being
		// true, normalizeLikePi is over-strict rather than unsafe.
		const marker = join(homedir(), ".opensec-confinement-test");
		writeFileSync(marker, "outside-the-repo\n");
		try {
			const text = await runTool(createReadToolDefinition(repo), {
				path: "~/.opensec-confinement-test",
			});
			expect(text).toContain("outside-the-repo");
		} finally {
			const { rmSync } = await import("node:fs");
			rmSync(marker, { force: true });
		}
	});
});

describe("grep hits are reported relative to the search root, not the repo", () => {
	// The assumption instrumentGrep now encodes. A scoped grep used to record no
	// coverage at all, silently, for exactly the searches agents make most.
	it("a whole-repo grep is already repo-relative", async () => {
		const text = await runTool(createGrepToolDefinition(repo), { pattern: "token" });
		expect(text).toContain("src/handlers/upload.ts:");
	});

	it("a scoped grep drops the scoped prefix", async () => {
		const text = await runTool(createGrepToolDefinition(repo), { pattern: "token", path: "src" });
		expect(text).toContain("handlers/upload.ts:");
		expect(text).not.toContain("src/handlers/upload.ts:");
	});
});

describe("agent-visible tool results use repository-relative paths", () => {
	const ctx = { repoRoot: repo };

	it("prefixes scoped grep results", async () => {
		const text = await runTool(
			rootRelativeResults(createGrepToolDefinition(repo) as never, ctx),
			{ pattern: "token", path: "src" },
		);
		expect(text).toContain("src/handlers/upload.ts:");
	});

	it("prefixes scoped find results", async () => {
		const text = await runTool(
			rootRelativeResults(createFindToolDefinition(repo) as never, ctx),
			{ pattern: "*.ts", path: "src" },
		);
		expect(text).toContain("src/handlers/upload.ts");
	});

	it("prefixes scoped ls results", async () => {
		const text = await runTool(
			rootRelativeResults(createLsToolDefinition(repo) as never, ctx),
			{ path: "src" },
		);
		expect(text).toContain("src/handlers/");
	});
});
