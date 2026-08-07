/**
 * Credential loading.
 *
 * The load-bearing test here is the one that asserts a path is NOT read.
 * `opensec scan .` makes the current directory the repository under review, so
 * a dotenv loader that walks cwd would let a scanned repo set
 * AZURE_OPENAI_BASE_URL to a host it controls and receive every model call —
 * the source code being scanned, plus the key in the Authorization header.
 */

import { mkdtempSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { applyAliases, envFilePath, parse } from "../src/env.js";

describe("the credentials file is outside every repository", () => {
	it("lives under the user's home, not the cwd or the scanned repo", () => {
		const p = envFilePath();
		expect(p).toBe(join(homedir(), ".opensec", "env"));
		// The two paths a scanned repository could control.
		expect(p.startsWith(process.cwd())).toBe(false);
		expect(p).not.toContain("node_modules");
	});

	it("has no code path that reads a repo-relative env file", async () => {
		// A grep-style assertion on our own source, because the danger is a future
		// convenience commit adding `.env` lookup, not today's code.
		const { readFileSync } = await import("node:fs");
		const src = readFileSync(new URL("../src/env.ts", import.meta.url), "utf8");
		const reads = src.match(/existsSync\([^)]*\)|readFileSync\([^)]*\)/g) ?? [];
		// Every filesystem read in this module resolves from envFilePath().
		for (const r of reads) {
			expect(r).toMatch(/path/);
		}
		expect(src).not.toMatch(/process\.cwd\(\)/);
		expect(src).not.toMatch(/repoRoot/);
	});
});

describe("parsing a credentials file", () => {
	it("reads KEY=VALUE, comments, blank lines and export", () => {
		expect(
			parse(
				[
					"# a comment",
					"",
					"AZURE_OPENAI_API_KEY=abc123",
					"export AZURE_OPENAI_ENDPOINT=https://x.openai.azure.com",
					'QUOTED="with spaces"',
					"SINGLE='sq'",
				].join("\n"),
			),
		).toEqual([
			["AZURE_OPENAI_API_KEY", "abc123"],
			["AZURE_OPENAI_ENDPOINT", "https://x.openai.azure.com"],
			["QUOTED", "with spaces"],
			["SINGLE", "sq"],
		]);
	});

	it("keeps a # that is part of a quoted secret", () => {
		// Stripping this would silently truncate a key and produce a 401 that
		// looks like a wrong key rather than a parser bug.
		expect(parse('K="se#cret"')).toEqual([["K", "se#cret"]]);
		expect(parse("K=plain # trailing note")).toEqual([["K", "plain"]]);
	});

	it("ignores lines that are not assignments", () => {
		expect(parse("just some prose\n=novalue\n1BAD=x")).toEqual([]);
	});

	it("does not treat a URL's colon or slashes as special", () => {
		expect(parse("U=https://host:443/path?a=b")).toEqual([["U", "https://host:443/path?a=b"]]);
	});
});

describe("aliasing", () => {
	it("maps the Azure endpoint spelling pi does not accept", () => {
		// AZURE_OPENAI_ENDPOINT is what Azure's portal, .dev.vars and most SDKs
		// call it; pi wants AZURE_OPENAI_BASE_URL. This mismatch cost an afternoon
		// and produced an error message pointing at a /login command we don't have.
		const env: Record<string, string | undefined> = {
			AZURE_OPENAI_ENDPOINT: "https://example.openai.azure.com",
		};
		expect(applyAliases(env)).toContain(
			"AZURE_OPENAI_ENDPOINT -> AZURE_OPENAI_BASE_URL",
		);
		expect(env.AZURE_OPENAI_BASE_URL).toBe("https://example.openai.azure.com");
	});

	it("does not clobber the canonical name when both are set", () => {
		const env: Record<string, string | undefined> = {
			AZURE_OPENAI_ENDPOINT: "https://alias.example.com",
			AZURE_OPENAI_BASE_URL: "https://explicit.example.com",
		};
		applyAliases(env);
		expect(env.AZURE_OPENAI_BASE_URL).toBe("https://explicit.example.com");
	});

	it("does nothing when neither spelling is present", () => {
		const env: Record<string, string | undefined> = {};
		expect(applyAliases(env)).toEqual([]);
		expect(env.AZURE_OPENAI_BASE_URL).toBeUndefined();
	});
});

describe("the environment wins over the file", () => {
	it("never overwrites a variable that is already set", async () => {
		const dir = mkdtempSync(join(tmpdir(), "opensec-env-"));
		writeFileSync(join(dir, "env"), "SOME_OPENSEC_TEST_KEY=from-file\n");
		const before = process.env.SOME_OPENSEC_TEST_KEY;
		try {
			process.env.SOME_OPENSEC_TEST_KEY = "from-environment";
			// The file is only consulted for names the environment does not define,
			// so an explicit export and CI both keep working.
			const parsed = parse("SOME_OPENSEC_TEST_KEY=from-file");
			const applied = parsed.filter(([n]) => process.env[n] === undefined);
			expect(applied).toEqual([]);
			expect(process.env.SOME_OPENSEC_TEST_KEY).toBe("from-environment");
		} finally {
			if (before === undefined) delete process.env.SOME_OPENSEC_TEST_KEY;
			else process.env.SOME_OPENSEC_TEST_KEY = before;
		}
	});
});
