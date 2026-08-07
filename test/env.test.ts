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

import {
	COMMAND_VALUE,
	applyAliases,
	piAuthPath,
	read,
	readPiAuth,
	resolvePiValue,
	type EnvLoadResult,
} from "../src/env.js";

describe("the credentials file is outside every repository", () => {
	it("resolves under the user's home, not the cwd or the scanned repo", () => {
		// The anchor is what makes this safe: the paths a scanned repository could
		// influence are the cwd and the repo root, and this is neither.
		const p = piAuthPath();
		expect(p).toBe(join(homedir(), ".pi", "agent", "auth.json"));
		expect(p.startsWith(homedir())).toBe(true);
		expect(p.startsWith(process.cwd())).toBe(false);
		expect(p).not.toContain("node_modules");
	});

	it("has no code path that reads a repo-relative env file", async () => {
		// A grep-style assertion on our own source, because the danger is a future
		// convenience commit adding `.env` lookup, not today's code. Every
		// filesystem read in this module must take the path parameter — never a
		// literal, never anything derived from the repo under review.
		const { readFileSync } = await import("node:fs");
		const src = readFileSync(new URL("../src/env.ts", import.meta.url), "utf8");
		const reads = src.match(/existsSync\(([^)]*)\)|readFileSync\(([^,)]*)/g) ?? [];
		expect(reads.length).toBeGreaterThan(0);
		for (const r of reads) {
			expect(r).toMatch(/\b(path|authPath)\b/);
		}
		expect(src).not.toMatch(/process\.cwd\(\)/);
		expect(src).not.toMatch(/repoRoot/);
	});

	it("does not execute anything while loading credentials", async () => {
		// pi resolves a `!cmd` key by spawning a shell. Reading a credentials file
		// is not a reason for this process to gain a code-execution path, so the
		// module must not import one.
		const { readFileSync } = await import("node:fs");
		const src = readFileSync(new URL("../src/env.ts", import.meta.url), "utf8");
		expect(src).not.toMatch(/child_process|execSync|spawnSync|node:child_process/);
	});
});

describe("reading pi's auth.json", () => {
	function blank(): EnvLoadResult {
		return {
			authPath: null,
			applied: [],
			skipped: [],
			aliased: [],
			warnings: [],
		};
	}

	function withAuth(contents: unknown): { authPath: string } {
		const dir = mkdtempSync(join(tmpdir(), "opensec-pi-"));
		const authPath = join(dir, "auth.json");
		writeFileSync(authPath, typeof contents === "string" ? contents : JSON.stringify(contents));
		return { authPath };
	}

	it("maps a provider id to the variable that provider's SDK reads", () => {
		// The shape pi actually writes: provider id at the top level, the endpoint
		// in the credential's own env block. A key without its endpoint is not
		// usable, so both have to come across.
		const { authPath } = withAuth({
			"azure-openai-responses": {
				type: "api_key",
				key: "sk-test-value",
				env: { AZURE_OPENAI_BASE_URL: "https://example.openai.azure.com" },
			},
		});
		const env: Record<string, string | undefined> = {};
		const result = blank();
		readPiAuth(authPath, env, result);

		expect(env.AZURE_OPENAI_API_KEY).toBe("sk-test-value");
		expect(env.AZURE_OPENAI_BASE_URL).toBe("https://example.openai.azure.com");
		expect(result.authPath).toBe(authPath);
		expect(result.applied).toContain("AZURE_OPENAI_API_KEY (azure-openai-responses)");
	});

	it("never overwrites a name the environment already defines", () => {
		const { authPath } = withAuth({
			openai: { type: "api_key", key: "from-pi" },
		});
		const env: Record<string, string | undefined> = { OPENAI_API_KEY: "from-environment" };
		const result = blank();
		readPiAuth(authPath, env, result);

		expect(env.OPENAI_API_KEY).toBe("from-environment");
		expect(result.skipped).toContain("OPENAI_API_KEY");
		expect(result.applied).toEqual([]);
	});

	it("skips an oauth credential rather than exporting a refresh token as a key", () => {
		// An OAuth credential is a token pi renews, not something a provider will
		// accept as an API key. Exporting it would produce a 401 that reads like a
		// wrong key.
		const { authPath } = withAuth({
			anthropic: { type: "oauth", refresh: "rt-value", access: "at-value" },
		});
		const env: Record<string, string | undefined> = {};
		const result = blank();
		readPiAuth(authPath, env, result);

		expect(env.ANTHROPIC_API_KEY).toBeUndefined();
		expect(result.applied).toEqual([]);
	});

	it("declines a key that runs a shell command, and says so", () => {
		const { authPath } = withAuth({
			openai: { type: "api_key", key: "!op read op://vault/key" },
		});
		const env: Record<string, string | undefined> = {};
		const result = blank();
		readPiAuth(authPath, env, result);

		expect(env.OPENAI_API_KEY).toBeUndefined();
		expect(result.warnings.join("\n")).toMatch(/shell command, which opensec does not execute/);
	});

	it("survives a torn or hand-edited file without taking the scan down", () => {
		// pi rewrites this under a lock. Reading mid-write is not fatal to us.
		const { authPath } = withAuth("{not valid json");
		const env: Record<string, string | undefined> = {};
		const result = blank();
		readPiAuth(authPath, env, result);

		expect(result.warnings.join("\n")).toMatch(/could not read/);
		expect(result.applied).toEqual([]);
	});

	it("ignores a provider it has no variable name for, env block included", () => {
		// pi supports far more providers than opensec resolves models for. An entry
		// we will never call must not get to export a base URL that redirects the
		// provider we do use.
		const { authPath } = withAuth({
			"some-future-provider": {
				type: "api_key",
				key: "x",
				env: { AZURE_OPENAI_BASE_URL: "https://unrelated.example.com" },
			},
		});
		const env: Record<string, string | undefined> = {};
		const result = blank();
		readPiAuth(authPath, env, result);

		expect(Object.keys(env)).toEqual([]);
		expect(result.applied).toEqual([]);
	});

	it("still supplies the endpoint when the key came from the environment", () => {
		// A key with no endpoint is not usable, so the env block applies even
		// though the key beside it loses to the environment.
		const { authPath } = withAuth({
			"azure-openai-responses": {
				type: "api_key",
				key: "key-from-pi",
				env: { AZURE_OPENAI_BASE_URL: "https://example.openai.azure.com" },
			},
		});
		const env: Record<string, string | undefined> = { AZURE_OPENAI_API_KEY: "exported" };
		const result = blank();
		readPiAuth(authPath, env, result);

		expect(env.AZURE_OPENAI_API_KEY).toBe("exported");
		expect(env.AZURE_OPENAI_BASE_URL).toBe("https://example.openai.azure.com");
	});
});

describe("the environment wins over pi", () => {
	function auth(contents: unknown | null): string {
		const dir = mkdtempSync(join(tmpdir(), "opensec-prec-"));
		const authPath = join(dir, "auth.json");
		if (contents !== null) writeFileSync(authPath, JSON.stringify(contents));
		return authPath;
	}

	const PI_AZURE = {
		"azure-openai-responses": {
			type: "api_key",
			key: "key-from-pi",
			env: { AZURE_OPENAI_BASE_URL: "https://pi.openai.azure.com" },
		},
	};

	it("takes both key and endpoint from pi when the environment is empty", () => {
		const env: Record<string, string | undefined> = {};
		read(auth(PI_AZURE), env);

		expect(env.AZURE_OPENAI_API_KEY).toBe("key-from-pi");
		expect(env.AZURE_OPENAI_BASE_URL).toBe("https://pi.openai.azure.com");
	});

	it("never overwrites an exported variable", () => {
		// CI and an explicit `export` have to keep working, so pi only fills gaps.
		const env: Record<string, string | undefined> = {
			AZURE_OPENAI_API_KEY: "key-from-environment",
		};
		const result = read(auth(PI_AZURE), env);

		expect(env.AZURE_OPENAI_API_KEY).toBe("key-from-environment");
		expect(result.skipped).toContain("AZURE_OPENAI_API_KEY");
	});

	it("honours an exported endpoint under the other spelling", () => {
		// An exported AZURE_OPENAI_ENDPOINT must beat pi's AZURE_OPENAI_BASE_URL,
		// or every model call goes somewhere the user did not choose. Aliasing runs
		// against whatever the environment holds, so the exported name is already
		// canonical by the time pi is consulted.
		const env: Record<string, string | undefined> = {
			AZURE_OPENAI_ENDPOINT: "https://ours.openai.azure.com",
		};
		applyAliases(env);
		read(auth(PI_AZURE), env);

		expect(env.AZURE_OPENAI_BASE_URL).toBe("https://ours.openai.azure.com");
	});

	it("works with no auth.json at all", () => {
		const env: Record<string, string | undefined> = {};
		const result = read(auth(null), env);

		expect(result.authPath).toBeNull();
		expect(result.applied).toEqual([]);
		expect(result.warnings).toEqual([]);
	});
});

describe("pi's config-value grammar", () => {
	it("treats a key with no $ as a literal", () => {
		expect(resolvePiValue("sk-abc123")).toBe("sk-abc123");
	});

	it("interpolates $NAME and ${NAME}", () => {
		expect(resolvePiValue("$K", {}, { K: "v" })).toBe("v");
		expect(resolvePiValue("pre-${K}-post", {}, { K: "v" })).toBe("pre-v-post");
	});

	it("prefers the credential's own env block over the ambient environment", () => {
		expect(resolvePiValue("$K", { K: "scoped" }, { K: "ambient" })).toBe("scoped");
	});

	it("returns undefined when a referenced variable is not set", () => {
		// Better to say so than to send a half-built key and get a 401 that reads
		// like a wrong key.
		expect(resolvePiValue("$MISSING_VAR_XYZ", {}, {})).toBeUndefined();
	});

	it("honours the $$ and $! escapes", () => {
		expect(resolvePiValue("a$$b")).toBe("a$b");
		expect(resolvePiValue("a$!b")).toBe("a!b");
	});

	it("recognises a command value without running it", () => {
		expect(resolvePiValue("!echo hi")).toBe(COMMAND_VALUE);
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

