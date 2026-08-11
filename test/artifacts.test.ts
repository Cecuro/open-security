/**
 * What opensec leaves on disk.
 *
 * Both of these are regressions for findings opensec produced by scanning
 * opensec at commit 74888df: every artifact we keep is a verbatim copy of
 * source code the agents read, and it was all being written at the process
 * umask — in a predictable path, on a machine that may have other users. The
 * threat model was worse than the rest, because it is model prose that skipped
 * the redactor every other piece of model prose goes through, and it now
 * outlives the scan that produced it.
 */

import { mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { opensecDir } from "../src/db/db.js";
import { renderMarkdown } from "../src/scan/render.js";
import { citedOutOfScope } from "../src/sdk/scanner.js";
import { redactSecrets, stripControlChars } from "../src/text.js";

const made: string[] = [];
afterEach(() => {
	for (const d of made.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe("artifacts under ~/.opensec are owner-only", () => {
	it("creates a subdirectory at 0700", () => {
		const name = `test-${process.pid}-${made.length}`;
		const dir = opensecDir(name);
		made.push(dir);
		expect(statSync(dir).mode & 0o777).toBe(0o700);
	});

	it("tightens a ~/.opensec that an older version left group-readable", () => {
		const root = join(homedir(), ".opensec");
		// Whatever it is now, opensecDir must leave it owner-only. mkdirSync's mode
		// argument does nothing when the directory already exists, which is exactly
		// how a 0755 directory from an earlier version would have survived.
		opensecDir();
		expect(statSync(root).mode & 0o777).toBe(0o700);
	});
});

describe("the stored threat model is redacted", () => {
	it("strips secret-shaped strings a threat model would legitimately quote", () => {
		// A threat model is asked to name sensitive assets, so a model that finds a
		// hardcoded key will name it. That text used to be written to disk verbatim.
		const written = stripControlChars(
			redactSecrets(
				[
					"## Sensitive assets",
					"",
					"- `config.ts:12` hardcodes an admin token: sk_live_9f8a7b6c5d4e3f2a1b0c9d8e",
					"- `deploy.sh:4` exports AKIAIOSFODNN7EXAMPLE for the uploader",
					"- the DB password is set inline: password = \"hunter2hunter2hunter2\"",
				].join("\n"),
			),
		);

		expect(written).not.toContain("9f8a7b6c5d4e3f2a1b0c9d8e");
		expect(written).not.toContain("AKIAIOSFODNN7EXAMPLE");
		expect(written).not.toContain("hunter2hunter2hunter2");
		// Still a usable threat model: the finding survives, the credential doesn't.
		expect(written).toContain("config.ts:12");
		expect(written).toContain("hardcodes an admin token");
	});

	it("leaves an ordinary threat model untouched", () => {
		const tm = "Entry points: `src/server.ts:14` mounts POST /upload without auth.";
		expect(stripControlChars(redactSecrets(tm))).toBe(tm);
	});
});

describe("a --db path the user chose is theirs", () => {
	it("does not force a mode on a ledger outside ~/.opensec", () => {
		// The owner-only rule is about the artifacts opensec chooses the location
		// for. A path the user passed is their call, including on a shared volume.
		const dir = mkdtempSync(join(tmpdir(), "opensec-db-"));
		mkdirSync(join(dir, "shared"), { mode: 0o755 });
		writeFileSync(join(dir, "shared", "x"), "");
		expect(statSync(join(dir, "shared")).mode & 0o777).toBe(0o755);
		rmSync(dir, { recursive: true, force: true });
	});
});

describe("user exclusions", () => {
	it("matches * within a segment and ** across them", async () => {
		const { globToRegExp } = await import("../src/scan/inventory.js");
		expect(globToRegExp("vendor/**").test("vendor/a/b.rs")).toBe(true);
		expect(globToRegExp("vendor/**").test("vendorish/a.rs")).toBe(false);
		expect(globToRegExp("**/examples/**").test("dep/examples/x/y.rs")).toBe(true);
		expect(globToRegExp("**/examples/**").test("dep/src/y.rs")).toBe(false);
		expect(globToRegExp("*.md").test("README.md")).toBe(true);
		expect(globToRegExp("*.md").test("docs/README.md")).toBe(false);
	});

	it("does not treat a dot as a wildcard", async () => {
		// Otherwise "a.md" would exclude "axmd", which is the kind of quiet
		// over-exclusion that shrinks a scan without anyone noticing.
		const { globToRegExp } = await import("../src/scan/inventory.js");
		expect(globToRegExp("a.md").test("axmd")).toBe(false);
	});
});

describe("a stored threat model can go stale sideways", () => {
	it("counts how much of it points outside this scan's scope", async () => {
		const { citedOutOfScope } = await import("../src/scan/threat-model.js");
		const tm = [
			"1. **Dashboard shell paths:** `dashboard/src/api/deposit/route.ts:29-42`.",
			"2. **Vault custody:** `contracts/receipt-vault/src/contract.rs:956-1130`.",
		].join("\n");
		const d = citedOutOfScope(tm, new Set(["contracts/receipt-vault/src/contract.rs"]));
		expect(d.cited).toBe(2);
		expect(d.outOfScope).toBe(1);
	});

	it("ignores bare words and keeps repo-relative paths", async () => {
		// The threat model is prose the user may edit, so this reads it loosely
		// rather than requiring them to maintain a machine-readable list.
		const { citedOutOfScope } = await import("../src/scan/threat-model.js");
		const d = citedOutOfScope("Review the vault. See a/b.rs and c/d.ts", new Set(["a/b.rs"]));
		expect(d.cited).toBe(2);
		expect(d.outOfScope).toBe(1);
	});

	it("says nothing when it cites no files at all", async () => {
		const { citedOutOfScope } = await import("../src/scan/threat-model.js");
		expect(citedOutOfScope("prose with no paths", new Set())).toEqual({
			cited: 0,
			outOfScope: 0,
		});
	});
});

describe("independent filings are reported as search, not as evidence", () => {
	const base = (id: string, mergedInto: string | null) => ({
		id,
		scan_id: "s",
		title: `finding ${id}`,
		cwe_ids: ["CWE-78"],
		locations: [{ path: "a.js", start_line: 1, end_line: 1 }],
		description: "s\n\ne",
		status: mergedInto ? "duplicate" as const : "confirmed" as const,
		duplicate_of: mergedInto,
		activities: [{ id: Number(id.slice(1)), worker_id: "w", kind: "assessment" as const, body: "traced", at: "now", data: {
			disposition: mergedInto ? "duplicate" as const : "confirmed" as const,
			inputs: {
				impact: "high" as const,
				vector: "remote" as const,
				auth_required: "none" as const,
				network_reachable: true,
				cross_tenant: false,
				code_execution_proven: false,
				traced_path_no_control: false,
				method: "code_reading" as const,
			},
		} }],
	});

	function render(candidates: unknown[]) {
		return renderMarkdown({
			scan: {
				id: "s",
				repo_id: "r",
				revision: null,
				profile: "local",
				status: "completed",
				phase: "report",
				config_hash: "h",
				started_at: "2026-01-01T00:00:00.000Z",
				completed_at: null,
				tokens_in: 0,
				tokens_out: 0,
				cost_usd: 0,
			},
			repoName: "r",
			repoPath: "/tmp/r",
			candidates,
			coverage: { files_in_scope: 1, files_touched: 1, bytes_in_scope: 1, bytes_read: 1 },
			extensions: [],
			excludedFiles: 0,
			modelRef: "m",
			promptHash: "h",
		} as never);
	}

	it("says how many filings collapsed, and that it is not corroboration", () => {
		const md = render([base("c1", null), base("c2", "c1"), base("c3", "c1")]);
		expect(md).toMatch(/Filed 3 times independently and merged/);
		expect(md).toMatch(/not evidence about the finding/);
	});

	it("stays silent for a finding filed once", () => {
		expect(render([base("c1", null)])).not.toMatch(/Filed \d+ times/);
	});
});

describe("a one-pass report says it is one sample", () => {
	function md(passes?: number) {
		return renderMarkdown({
			scan: {
				id: "s", repo_id: "r", revision: null, profile: "local", status: "completed",
				phase: "report", config_hash: "h", started_at: "x", completed_at: null,
				tokens_in: 0, tokens_out: 0, cost_usd: 0,
			},
			repoName: "r", repoPath: "/tmp/r", candidates: [],
			coverage: { files_in_scope: 1, files_touched: 1, bytes_in_scope: 1, bytes_read: 1 },
			extensions: [], excludedFiles: 0, modelRef: "m", promptHash: "h", passes,
		} as never);
	}

	it("warns on a single pass, because repeat scans find different sets", () => {
		expect(md(1)).toMatch(/This was \*\*one pass\*\*/);
		expect(md(1)).toMatch(/one sample, not the finding list/);
	});

	it("stays quiet once more than one pass ran", () => {
		expect(md(2)).not.toMatch(/one pass/);
	});

	it("stays quiet when the caller does not report passes at all", () => {
		expect(md(undefined)).not.toMatch(/one pass/);
	});
});

describe("an exclusion that excluded nothing says so", () => {
	it("reports globs that matched no file, and stays quiet about ones that did", async () => {
		// `--exclude peridot-dashboard` matches nothing because entries are files;
		// it needed `peridot-dashboard/**`. Silence there means paying for the
		// wider scan and reading findings you believed were out of scope.
		const { inventory } = await import("../src/scan/inventory.js");
		const root = mkdtempSync(join(tmpdir(), "opensec-inv-"));
		mkdirSync(join(root, "app"), { recursive: true });
		writeFileSync(join(root, "app", "a.ts"), "const a = 1;\n");
		writeFileSync(join(root, "b.ts"), "const b = 2;\n");

		const inv = await inventory(root, { exclude: ["app/**", "app", "nope/**"] });
		expect(inv.inScope.map((f) => f.path)).toEqual(["b.ts"]);
		expect(inv.unusedExcludes).toEqual(["app", "nope/**"]);
	});

	it("is empty when every glob did something", async () => {
		const { inventory } = await import("../src/scan/inventory.js");
		const root = mkdtempSync(join(tmpdir(), "opensec-inv2-"));
		writeFileSync(join(root, "keep.ts"), "1\n");
		writeFileSync(join(root, "drop.ts"), "2\n");
		const inv = await inventory(root, { exclude: ["drop.ts"] });
		expect(inv.unusedExcludes).toEqual([]);
	});
});

describe("drift is only claimed against a real inventory", () => {
	it("reports nothing when there is nothing to compare against", () => {
		// Phases are individually callable. `new Set(undefined)` is empty, so an
		// unguarded comparison calls every path the threat model cites
		// out-of-scope — confidently, and wrongly, to an SDK caller who invoked
		// threatModel() on its own.
		const tm = "See `a/b.rs:1-10` and `c/d.ts:4`.";
		expect(citedOutOfScope(tm, new Set())).toEqual({ cited: 2, outOfScope: 2 });
		// The guard lives at the call site, so what this pins is the shape the
		// call site must not hand it: an empty set is a claim, not a default.
		expect(citedOutOfScope(tm, new Set(["a/b.rs", "c/d.ts"]))).toEqual({
			cited: 2,
			outOfScope: 0,
		});
	});
});
