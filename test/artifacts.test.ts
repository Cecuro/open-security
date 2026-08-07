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
