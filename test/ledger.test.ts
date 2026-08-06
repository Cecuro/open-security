import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { Ledger } from "../src/db/db.js";

function ledger(): Ledger {
	const l = Ledger.open(join(mkdtempSync(join(tmpdir(), "opensec-ledger-")), "l.db"));
	const repoId = l.upsertRepo("/tmp/fake-repo", "fake", null);
	l.createScan({ id: "s", repoId, revision: null, profile: "static", configHash: "c" });
	return l;
}

describe("a failed scan keeps the phase it died in", () => {
	it("does not overwrite the phase with 'report'", () => {
		const l = ledger();
		l.setPhase("s", "threat_model");
		l.finishScan("s", "failed");
		const scan = l.getScan("s");
		expect(scan?.status).toBe("failed");
		expect(scan?.phase).toBe("threat_model");
		l.close();
	});

	it("advances a completed scan to report", () => {
		const l = ledger();
		l.setPhase("s", "investigate");
		l.finishScan("s", "completed");
		expect(l.getScan("s")?.phase).toBe("report");
		l.close();
	});
});

describe("coverage counts only what was actually reached", () => {
	it("starts at zero even with files in scope", () => {
		const l = ledger();
		l.insertFiles("s", [
			{ path: "a.js", sha: "1", bytes: 100, excludedReason: null },
			{ path: "b.js", sha: "2", bytes: 200, excludedReason: null },
			{ path: "c.png", sha: "", bytes: 0, excludedReason: "binary (.png)" },
		]);
		const c = l.coverage("s");
		expect(c.files_in_scope).toBe(2);
		expect(c.files_touched).toBe(0);
		expect(c.bytes_in_scope).toBe(300);
		expect(c.bytes_read).toBe(0);
		expect(l.excludedCount("s")).toBe(1);
		l.close();
	});

	it("keeps the high-water mark across repeated reads, and never exceeds the file", () => {
		const l = ledger();
		l.insertFiles("s", [{ path: "a.js", sha: "1", bytes: 100, excludedReason: null }]);
		l.recordTouch("s", "a.js", 40);
		l.recordTouch("s", "a.js", 10); // a later partial read must not lower it
		expect(l.coverage("s").bytes_read).toBe(40);
		// A grep hit that returns more text than the file holds cannot inflate coverage.
		l.recordTouch("s", "a.js", 5000);
		expect(l.coverage("s").bytes_read).toBe(100);
		l.close();
	});

	it("counts a grep touch as reached but not as read", () => {
		const l = ledger();
		l.insertFiles("s", [{ path: "a.js", sha: "1", bytes: 100, excludedReason: null }]);
		l.recordTouch("s", "a.js", 0);
		const c = l.coverage("s");
		expect(c.files_touched).toBe(1);
		expect(c.bytes_read).toBe(0);
		l.close();
	});
});
