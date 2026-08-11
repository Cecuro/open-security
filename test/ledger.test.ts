import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { Ledger } from "../src/db/db.js";
import { testScanConfig } from "./config.js";

function ledger(): Ledger {
	const l = Ledger.open(join(mkdtempSync(join(tmpdir(), "opensec-ledger-")), "l.db"));
	const repoId = l.upsertRepo("/tmp/fake-repo", "fake", null);
	l.createScan({ id: "s", repoId, revision: null, config: testScanConfig() });
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

describe("the worklist is what nothing has read yet", () => {
	function withFiles(): Ledger {
		const l = ledger();
		l.insertFiles("s", [
			{ path: "a.js", sha: "1", bytes: 100, excludedReason: null },
			{ path: "b.js", sha: "2", bytes: 100, excludedReason: null },
			{ path: "c.js", sha: "3", bytes: 100, excludedReason: null },
			{ path: "d.png", sha: "", bytes: 0, excludedReason: "binary (.png)" },
		]);
		return l;
	}

	it("starts as every in-scope file, and never an excluded one", () => {
		const l = withFiles();
		const { files, unread } = l.listWork("s", 100);
		expect(unread).toBe(3);
		expect(files.map((f) => f.path)).toEqual(["a.js", "b.js", "c.js"]);
		l.close();
	});

	it("shrinks only when bytes are read", () => {
		// The list cannot be advanced past work that was not done, because there
		// is nothing to advance — a file leaves it by being read, or not at all.
		const l = withFiles();
		l.recordTouch("s", "a.js", 100);
		expect(l.listWork("s", 100).unread).toBe(2);
		expect(l.listWork("s", 100).files.map((f) => f.path)).toEqual(["b.js", "c.js"]);
		l.close();
	});

	it("does not count a grep touch as read", () => {
		// A searched file is touched with zero bytes. If that emptied the
		// worklist, one repo-wide grep would clear it for free.
		const l = withFiles();
		l.recordTouch("s", "a.js", 0);
		expect(l.listWork("s", 100).unread).toBe(3);
		expect(l.listWork("s", 100).files.map((f) => f.path)).toContain("a.js");
		l.close();
	});

	it("empties only when everything in scope has been read", () => {
		const l = withFiles();
		for (const p of ["a.js", "b.js", "c.js"]) l.recordTouch("s", p, 100);
		expect(l.listWork("s", 100).unread).toBe(0);
		expect(l.listWork("s", 100).files).toEqual([]);
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

describe("a truncated read does not finish a large file", () => {
	// pi caps a read at 50KB. Under a high-water mark a 190KB file records
	// 51,200 once and can never record more, so coverage ceilings and the
	// worklist calls it done — with three quarters of it unread.
	function big(): Ledger {
		const l = ledger();
		l.insertFiles("s", [{ path: "big.rs", sha: "1", bytes: 150_000, excludedReason: null }]);
		return l;
	}

	it("keeps the file on the worklist after one truncated read", () => {
		const l = big();
		l.recordTouch("s", "big.rs", 51_200);
		expect(l.listWork("s", 10).unread).toBe(1);
		expect(l.coverage("s").bytes_read).toBe(51_200);
		l.close();
	});

	it("accumulates reads that carried an offset", () => {
		const l = big();
		l.recordTouch("s", "big.rs", 51_200);
		l.recordTouch("s", "big.rs", 51_200, true);
		expect(l.coverage("s").bytes_read).toBe(102_400);
		expect(l.listWork("s", 10).unread).toBe(1);
		l.recordTouch("s", "big.rs", 51_200, true);
		expect(l.listWork("s", 10).unread).toBe(0);
		l.close();
	});

	it("never counts past the size of the file", () => {
		const l = big();
		for (let i = 0; i < 10; i++) l.recordTouch("s", "big.rs", 51_200, true);
		expect(l.coverage("s").bytes_read).toBe(150_000);
		l.close();
	});

	it("cannot be inflated by re-reading from the top", () => {
		// A read with no offset is a read from the start, and it replaces rather
		// than adds — otherwise the same 50KB four times would 'cover' 200KB.
		const l = big();
		for (let i = 0; i < 4; i++) l.recordTouch("s", "big.rs", 51_200);
		expect(l.coverage("s").bytes_read).toBe(51_200);
		l.close();
	});

	it("ignores supporting files outside the scan inventory", () => {
		const l = big();
		expect(() => {
			l.recordTouch("s", "supporting.rs", 51_200, false, "pass-1", "probe-1");
			l.recordTouch("s", "supporting.rs", 51_200, true, "pass-1", "probe-1");
		}).not.toThrow();
		expect(l.coverage("s").bytes_read).toBe(0);
		l.close();
	});
});

describe("a worklist scoped to a partition", () => {
	function withFiles(): Ledger {
		const l = ledger();
		l.insertFiles("s", [
			{ path: "a.js", sha: "1", bytes: 100, excludedReason: null },
			{ path: "b.js", sha: "2", bytes: 100, excludedReason: null },
			{ path: "c.js", sha: "3", bytes: 100, excludedReason: null },
		]);
		return l;
	}

	it("returns only the owned files", () => {
		const l = withFiles();
		const { files, unread } = l.listWork("s", 100, ["a.js", "b.js"]);
		expect(unread).toBe(2);
		expect(files.map((f) => f.path)).toEqual(["a.js", "b.js"]);
		l.close();
	});

	it("is unaffected by reads outside it", () => {
		const l = withFiles();
		l.recordTouch("s", "c.js", 100);
		expect(l.listWork("s", 100, ["a.js", "b.js"]).unread).toBe(2);
		l.close();
	});

	it("ties a finding to the probe that owns the file", () => {
		const l = withFiles();
		expect(l.fileInScope("s", "a.js", ["a.js", "b.js"])).toBe(true);
		expect(l.fileInScope("s", "c.js", ["a.js", "b.js"])).toBe(false);
		expect(l.fileInScope("s", "c.js")).toBe(true);
		l.close();
	});

	it("treats an empty partition as no work, not as the whole repository", () => {
		// `IN ()` is not valid SQL, and falling through to an unscoped query would
		// hand one probe everything.
		const l = withFiles();
		expect(l.listWork("s", 100, []).unread).toBe(0);
		expect(l.listWork("s", 100, []).files).toEqual([]);
		l.close();
	});
});

describe("passes read independently", () => {
	function withFiles(): Ledger {
		const l = ledger();
		l.insertFiles("s", [
			{ path: "a.js", sha: "1", bytes: 100, excludedReason: null },
			{ path: "b.js", sha: "2", bytes: 100, excludedReason: null },
		]);
		return l;
	}

	it("does not hand a second pass an empty worklist", () => {
		// Without this, pass 2 opens on nothing, reviews nothing, and its silence
		// reads as agreement with pass 1 rather than as the no-op it is.
		const l = withFiles();
		l.recordTouch("s", "a.js", 100, false, "pass-1");
		l.recordTouch("s", "b.js", 100, false, "pass-1");

		// Assert on the rows, not only the count. The first version of this test
		// checked `unread` alone; the two queries had different parameter orders,
		// so the count was right while every probe got an empty list and the scan
		// reported itself clean.
		const p1 = l.listWork("s", 10, undefined, "pass-1");
		expect(p1.unread).toBe(0);
		expect(p1.files).toEqual([]);

		const p2 = l.listWork("s", 10, undefined, "pass-2");
		expect(p2.unread).toBe(2);
		expect(p2.files.map((f) => f.path)).toEqual(["a.js", "b.js"]);
		l.close();
	});

	it("still reports coverage as the union of every pass", () => {
		// Coverage is a claim about the scan, not about one pass, so a file read
		// by either counts once and is not double counted.
		const l = withFiles();
		l.recordTouch("s", "a.js", 100, false, "pass-1");
		l.recordTouch("s", "a.js", 100, false, "pass-2");
		const c = l.coverage("s");
		expect(c.files_touched).toBe(1);
		expect(c.bytes_read).toBe(100);
		l.close();
	});

	it("keeps the unscoped worklist meaning read-by-anyone", () => {
		const l = withFiles();
		l.recordTouch("s", "a.js", 100, false, "pass-1");
		const w = l.listWork("s", 10);
		expect(w.unread).toBe(1);
		expect(w.files.map((f) => f.path)).toEqual(["b.js"]);
		l.close();
	});

	it("returns rows and count consistently when a partition is also scoped", () => {
		// The combination is where the parameter order actually broke: a read
		// group, a partition and a limit, all in one statement.
		const l = withFiles();
		l.recordTouch("s", "a.js", 100, false, "pass-1");
		const scoped = l.listWork("s", 10, ["a.js", "b.js"], "pass-1");
		expect(scoped.unread).toBe(1);
		expect(scoped.files.map((f) => f.path)).toEqual(["b.js"]);
		expect(scoped.files.length).toBe(scoped.unread);

		const fresh = l.listWork("s", 10, ["a.js", "b.js"], "pass-2");
		expect(fresh.unread).toBe(2);
		expect(fresh.files.map((f) => f.path)).toEqual(["a.js", "b.js"]);
	});
});
