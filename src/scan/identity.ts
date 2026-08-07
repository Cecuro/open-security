/**
 * Candidate identity — the deterministic half of dedup.
 *
 * Two probes reading the same code from different partitions file the same flaw
 * in different words. Comparing prose is a model's job; comparing identity is
 * not, and doing it in code means the common case never costs a token.
 *
 * Identity is `(cwe family, {path, role} set, instance)`. Deliberately NOT line
 * numbers: the same finding filed against line 40 and line 43 of the same
 * function is one finding, and an identity that moves when the code moves is
 * useless to a future diff scan.
 *
 * `instance` is the escape hatch in the other direction — two hardcoded secrets
 * in one file are two findings needing two patches, and the probe says so by
 * giving them different instances.
 */

import { createHash } from "node:crypto";

import type { Location, LocationRole } from "../types.js";

/**
 * CWE ids that name the same broken control. Without this, one probe filing
 * CWE-22 and another filing CWE-23 for the identical path traversal produce two
 * rows that no deterministic rule can join.
 *
 * Anything not listed is its own family. Being wrong here costs a duplicate
 * pair in the report; being aggressive here would silently merge two real bugs,
 * so the table only contains aliases, never "related" classes.
 */
const FAMILIES: Record<string, string> = {
	"CWE-22": "path-traversal",
	"CWE-23": "path-traversal",
	"CWE-36": "path-traversal",
	"CWE-73": "path-traversal",
	"CWE-77": "command-injection",
	"CWE-78": "command-injection",
	"CWE-88": "command-injection",
	"CWE-79": "xss",
	"CWE-80": "xss",
	"CWE-83": "xss",
	"CWE-89": "sql-injection",
	"CWE-564": "sql-injection",
	"CWE-502": "deserialization",
	"CWE-611": "xxe",
	"CWE-776": "xxe",
	"CWE-918": "ssrf",
	"CWE-352": "csrf",
	"CWE-259": "hardcoded-credentials",
	"CWE-798": "hardcoded-credentials",
	"CWE-284": "missing-authz",
	"CWE-639": "missing-authz",
	"CWE-862": "missing-authz",
	"CWE-863": "missing-authz",
	"CWE-326": "weak-crypto",
	"CWE-327": "weak-crypto",
	"CWE-328": "weak-crypto",
};

export function cweFamily(cweIds: string[]): string {
	const fams = [...new Set(cweIds.map((c) => FAMILIES[c] ?? c.toLowerCase()))].sort();
	// No classification is not a family — an unclassified finding must not merge
	// with every other unclassified finding that happens to share a file.
	return fams.length > 0 ? fams.join("+") : "unclassified";
}

export interface Identity {
	cweIds: string[];
	locations: Array<Pick<Location, "path"> & { role?: LocationRole }>;
	instance?: string | null;
}

/** The human-readable identity. Stored nowhere; hashed, and shown in errors. */
export function identityOf(c: Identity): string {
	const places = [...new Set(c.locations.map((l) => `${l.path}#${l.role ?? "evidence"}`))].sort();
	return [cweFamily(c.cweIds), places.join(","), (c.instance ?? "").trim()].join("|");
}

export function identityHash(c: Identity): string {
	return createHash("sha256").update(identityOf(c)).digest("hex").slice(0, 16);
}

/**
 * Groups worth spending a model on. Identity already collapsed the exact
 * matches; what is left is rows that look related but are not identical, and
 * only a reader can say whether one patch fixes both.
 *
 * Keyed on `(cwe family, primary path)`. A pair whose primary locations differ
 * is not grouped and so never reaches the reducer — that is under-merging,
 * which costs a duplicate in the report. The other direction destroys a finding
 * with no way to notice, so the bias is deliberate.
 */
export function collisionGroups<T extends { cwe_ids: string[]; locations: Location[] }>(
	candidates: T[],
): T[][] {
	const groups = new Map<string, T[]>();
	for (const c of candidates) {
		const primary = c.locations[0]?.path ?? "";
		const key = `${cweFamily(c.cwe_ids)}|${primary}`;
		const bucket = groups.get(key);
		if (bucket) bucket.push(c);
		else groups.set(key, [c]);
	}
	// Singletons never reach a model. That is most of them, on most scans.
	return [...groups.values()].filter((g) => g.length > 1);
}

/**
 * Union two agents' prose without losing either. Blocks, not sentences: a
 * paragraph is the unit a reader can still follow after merging, and dropping
 * an exact repeat is the only deduplication that is safe to do without reading.
 */
export function mergeProse(a: string, b: string, limit = 20000): string {
	const blocks: string[] = [];
	const seen = new Set<string>();
	for (const text of [a, b]) {
		for (const block of text.split(/\n{2,}/)) {
			const t = block.trim();
			if (t.length === 0 || seen.has(t)) continue;
			seen.add(t);
			blocks.push(t);
		}
	}
	return blocks.join("\n\n").slice(0, limit);
}

export function mergeLocations(a: Location[], b: Location[]): Location[] {
	const out: Location[] = [];
	const seen = new Set<string>();
	for (const l of [...a, ...b]) {
		const key = `${l.path}:${l.start_line}-${l.end_line}`;
		if (seen.has(key)) continue;
		seen.add(key);
		out.push(l);
	}
	return out.slice(0, 20);
}
