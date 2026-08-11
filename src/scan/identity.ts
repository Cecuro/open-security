import { createHash } from "node:crypto";

import type { Location, LocationRole } from "../types.js";

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
	return fams.length > 0 ? fams.join("+") : "unclassified";
}

export interface Identity {
	cweIds: string[];
	locations: Array<Pick<Location, "path"> & { role?: LocationRole }>;
	instance?: string | null;
}

export function identityOf(c: Identity): string {
	const places = [...new Set(c.locations.map((l) => `${l.path}#${l.role ?? "evidence"}`))].sort();
	return [cweFamily(c.cweIds), places.join(","), (c.instance ?? "").trim()].join("|");
}

export function identityHash(c: Identity): string {
	return createHash("sha256").update(identityOf(c)).digest("hex").slice(0, 16);
}

/**
 * Which candidates are worth asking the reducer about.
 *
 * Keyed on the file holding `root_control` — the check that is missing or
 * wrong, which is to say the line a patch would touch. Two agents describing
 * one bug rarely agree on anything else: the same liquidation flaw arrived once
 * as `perps.rs` with no CWE and once as `contract.rs` with CWE-682, citing
 * root_control lines 44 apart. Grouping on the primary location and the CWE
 * family missed it three times over, and it reached the report twice.
 *
 * Deliberately recall-first, and deliberately not the identity hash. Grouping
 * two unrelated findings costs one reducer call, which is cheap and which the
 * reducer is there to refuse. Failing to group two descriptions of one bug puts
 * both in the report, which nothing downstream ever catches.
 */
export function collisionGroups<T extends { cwe_ids: string[]; locations: Location[] }>(
	candidates: T[],
): T[][] {
	const groups = new Map<string, T[]>();
	for (const c of candidates) {
		const root = c.locations.find((l) => l.role === "root_control")?.path;
		const key = root ?? c.locations[0]?.path ?? "";
		const bucket = groups.get(key);
		if (bucket) bucket.push(c);
		else groups.set(key, [c]);
	}
	return [...groups.values()].filter((g) => g.length > 1);
}
