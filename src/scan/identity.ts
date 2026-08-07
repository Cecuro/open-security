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
	return [...groups.values()].filter((g) => g.length > 1);
}

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
