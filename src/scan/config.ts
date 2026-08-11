import { createHash } from "node:crypto";

import type { Profile, ScanConfig, ScanScope } from "../types.js";
import { DEFAULT_PARTITION_MAX_FILES } from "./partition.js";

export const DEFAULT_CONCURRENCY = 4;
export const DEFAULT_PASSES = 1;
export const DEFAULT_MAX_TURNS = 80;

export interface ScanConfigInput {
	modelRef: string;
	promptHash: string;
	profile?: Profile;
	scope?: ScanScope;
	passes?: number;
	concurrency?: number;
	maxTurns?: number;
	maxFiles?: number | null;
	exclude?: readonly string[];
	maxCostUsd?: number | null;
	partitionMaxFiles?: number;
	refreshThreatModel?: boolean;
}

/** Apply defaults and canonical ordering once, before a scan starts. */
export function normalizeScanConfig(input: ScanConfigInput): ScanConfig {
	return {
		modelRef: requiredText(input.modelRef, "modelRef"),
		profile: input.profile ?? "container",
		scope: normalizeScope(input.scope ?? { kind: "repository" }),
		promptHash: requiredText(input.promptHash, "promptHash"),
		passes: positiveInteger(input.passes ?? DEFAULT_PASSES, "passes"),
		concurrency: positiveInteger(input.concurrency ?? DEFAULT_CONCURRENCY, "concurrency"),
		maxTurns: positiveInteger(input.maxTurns ?? DEFAULT_MAX_TURNS, "maxTurns"),
		maxFiles: optionalPositiveInteger(input.maxFiles, "maxFiles"),
		exclude: [...new Set((input.exclude ?? []).map((value) => value.trim()).filter(Boolean))].sort(),
		maxCostUsd: optionalPositiveNumber(input.maxCostUsd, "maxCostUsd"),
		partitionMaxFiles: positiveInteger(
			input.partitionMaxFiles ?? DEFAULT_PARTITION_MAX_FILES,
			"partitionMaxFiles",
		),
		refreshThreatModel: input.refreshThreatModel ?? false,
	};
}

export function scanConfigHash(config: ScanConfig): string {
	return createHash("sha256").update(JSON.stringify(config)).digest("hex").slice(0, 12);
}

export function parseScanConfig(value: unknown): ScanConfig | null {
	if (typeof value !== "string" || value.length === 0) return null;
	try {
		const parsed = JSON.parse(value) as ScanConfig;
		return normalizeScanConfig(parsed);
	} catch {
		return null;
	}
}

function normalizeScope(scope: ScanScope): ScanScope {
	if (scope.kind === "diff") return { kind: "diff", base: requiredText(scope.base, "scope.base") };
	if (scope.kind === "working_tree") return { kind: "working_tree" };
	return { kind: "repository" };
}

function requiredText(value: string, name: string): string {
	const normalized = value.trim();
	if (!normalized) throw new Error(`${name} is required`);
	return normalized;
}

function positiveInteger(value: number, name: string): number {
	if (!Number.isInteger(value) || value < 1) throw new Error(`${name} must be a positive integer`);
	return value;
}

function optionalPositiveInteger(value: number | null | undefined, name: string): number | null {
	return value === undefined || value === null ? null : positiveInteger(value, name);
}

function optionalPositiveNumber(value: number | null | undefined, name: string): number | null {
	if (value === undefined || value === null) return null;
	if (!Number.isFinite(value) || value <= 0) throw new Error(`${name} must be a positive number`);
	return value;
}
