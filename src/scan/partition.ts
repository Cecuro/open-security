/**
 * Partitioning: who is accountable for which files. No LLM.
 *
 * **Ownership is partitioned; reading is not.** Real bugs cross files — the
 * source in `handlers/upload.ts`, the missing containment in `lib/archive.ts` —
 * so every probe reads the whole repository and only its *worklist* is its own
 * (plan §4).
 *
 * This is the cheap version, and it is deliberately labelled as such. The plan
 * calls for size-capped clusters over an import graph, split by directory
 * affinity and merged at the floor. What is here instead: files are already
 * sorted `LC_ALL=C` by inventory, and sorted paths cluster by directory for
 * free, so chunking the sorted list gives directory affinity without building a
 * graph. It balances by count, which is the property parallel probes need. It
 * does NOT know that `utils/crypto.ts` belongs with `auth/session.ts`, and the
 * import-graph version that would is still M1.
 */

export interface Partition {
	id: number;
	paths: string[];
	bytes: number;
}

export interface PartitionOptions {
	/** Ceiling on files per probe. One probe owning 300 files is a weak claim. */
	maxFiles?: number;
	/** Never spin up a probe for a handful of files. */
	minFiles?: number;
	/** Hard ceiling on concurrent probes. */
	maxPartitions?: number;
}

export const DEFAULT_PARTITION_MAX_FILES = 60;
export const DEFAULT_PARTITION_MIN_FILES = 8;
export const DEFAULT_MAX_PARTITIONS = 8;

export function partition(
	files: Array<{ path: string; bytes: number }>,
	opts: PartitionOptions = {},
): Partition[] {
	const maxFiles = opts.maxFiles ?? DEFAULT_PARTITION_MAX_FILES;
	const minFiles = opts.minFiles ?? DEFAULT_PARTITION_MIN_FILES;
	const maxPartitions = opts.maxPartitions ?? DEFAULT_MAX_PARTITIONS;

	if (files.length === 0) return [];

	// Sorted so the result is byte-identical across runs, and so neighbouring
	// paths — which are usually the same directory — land together.
	const sorted = [...files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

	// How many probes this repo justifies: enough that no partition exceeds the
	// cap, but never so many that each one owns a trivial slice.
	let count = Math.ceil(sorted.length / maxFiles);
	count = Math.min(count, maxPartitions, Math.max(1, Math.floor(sorted.length / minFiles)));
	count = Math.max(1, count);

	// Even split rather than fill-to-cap: eight probes with 30 files each beat
	// four with 60 and one with 3, and the size distribution is what the scan
	// header reports.
	const per = Math.ceil(sorted.length / count);
	const parts: Partition[] = [];
	for (let i = 0; i < count; i++) {
		const slice = sorted.slice(i * per, (i + 1) * per);
		if (slice.length === 0) continue;
		parts.push({
			id: parts.length,
			paths: slice.map((f) => f.path),
			bytes: slice.reduce((n, f) => n + f.bytes, 0),
		});
	}
	return parts;
}

/**
 * Run `tasks` with at most `limit` in flight.
 *
 * Deliberately not `Promise.all` over everything: eight concurrent probes each
 * holding a context window is real memory and real rate-limit pressure, and a
 * provider 429 mid-scan is worse than finishing a minute later. Results keep
 * input order. A rejection propagates — a phase that half-ran is not a phase
 * that ran.
 */
export async function mapConcurrent<T, R>(
	items: T[],
	limit: number,
	fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
	const results = new Array<R>(items.length);
	let next = 0;
	const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
		for (;;) {
			const i = next++;
			if (i >= items.length) return;
			results[i] = await fn(items[i] as T, i);
		}
	});
	await Promise.all(workers);
	return results;
}

/**
 * Printed in the scan header, because one probe owning most of the repo is a
 * run whose coverage claim is worth less, and that should be visible rather
 * than buried (plan §4).
 */
export function describeDistribution(parts: Partition[]): string {
	if (parts.length === 0) return "no partitions";
	const sizes = parts.map((p) => p.paths.length);
	const min = Math.min(...sizes);
	const max = Math.max(...sizes);
	return `${parts.length} partition(s), ${sizes.join("/")} files (min ${min}, max ${max})`;
}
