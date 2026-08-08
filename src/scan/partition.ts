/**
 * Cutting the repository into pieces one agent can hold.
 *
 * This came back after being deleted. The argument for removing it was that
 * codex-security has no partitioning and gets independence from workers that
 * each review everything — which is true, and which ignored a hard limit: a
 * 3.4MB repository does not fit in one context. Handed all 427 files and a
 * worklist that would not let it skip any, a probe made 456 read calls, one
 * delegate call, accumulated 3.6MB of tool results and died mid-discovery.
 *
 * So a partition is not an accountability device. It is the unit that fits.
 * Independence is a separate axis and is bought separately, by running more
 * probes — not by widening the one each probe carries.
 */
export interface Partition {
	id: number;
	paths: string[];
	bytes: number;
}

export interface PartitionOptions {
	maxFiles?: number;
	maxPartitions?: number;
}

const DEFAULT_PARTITION_MAX_FILES = 15;
const DEFAULT_MAX_PARTITIONS = 8;

export function partition(
	files: Array<{ path: string; bytes: number }>,
	opts: PartitionOptions = {},
): Partition[] {
	const maxFiles = opts.maxFiles ?? DEFAULT_PARTITION_MAX_FILES;
	const maxPartitions = opts.maxPartitions ?? DEFAULT_MAX_PARTITIONS;

	if (files.length === 0) return [];

	const sorted = [...files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

	const count = Math.max(1, Math.min(Math.ceil(sorted.length / maxFiles), maxPartitions));

	const base = Math.floor(sorted.length / count);
	const extra = sorted.length % count;
	const parts: Partition[] = [];
	let start = 0;
	for (let i = 0; i < count; i++) {
		const size = base + (i < extra ? 1 : 0);
		const slice = sorted.slice(start, start + size);
		start += size;
		if (slice.length === 0) continue;
		parts.push({
			id: parts.length,
			paths: slice.map((f) => f.path),
			bytes: slice.reduce((n, f) => n + f.bytes, 0),
		});
	}
	return parts;
}

export function describeDistribution(parts: Partition[]): string {
	if (parts.length === 0) return "no partitions";
	const sizes = parts.map((p) => p.paths.length);
	return `${parts.length} partition(s), ${sizes.join("/")} files (min ${Math.min(...sizes)}, max ${Math.max(...sizes)})`;
}
