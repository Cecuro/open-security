export interface Partition {
	id: number;
	paths: string[];
	bytes: number;
}

export interface PartitionOptions {
	maxFiles?: number;
	minFiles?: number;
	maxPartitions?: number;
}

export const DEFAULT_PARTITION_MAX_FILES = 15;
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

	const sorted = [...files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

	let count = Math.ceil(sorted.length / maxFiles);
	count = Math.min(count, maxPartitions, Math.max(1, Math.floor(sorted.length / minFiles)));
	count = Math.max(1, count);

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

export function describeDistribution(parts: Partition[]): string {
	if (parts.length === 0) return "no partitions";
	const sizes = parts.map((p) => p.paths.length);
	const min = Math.min(...sizes);
	const max = Math.max(...sizes);
	return `${parts.length} partition(s), ${sizes.join("/")} files (min ${min}, max ${max})`;
}
