/**
 * Run a bounded number of agents at once.
 *
 * This file used to also cut the repository into partitions, one per probe.
 * That is gone: probes are independent looks at the whole repository now, not
 * a division of labour, so the only thing left to manage is how many run at
 * once.
 */
export async function mapConcurrent<T, R>(
	items: T[],
	limit: number,
	fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
	const results = new Array<R>(items.length);
	let next = 0;
	let firstError: unknown;
	let failed = false;
	const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
		// On failure, stop taking new items but let in-flight ones finish: each
		// item here is a full agent run whose work lands in the ledger, and the
		// caller may close that ledger the moment this rejects.
		for (;;) {
			if (failed) return;
			const i = next++;
			if (i >= items.length) return;
			try {
				results[i] = await fn(items[i] as T, i);
			} catch (err) {
				if (!failed) {
					failed = true;
					firstError = err;
				}
			}
		}
	});
	await Promise.all(workers);
	if (failed) throw firstError;
	return results;
}
