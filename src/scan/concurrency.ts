/**
 * Run a bounded number of agents at once.
 *
 * Passes are independent looks at the whole repository, so this only controls
 * how many run at once.
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
