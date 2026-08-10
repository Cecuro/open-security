/** How much of stored threat-model prose points outside this scan. */
export function citedOutOfScope(
	text: string,
	inScope: ReadonlySet<string>,
): { cited: number; outOfScope: number } {
	const paths = new Set(
		(text.match(/[A-Za-z0-9_@./-]+\.[A-Za-z0-9]{1,5}(?=[:`\s,)]|$)/g) ?? [])
			.map((path) => path.replace(/^[./]+/, ""))
			.filter((path) => path.includes("/")),
	);
	let outOfScope = 0;
	for (const path of paths) if (!inScope.has(path)) outOfScope++;
	return { cited: paths.size, outOfScope };
}
