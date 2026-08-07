import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		// `.claude/worktrees/` holds full checkouts of this repository, each with
		// its own copy of the suite. Vitest's default exclude covers node_modules
		// and dist but knows nothing about them, so running from the repo root
		// collected every worktree's tests too: 677 tests across 66 files instead
		// of 143 across 14, and 65 seconds instead of 10.
		//
		// The count is the real problem, not the time. A suite that silently runs
		// several revisions of itself reports a number that means nothing — a test
		// deleted here still passes from a worktree, and a failure points at a file
		// path that is not the one being edited.
		exclude: [
			"**/node_modules/**",
			"**/dist/**",
			"**/.claude/**",
			"**/.git/**",
		],
	},
});
