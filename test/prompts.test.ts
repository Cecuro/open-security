import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { loadPrompts } from "../src/scan/prompts.js";

describe("prompt shared sections", () => {
	it("expands the plain writing guide in shipped prompts", () => {
		const prompt = loadPrompts().get("probe.md");

		expect(prompt).toContain("Write plainly. Use short common words and active voice.");
		expect(prompt).not.toContain("{{PLAIN_WRITING_GUIDE}}");
	});

	it("expands known sections in overrides and leaves unknown ones visible", () => {
		const dir = mkdtempSync(join(tmpdir(), "opensec-prompts-"));
		writeFileSync(
			join(dir, "probe.md"),
			"{{PLAIN_WRITING_GUIDE}}\n{{UNKNOWN_GUIDE}}\nReview the worklist.\n",
		);

		const prompts = loadPrompts(dir);
		const prompt = prompts.get("probe.md");

		expect(prompt).toContain("Write plainly. Use short common words and active voice.");
		expect(prompt).toContain("{{UNKNOWN_GUIDE}}");
		expect(prompts.sources["probe.md"]).toBe(join(dir, "probe.md"));
	});
});
