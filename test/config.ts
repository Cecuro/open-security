import { normalizeScanConfig, type ScanConfigInput } from "../src/scan/config.js";
import type { Profile, ScanConfig } from "../src/types.js";

export function testScanConfig(
	profile: Profile = "local",
	overrides: Partial<ScanConfigInput> = {},
): ScanConfig {
	return normalizeScanConfig({
		modelRef: "test/model",
		promptHash: "test-prompts",
		profile,
		...overrides,
	});
}
