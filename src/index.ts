/** Public SDK surface. `import { Scanner } from "opensec"`. */

export { Scanner, type ScannerOptions, type ScanResult } from "./sdk/scanner.js";
export { Ledger, defaultDbPath, opensecDir, scanArtifactDir } from "./db/db.js";
export { inventory, type InventoryResult, type InventoryEntry } from "./scan/inventory.js";
export {
	computeSeverity,
	formatSeverity,
	renderMatrix,
	reportabilityGate,
	suppressionClaim,
	severityRank,
	CONFIDENCE_BY_METHOD,
} from "./scan/severity.js";
export { renderMarkdown, type ReportInput } from "./scan/render.js";
export { loadEnv, describeEnv, envFilePath, type EnvLoadResult } from "./env.js";
export { loadPrompts, wrapUntrusted, type Prompts, PROMPT_NAMES } from "./scan/prompts.js";
export { AgentRunner } from "./agents/session.js";
export { createOpensecTool, type RunContext, type Verb } from "./agents/tool.js";
export {
	collisionGroups,
	cweFamily,
	identityHash,
	identityOf,
	type Identity,
} from "./scan/identity.js";
export { MIGRATIONS, SCHEMA_VERSION, type Migration } from "./db/migrations.js";
export type * from "./types.js";
