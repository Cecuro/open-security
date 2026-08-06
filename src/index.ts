/** Public SDK surface. `import { Scanner } from "opensec"`. */

export { Scanner, type ScannerOptions, type ScanResult } from "./sdk/scanner.js";
export { Ledger, defaultDbPath, scanArtifactDir } from "./db/db.js";
export { inventory, type InventoryResult, type InventoryEntry } from "./scan/inventory.js";
export {
	computeSeverity,
	formatSeverity,
	renderMatrix,
	reportabilityGate,
	severityRank,
	CONFIDENCE_BY_METHOD,
} from "./scan/severity.js";
export { renderMarkdown, type ReportInput } from "./scan/render.js";
export { loadPrompts, wrapUntrusted, type Prompts, PROMPT_NAMES } from "./scan/prompts.js";
export { AgentRunner } from "./agents/session.js";
export { createOpensecTool, type RunContext } from "./agents/tool.js";
export type * from "./types.js";
