import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const cli = fileURLToPath(new URL("../dist/cli/agent.js", import.meta.url));
const result = spawnSync(process.execPath, [cli, "--help"], { encoding: "utf8" });

if (result.status !== 0 || !result.stdout.includes("AGENT COMMANDS")) {
	process.stderr.write(result.stderr || "compiled agent CLI did not run its command entrypoint\n");
	process.exit(1);
}
