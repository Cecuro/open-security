// schema.sql is data, not TypeScript, so tsc does not carry it into dist/.
import { chmodSync, cpSync, copyFileSync, mkdirSync } from "node:fs";

// tsc creates the bin entry as a regular file. npm's global symlink needs the
// target itself to stay executable after every local build and install.
chmodSync("dist/cli/index.js", 0o755);

mkdirSync("dist/db", { recursive: true });
copyFileSync("src/db/schema.sql", "dist/db/schema.sql");

mkdirSync("dist/review", { recursive: true });
cpSync("src/review/assets", "dist/review/assets", { recursive: true });
