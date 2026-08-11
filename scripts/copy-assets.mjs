// schema.sql is data, not TypeScript, so tsc does not carry it into dist/.
import { cpSync, copyFileSync, mkdirSync } from "node:fs";

mkdirSync("dist/db", { recursive: true });
copyFileSync("src/db/schema.sql", "dist/db/schema.sql");

mkdirSync("dist/review", { recursive: true });
cpSync("src/review/assets", "dist/review/assets", { recursive: true });
