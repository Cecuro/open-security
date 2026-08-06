// schema.sql is data, not TypeScript, so tsc does not carry it into dist/.
import { copyFileSync, mkdirSync } from "node:fs";

mkdirSync("dist/db", { recursive: true });
copyFileSync("src/db/schema.sql", "dist/db/schema.sql");
