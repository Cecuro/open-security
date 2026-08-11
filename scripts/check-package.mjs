import { spawnSync } from "node:child_process";

const npm = process.platform === "win32" ? "npm.cmd" : "npm";
const result = spawnSync(npm, ["pack", "--dry-run", "--json", "--ignore-scripts"], {
	cwd: new URL("..", import.meta.url),
	encoding: "utf8",
});

if (result.status !== 0) {
	process.stderr.write(result.stderr || result.stdout);
	process.exit(result.status ?? 1);
}

const [pack] = JSON.parse(result.stdout);
const files = new Set(pack.files.map((file) => file.path));
const required = [
	"README.md",
	"package.json",
	"dist/cli/index.js",
	"dist/db/schema.sql",
	"dist/review/server.js",
	"dist/review/assets/index.html",
	"dist/review/assets/app.js",
	"dist/review/assets/styles.css",
];
const missing = required.filter((file) => !files.has(file));
if (missing.length > 0) {
	throw new Error(`package is missing: ${missing.join(", ")}`);
}
if (pack.version === "0.0.0") throw new Error("set a release version before packing");

process.stdout.write(`package ${pack.name}@${pack.version}: ${pack.entryCount} files, ${pack.size} bytes\n`);
