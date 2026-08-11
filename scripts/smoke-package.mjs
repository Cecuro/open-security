import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const npm = process.platform === "win32" ? "npm.cmd" : "npm";
const root = new URL("..", import.meta.url);
const temp = mkdtempSync(join(tmpdir(), "opensec-package-"));

try {
	const packed = run(npm, ["pack", "--json", "--ignore-scripts", "--pack-destination", temp], root);
	const [{ filename }] = JSON.parse(packed);
	const consumer = join(temp, "consumer");
	mkdirSync(consumer);
	run(npm, ["install", "--no-audit", "--no-fund", "--prefix", consumer, join(temp, filename)], root);

	const cli = join(consumer, "node_modules", "opensec", "dist", "cli", "index.js");
	const help = run(process.execPath, [cli, "--help"], consumer);
	if (!help.includes("opensec review")) throw new Error("installed CLI help is missing the review command");

	const child = spawn(process.execPath, [cli, "review", "--db", join(temp, "ledger.db"), "--no-open"], {
		cwd: consumer,
		stdio: ["ignore", "pipe", "pipe"],
	});
	const url = await reviewUrl(child);
	for (const path of ["/", "/assets/styles.css", "/assets/app.js"]) {
		const response = await fetch(new URL(path, url));
		if (!response.ok) throw new Error(`installed reviewer returned ${response.status} for ${path}`);
	}
	child.kill("SIGTERM");
	await exited(child);
	process.stdout.write("installed package serves the bundled reviewer and shuts down cleanly\n");
} finally {
	rmSync(temp, { recursive: true, force: true });
}

function run(command, args, cwd) {
	const result = spawnSync(command, args, { cwd, encoding: "utf8" });
	if (result.status !== 0) {
		throw new Error(result.stderr || result.stdout || `${command} exited ${result.status}`);
	}
	return result.stdout;
}

function reviewUrl(child) {
	return new Promise((resolve, reject) => {
		let output = "";
		const timer = setTimeout(() => reject(new Error(`reviewer did not start:\n${output}`)), 15_000);
		child.stdout.on("data", (chunk) => {
			output += chunk;
			const match = output.match(/OpenSec review: (http:\/\/127\.0\.0\.1:\d+\/)/);
			if (!match) return;
			clearTimeout(timer);
			resolve(match[1]);
		});
		child.stderr.on("data", (chunk) => { output += chunk; });
		child.once("exit", (code) => {
			clearTimeout(timer);
			reject(new Error(`reviewer exited ${code}:\n${output}`));
		});
	});
}

function exited(child) {
	return new Promise((resolve, reject) => {
		const timer = setTimeout(() => {
			child.kill("SIGKILL");
			reject(new Error("reviewer did not stop after SIGTERM"));
		}, 10_000);
		child.once("exit", (code) => {
			clearTimeout(timer);
			if (code === 0 || code === null) resolve();
			else reject(new Error(`reviewer exited ${code}`));
		});
	});
}
