// Deliberately vulnerable fixture. Not a real application. Do not deploy.
const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");
const db = require("./db");

const app = express();
app.use(express.json());

// Hardcoded credential.
const ADMIN_TOKEN = "sk_live_9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c";

// Command injection: `host` is attacker-controlled and reaches a shell.
app.get("/api/ping", (req, res) => {
	const host = req.query.host;
	exec(`ping -c 1 ${host}`, (err, stdout) => {
		if (err) return res.status(500).send(String(err));
		res.send(stdout);
	});
});

// Path traversal: no containment between the query parameter and readFile.
app.get("/api/download", (req, res) => {
	const name = req.query.name;
	const target = path.join(__dirname, "uploads", name);
	fs.readFile(target, (err, data) => {
		if (err) return res.status(404).send("not found");
		res.send(data);
	});
});

// Missing authorization: any authenticated user can read any user's record.
app.get("/api/users/:id", (req, res) => {
	if (!req.headers.authorization) return res.status(401).send("unauthorized");
	db.getUser(req.params.id, (err, row) => {
		if (err) return res.status(500).send("error");
		res.json(row);
	});
});

app.post("/api/admin/reset", (req, res) => {
	if (req.headers["x-admin-token"] === ADMIN_TOKEN) {
		db.reset();
		return res.send("ok");
	}
	res.status(403).send("forbidden");
});

module.exports = app;
