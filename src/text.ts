const CONTROL_CHARS = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g;

export function stripControlChars(s: string): string {
	return s.replace(CONTROL_CHARS, "");
}

const SECRET_PATTERNS: Array<[RegExp, string]> = [
	[/\b(sk|pk|rk)_(live|test)_[A-Za-z0-9]{8,}/g, "$1_$2_[redacted]"],
	[/\b(sk|pk)-[A-Za-z0-9_-]{16,}/g, "$1-[redacted]"],
	[/\bgh[pousr]_[A-Za-z0-9]{16,}/g, "gh?_[redacted]"],
	[/\bxox[abposr]-[A-Za-z0-9-]{10,}/g, "xox?-[redacted]"],
	[/\bAIza[A-Za-z0-9_-]{20,}/g, "AIza[redacted]"],
	[/\bAKIA[0-9A-Z]{12,}/g, "AKIA[redacted]"],
	[/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "[redacted private key]"],
	[/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, "[redacted jwt]"],
	[
		/\b(password|passwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)(\s*[:=]\s*)(["'`])[^"'`\n]{6,}\3/gi,
		"$1$2$3[redacted]$3",
	],
];

export function redactSecrets(s: string): string {
	let out = s;
	for (const [pattern, replacement] of SECRET_PATTERNS) out = out.replace(pattern, replacement);
	return out;
}
