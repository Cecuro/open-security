/**
 * Shared text hygiene. One copy, because a security-relevant regex duplicated
 * across the write boundary and the terminal is a regex that will drift.
 */

/**
 * Keep tab, newline and carriage return; drop every other C0 control plus DEL.
 * ESC in particular: OSC 52 writes the clipboard and OSC 8 forges links, and
 * every string this runs on originated in attacker-authored source.
 */
// biome-ignore lint/suspicious/noControlCharactersInRegex: stripping them is the point
const CONTROL_CHARS = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g;

export function stripControlChars(s: string): string {
	return s.replace(CONTROL_CHARS, "");
}

/**
 * Findings about hardcoded credentials quote the credential — `probe.md` asks
 * for "the code path you traced, quoted", and secrets in code are one of the
 * things it is told to hunt. Without this the happy path copies live keys out
 * of the repo into a long-lived global SQLite database and into report files
 * (plan §5).
 *
 * Deliberately shape-based and conservative. It cannot catch every secret, so
 * it leaves the surrounding evidence intact and readable — a finding that says
 * `sk_live_[redacted]` still tells you which line to look at.
 */
const SECRET_PATTERNS: Array<[RegExp, string]> = [
	// Vendor-prefixed keys: Stripe, OpenAI, GitHub, Slack, Google, AWS.
	[/\b(sk|pk|rk)_(live|test)_[A-Za-z0-9]{8,}/g, "$1_$2_[redacted]"],
	[/\b(sk|pk)-[A-Za-z0-9_-]{16,}/g, "$1-[redacted]"],
	[/\bgh[pousr]_[A-Za-z0-9]{16,}/g, "gh?_[redacted]"],
	[/\bxox[abposr]-[A-Za-z0-9-]{10,}/g, "xox?-[redacted]"],
	[/\bAIza[A-Za-z0-9_-]{20,}/g, "AIza[redacted]"],
	[/\bAKIA[0-9A-Z]{12,}/g, "AKIA[redacted]"],
	// PEM private keys.
	[/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "[redacted private key]"],
	// JWTs.
	[/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, "[redacted jwt]"],
	// key = "...." / password: '....' — the assignment, not the identifier.
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
