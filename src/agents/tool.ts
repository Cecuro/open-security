/**
 * The one structured tool the scan's agents write through (plan §3).
 *
 * Five verbs. Prose arrives as JSON and never touches a shell — no backtick
 * command substitution, no --body-file dance. There is deliberately no
 * `files.done` verb: coverage is derived from traces, so an agent cannot mark
 * work it never did.
 *
 * `candidate.validate` and `candidate.assess` were one verb until the passes
 * were split. Keeping them separate is what makes the split real: a validating
 * agent has no way to record a severity, and an assessing agent has no way to
 * revisit whether the finding was real.
 */

import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { isAbsolute, relative, resolve } from "node:path";

import { defineTool } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

import type { Ledger } from "../db/db.js";
import { now } from "../db/db.js";
import { computeSeverity } from "../scan/severity.js";
import { redactSecrets, stripControlChars } from "../text.js";
import type {
	AuthRequired,
	Disposition,
	Impact,
	Location,
	LocationRole,
	Method,
	Profile,
	Reachability,
	Resolution,
	SeverityInputs,
	Vector,
} from "../types.js";

/**
 * Bound to (scan_id, worker_id): everything a tool call needs to know about
 * who is writing and what they are allowed to write about.
 */
export interface RunContext {
	scanId: string;
	workerId: string;
	repoRoot: string;
	profile: Profile;
	ledger: Ledger;
	/** Per-run delimiter wrapping repo-derived text. Stripped from agent prose. */
	nonce: string;
	/**
	 * Which verbs this worker may call. Every phase used to get all of them, so a
	 * reducer could dispose of anything and a subagent could file findings its
	 * parent never saw. Subagents get a read-only subset (plan §4's ownership
	 * rule only means something if writes are attributable to an accountable
	 * worker).
	 */
	verbs?: Verb[];
	/** How many subagents deep this worker is. 0 is a phase agent. */
	depth?: number;
	/**
	 * Which partition this worker owns. Undefined means the whole scan, which is
	 * what every phase after discovery gets — only probes are partitioned.
	 */
	partitionId?: number;
	/**
	 * Which candidates this worker may write to. Undefined means any. Validate is
	 * handed exactly the row it was asked about; the reducer is handed its group.
	 */
	resolvableIds?: string[];
	/**
	 * Which dispositions this worker may set. The reducer gets `["duplicate"]`
	 * only: it is comparing rows that have not been validated yet, so letting it
	 * mark one `not_applicable` would drop a finding nobody ever read.
	 */
	dispositions?: Disposition[];
}

export type Verb =
	| "work.next"
	| "candidate.create"
	| "candidate.validate"
	| "candidate.assess"
	| "lead.record";

/**
 * Verbs by role, not one set for everyone.
 *
 * A scan of opensec by opensec found the reason: with probes running in
 * parallel, every phase holding every verb meant one probe could resolve
 * another probe's candidate — ids are predictable `c1`, `c2` — and quietly
 * suppress a finding it never saw. Probes file; validate judges; assess rates;
 * the reducer only merges. Nobody needs the whole set.
 */
export const PROBE_VERBS: Verb[] = ["work.next", "candidate.create", "lead.record"];
export const VALIDATE_VERBS: Verb[] = ["work.next", "candidate.validate", "lead.record"];
export const ASSESS_VERBS: Verb[] = ["work.next", "candidate.assess", "lead.record"];
export const REDUCE_VERBS: Verb[] = ["candidate.validate"];
export const SUBAGENT_VERBS: Verb[] = ["work.next", "lead.record"];

const ROLES = ["entrypoint", "source", "root_control", "sink", "evidence"] as const;

const LocationSchema = Type.Object(
	{
		path: Type.String({ description: "Repo-relative path, e.g. src/handlers/upload.ts" }),
		start_line: Type.Integer({ minimum: 1 }),
		end_line: Type.Integer({ minimum: 1 }),
		symbol: Type.Optional(Type.String({ description: "Enclosing function or class, if known" })),
		role: Type.Optional(
			Type.Union(
				ROLES.map((r) => Type.Literal(r)),
				{
					description:
						"What this location IS to the finding: entrypoint (attacker's way in), " +
						"source (where untrusted data enters), root_control (the check that is " +
						"missing or wrong), sink (where the harm happens), evidence (supporting). " +
						"Defaults to evidence.",
				},
			),
		),
	},
	{ additionalProperties: false },
);

const SuppressionSchema = Type.Object(
	{
		self_only: Type.Optional(Type.Boolean()),
		requires_preexisting_privilege: Type.Optional(Type.Boolean()),
		privilege_delta_is_the_bug: Type.Optional(Type.Boolean()),
		precondition_unreachable: Type.Optional(Type.Boolean()),
		evidence: Type.Optional(Type.String()),
		source: Type.Optional(
			Type.Union([
				Type.Literal("policy_flag"),
				Type.Literal("code_evidence"),
				Type.Literal("repo_claim"),
			]),
		),
	},
	{ additionalProperties: false },
);

const ParamsSchema = Type.Object(
	{
		verb: Type.Union([
			Type.Literal("work.next"),
			Type.Literal("candidate.create"),
			Type.Literal("candidate.validate"),
			Type.Literal("candidate.assess"),
			Type.Literal("lead.record"),
		]),

		// work.next
		limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 200 })),
		cursor: Type.Optional(Type.Integer({ minimum: 0 })),

		// candidate.create
		title: Type.Optional(Type.String()),
		cwe: Type.Optional(
			Type.Array(Type.String(), {
				description: "CWE ids like CWE-89. Leave empty when there is no clear class.",
			}),
		),
		locations: Type.Optional(Type.Array(LocationSchema)),
		summary: Type.Optional(Type.String()),
		evidence: Type.Optional(Type.String()),
		instance: Type.Optional(
			Type.String({
				description:
					"What distinguishes this from a sibling finding of the same class in the same " +
					"place — the parameter name, the secret's variable, the route. Two findings " +
					"with the same class, files and instance are treated as one.",
			}),
		),

		// candidate.validate / candidate.assess
		id: Type.Optional(Type.String()),
		disposition: Type.Optional(
			Type.Union([
				Type.Literal("confirmed"),
				Type.Literal("not_applicable"),
				Type.Literal("duplicate"),
				Type.Literal("needs_follow_up"),
			]),
		),
		rationale: Type.Optional(Type.String()),
		duplicate_of: Type.Optional(Type.String()),

		// candidate.assess — reachability
		entry_point: Type.Optional(
			Type.String({ description: "path:line where an attacker starts, and what they control" }),
		),
		path: Type.Optional(
			Type.Array(Type.String(), {
				description: "Each hop from entry point to sink, in order, with path:line",
			}),
		),
		controls: Type.Optional(
			Type.Array(Type.String(), {
				description:
					"Every check, filter or encoder ON that path, with path:line. An empty list " +
					"is a claim that there are none, and it is what promotes a finding.",
			}),
		),

		// candidate.assess — severity inputs
		impact: Type.Optional(
			Type.Union([
				Type.Literal("none"),
				Type.Literal("low"),
				Type.Literal("medium"),
				Type.Literal("high"),
			]),
		),
		vector: Type.Optional(
			Type.Union([
				Type.Literal("remote"),
				Type.Literal("local_network"),
				Type.Literal("localhost"),
				Type.Literal("none"),
				Type.Literal("unknown"),
			]),
		),
		auth_required: Type.Optional(
			Type.Union([Type.Literal("none"), Type.Literal("user"), Type.Literal("admin")]),
		),
		network_reachable: Type.Optional(Type.Boolean()),
		cross_tenant: Type.Optional(Type.Boolean()),
		code_execution_proven: Type.Optional(Type.Boolean()),
		traced_path_no_control: Type.Optional(Type.Boolean()),
		method: Type.Optional(
			Type.Union([
				Type.Literal("reproduced_poc"),
				Type.Literal("asan"),
				Type.Literal("debugger"),
				Type.Literal("code_reading"),
				Type.Literal("counterevidence"),
			]),
		),
		suppression: Type.Optional(SuppressionSchema),

		// lead.record
		text: Type.Optional(Type.String()),
		status: Type.Optional(
			Type.Union([
				Type.Literal("open"),
				Type.Literal("dead_end"),
				Type.Literal("became_candidate"),
			]),
		),
	},
	// A typo'd field is silent data loss, so unknown fields are rejected.
	{ additionalProperties: false },
);

const DESCRIPTION = `Record security review work. One tool, five verbs:

- work.next({ limit, cursor }) — the files you are accountable for, and the total.
- candidate.create({ title, cwe, locations, summary, evidence, instance }) — a
  suspected flaw. locations must cite real line ranges in files inside the repo.
- candidate.validate({ id, disposition, rationale }) — is it real? No severity here.
- candidate.assess({ id, entry_point, path, controls, impact, ... }) — how far it
  reaches, plus the observable inputs severity is computed from. You do not set
  severity.
- lead.record({ text, status }) — a hypothesis you chased. Record dead ends too.`;

export function createOpensecTool(ctx: RunContext) {
	return defineTool({
		name: "opensec",
		label: "opensec",
		description: DESCRIPTION,
		parameters: ParamsSchema,
		promptSnippet: "opensec - record worklist progress, candidates, verdicts and leads",
		promptGuidelines: [
			"Call opensec work.next before reviewing anything — it is the list you are accountable for.",
			"Record dead ends with lead.record. Silence is indistinguishable from never having looked.",
		],
		// The single writer to the ledger. Serialising it keeps two calls in one
		// tool batch from interleaving a create and a validate.
		executionMode: "sequential",
		async execute(_id, params) {
			// Validation failures throw. The agent loop catches per tool call and
			// hands the message back to the model, so a hallucinated line number is
			// a hard, recoverable tool error rather than a bad row in the report.
			const output = run(ctx, params as Params);
			return { content: [{ type: "text", text: output }], details: undefined };
		},
	});
}

type Params = {
	verb: Verb;
	[k: string]: unknown;
};

const ALL_VERBS: Verb[] = [
	"work.next",
	"candidate.create",
	"candidate.validate",
	"candidate.assess",
	"lead.record",
];

function run(ctx: RunContext, p: Params): string {
	const allowed = ctx.verbs ?? ALL_VERBS;
	if (!allowed.includes(p.verb)) {
		throw new Error(
			`'${p.verb}' is not available to ${ctx.workerId}. You may call: ${allowed.join(", ")}. ` +
				`Report what you found in your final message instead — whoever delegated to you records it.`,
		);
	}
	switch (p.verb) {
		case "work.next":
			return workNext(ctx, p);
		case "candidate.create":
			return candidateCreate(ctx, p);
		case "candidate.validate":
			return candidateValidate(ctx, p);
		case "candidate.assess":
			return candidateAssess(ctx, p);
		case "lead.record":
			return leadRecord(ctx, p);
		default:
			throw new Error(`unknown verb: ${String(p.verb)}`);
	}
}

function workNext(ctx: RunContext, p: Params): string {
	const limit = (p.limit as number | undefined) ?? 40;
	const cursor = (p.cursor as number | undefined) ?? 0;
	const { files, total } = ctx.ledger.listWork(ctx.scanId, limit, cursor, ctx.partitionId);
	const next = cursor + files.length;
	const lines = files.map((f) => `${f.path} (${f.bytes_total} bytes)`);
	return JSON.stringify(
		{
			files: lines,
			returned: files.length,
			cursor: next,
			total,
			remaining: Math.max(0, total - next),
			note:
				next < total
					? `call work.next again with cursor=${next} for the rest`
					: "end of worklist",
		},
		null,
		1,
	);
}

function candidateCreate(ctx: RunContext, p: Params): string {
	const title = requireText(p.title, "title");
	const summary = requireText(p.summary, "summary");
	const evidence = requireText(p.evidence, "evidence");
	const rawLocations = p.locations as Location[] | undefined;
	if (!rawLocations || rawLocations.length === 0) {
		throw new Error("candidate.create requires at least one location");
	}

	const locations = rawLocations.map((l) => validateLocation(ctx, l));

	// Ties every finding to an owner. With one probe this is just "in scope",
	// but it is the same check that carries into per-worker partitions.
	if (!locations.some((l) => ctx.ledger.fileInScope(ctx.scanId, l.path, ctx.partitionId))) {
		throw new Error(
			`no location is in your worklist — cite at least one file from work.next. ` +
				`Got: ${locations.map((l) => l.path).join(", ")}`,
		);
	}

	const instance =
		typeof p.instance === "string" && p.instance.trim().length > 0
			? sanitize(ctx, p.instance).slice(0, 200)
			: null;

	const { id, merged } = ctx.ledger.upsertCandidate({
		scanId: ctx.scanId,
		workerId: ctx.workerId,
		title: sanitize(ctx, title),
		cweIds: normalizeCwe(p.cwe as string[] | undefined),
		locations,
		summary: sanitize(ctx, summary),
		evidence: sanitize(ctx, evidence),
		instance,
	});

	return JSON.stringify({
		id,
		status: merged ? "merged_into_existing" : "recorded",
		locations: locations.length,
		...(merged
			? {
					note:
						`another worker already filed this exact finding (same class, same files ` +
						`and roles, same instance). Your evidence was added to ${id}. It has not ` +
						`been judged yet — finding it twice is search evidence, not proof.`,
				}
			: {}),
	});
}

/**
 * Pass one: is it real? No severity inputs are accepted here, which is the
 * whole point of the split — a reader deciding "does this hold up" cannot
 * simultaneously talk themselves into a reachability story.
 */
function candidateValidate(ctx: RunContext, p: Params): string {
	const { candidate, id } = requireCandidate(ctx, p);
	const rationale = sanitize(ctx, requireText(p.rationale, "rationale"));

	// Degradation is directional: an unparseable disposition becomes
	// needs_follow_up, never a quiet drop (plan §4).
	let disposition = (p.disposition as Disposition | undefined) ?? "needs_follow_up";
	const notes: string[] = [];

	if (ctx.dispositions && !ctx.dispositions.includes(disposition)) {
		throw new Error(
			`${ctx.workerId} may only set disposition: ${ctx.dispositions.join(", ")}. ` +
				`Got '${disposition}'.`,
		);
	}

	if (disposition === "duplicate") {
		const dup = typeof p.duplicate_of === "string" ? p.duplicate_of : "";
		const target = dup ? ctx.ledger.getCandidate(ctx.scanId, dup) : undefined;
		if (!target || dup === id) {
			disposition = "needs_follow_up";
			notes.push(`duplicate_of '${dup}' does not resolve; kept as needs_follow_up`);
		} else if (target.merged_into) {
			// Every duplicate must point at a row that survives. Without this, a
			// mutual merge (c1→c2, c2→c1) removes BOTH rows from the report — the
			// silent instance destruction plan §4 calls unacceptable. The prompt tells
			// the model not to chain, but a prompt is not an enforcement mechanism.
			disposition = "needs_follow_up";
			notes.push(
				`duplicate_of '${dup}' is itself merged into '${target.merged_into}'; ` +
					`point every duplicate at the surviving row. Kept as needs_follow_up.`,
			);
		} else {
			ctx.ledger.resolveCandidate(ctx.scanId, id, {
				disposition: "duplicate",
				rationale,
				duplicate_of: dup,
				validation: { disposition: "duplicate", rationale, at: now() },
			});
			return JSON.stringify({ id, disposition: "duplicate", duplicate_of: dup });
		}
	}

	const resolution: Resolution = {
		...(candidate.resolution ?? {}),
		disposition,
		rationale,
		validation: { disposition, rationale, at: now() },
	};
	ctx.ledger.resolveCandidate(ctx.scanId, id, resolution);

	return JSON.stringify({
		id,
		disposition,
		notes,
		next:
			disposition === "confirmed"
				? "a separate attack-path pass will rate this. You do not assess it."
				: undefined,
	});
}

/**
 * Pass two, over survivors only: how far does it reach, and what does that make
 * it worth? Reachability is recorded as structure rather than prose so the one
 * input that promotes a finding to critical can be checked against it.
 */
function candidateAssess(ctx: RunContext, p: Params): string {
	const { candidate, id } = requireCandidate(ctx, p);

	const validated = candidate.resolution?.validation?.disposition;
	if (validated !== "confirmed") {
		throw new Error(
			`${id} was not confirmed by validation (it is '${validated ?? "unvalidated"}'), ` +
				`so there is nothing to assess. Only confirmed findings reach this pass.`,
		);
	}

	const rationale = sanitize(ctx, requireText(p.rationale, "rationale"));
	const notes: string[] = [];
	const reachability = readReachability(ctx, p);
	const inputs = readSeverityInputs(ctx, p, notes);

	if (!inputs) {
		// No severity is a downgrade of the claim, not a deletion of the finding.
		const resolution: Resolution = {
			...(candidate.resolution ?? { disposition: "needs_follow_up", rationale }),
			disposition: "needs_follow_up",
			rationale,
			attack_path: { reachability, rationale, at: now() },
		};
		ctx.ledger.resolveCandidate(ctx.scanId, id, resolution);
		return JSON.stringify({
			id,
			disposition: "needs_follow_up",
			notes: [...notes, "impact and method are both required to compute a severity"],
		});
	}

	// The one input the tool can check. `traced_path_no_control` is one of two
	// routes to critical, and until the reachability trace existed nothing backed
	// it — a model could assert it while describing a path full of checks.
	if (inputs.traced_path_no_control) {
		if (reachability.path.length === 0) {
			inputs.traced_path_no_control = false;
			notes.push(
				"traced_path_no_control was set but no path was recorded; a claim to have traced " +
					"something requires the trace. Treated as false.",
			);
		} else if (reachability.controls.length > 0) {
			inputs.traced_path_no_control = false;
			notes.push(
				`traced_path_no_control was set while listing ${reachability.controls.length} ` +
					`control(s) on the path. Those two cannot both be true. Treated as false.`,
			);
		}
	}

	const computed = computeSeverity(inputs, ctx.profile);
	const resolution: Resolution = {
		...(candidate.resolution ?? {}),
		// The gate, not the model, decides whether this leaves the report.
		disposition: computed.reportable ? "confirmed" : "suppressed",
		rationale,
		attack_path: { reachability, rationale, at: now() },
		inputs,
		computed,
	};
	ctx.ledger.resolveCandidate(ctx.scanId, id, resolution);

	return JSON.stringify({
		id,
		disposition: resolution.disposition,
		severity: computed.severity,
		confidence: computed.confidence,
		proof_gap: computed.proof_gap,
		notes,
	});
}

function leadRecord(ctx: RunContext, p: Params): string {
	const text = sanitize(ctx, requireText(p.text, "text"));
	const status = (p.status as "open" | "dead_end" | "became_candidate" | undefined) ?? "open";
	ctx.ledger.recordLead(ctx.scanId, { worker_id: ctx.workerId, text, status });
	return JSON.stringify({ status: "recorded" });
}

function requireCandidate(ctx: RunContext, p: Params) {
	const id = requireText(p.id, "id");
	if (ctx.resolvableIds && !ctx.resolvableIds.includes(id)) {
		throw new Error(
			`${ctx.workerId} may not write to '${id}'. You were asked about: ` +
				`${ctx.resolvableIds.join(", ")}.`,
		);
	}
	const candidate = ctx.ledger.getCandidate(ctx.scanId, id);
	if (!candidate) throw new Error(`no candidate ${id} in this scan`);
	return { candidate, id };
}

function readReachability(ctx: RunContext, p: Params): Reachability {
	const list = (v: unknown): string[] =>
		Array.isArray(v)
			? v
					.filter((x): x is string => typeof x === "string" && x.trim().length > 0)
					.map((x) => sanitize(ctx, x).slice(0, 500))
					.slice(0, 40)
			: [];
	return {
		entry_point:
			typeof p.entry_point === "string" ? sanitize(ctx, p.entry_point).slice(0, 500) : "",
		path: list(p.path),
		controls: list(p.controls),
	};
}

function readSeverityInputs(
	ctx: RunContext,
	p: Params,
	notes: string[],
): SeverityInputs | null {
	const impact = p.impact as Impact | undefined;
	const vector = p.vector as Vector | undefined;
	const method = p.method as Method | undefined;
	if (!impact || !method) return null;
	if (!vector) notes.push("no vector given; treated as unknown, which caps likelihood at low");

	// suppression.evidence is agent prose like every other free-text field, and
	// it reaches the report through computed.rationale.
	const suppression = p.suppression as SeverityInputs["suppression"];
	if (suppression?.evidence) {
		suppression.evidence = sanitize(ctx, suppression.evidence);
	}

	return {
		impact,
		vector: vector ?? "unknown",
		auth_required: (p.auth_required as AuthRequired | undefined) ?? "user",
		network_reachable: p.network_reachable === true,
		cross_tenant: p.cross_tenant === true,
		code_execution_proven: p.code_execution_proven === true,
		traced_path_no_control: p.traced_path_no_control === true,
		method,
		suppression,
	};
}

/**
 * Locations must resolve inside the repo, be a regular file, and cite a line
 * range that exists. Scanned code is attacker-authored, so a symlink out of the
 * tree is a rejection rather than a read.
 */
function validateLocation(ctx: RunContext, loc: Location): Location {
	if (typeof loc?.path !== "string" || loc.path.length === 0) {
		throw new Error("location.path is required");
	}
	if (isAbsolute(loc.path)) {
		throw new Error(`location.path must be repo-relative, got '${loc.path}'`);
	}

	const root = realpathSync(ctx.repoRoot);
	const abs = resolve(root, loc.path);

	// Three checks, in this order, so each failure reports its real cause.
	//
	// 1. Lexical containment catches `../etc/passwd` before touching the disk.
	if (outsideRoot(root, abs)) {
		throw new Error(`location '${loc.path}' resolves outside the repo`);
	}

	// 2. A symlinked leaf is rejected outright rather than silently rewritten to
	//    its target: an agent citing a link has cited the wrong file.
	let leaf: ReturnType<typeof lstatSync>;
	try {
		leaf = lstatSync(abs);
	} catch {
		throw new Error(`no such file: ${loc.path}`);
	}
	if (leaf.isSymbolicLink()) throw new Error(`location '${loc.path}' is a symlink`);
	if (!leaf.isFile()) throw new Error(`location '${loc.path}' is not a regular file`);

	// 3. Lexical containment is not enough on its own: `lstat` declines to follow
	//    only the FINAL component, so `docs/passwd` where `docs` is a symlink to
	//    /tmp/outside passes step 1 and reads a file outside the repo entirely.
	//    Containment must also hold for the fully resolved path.
	const real = realpathSync(abs);
	if (outsideRoot(root, real)) {
		throw new Error(
			`location '${loc.path}' resolves outside the repo through a symlinked directory`,
		);
	}
	const rel = relative(root, real);

	const lineCount = countLines(readFileSync(real, "utf8"));
	const start = Number(loc.start_line);
	const end = Number(loc.end_line ?? loc.start_line);
	if (!Number.isInteger(start) || start < 1 || start > lineCount) {
		throw new Error(`${loc.path}:${start} does not exist — the file has ${lineCount} lines`);
	}
	if (!Number.isInteger(end) || end < start || end > lineCount) {
		throw new Error(
			`${loc.path}:${start}-${end} is not a valid range — the file has ${lineCount} lines`,
		);
	}

	return {
		path: rel,
		start_line: start,
		end_line: end,
		// symbol is agent prose like any other field and gets the same treatment.
		...(loc.symbol ? { symbol: sanitize(ctx, String(loc.symbol)).slice(0, 200) } : {}),
		// An unrecognised role becomes `evidence` rather than an error: it changes
		// identity, so a typo must not quietly create a second finding.
		...(loc.role && (ROLES as readonly string[]).includes(loc.role)
			? { role: loc.role as LocationRole }
			: {}),
	};
}

function outsideRoot(root: string, abs: string): boolean {
	const rel = relative(root, abs);
	return rel.length === 0 || rel.startsWith("..") || isAbsolute(rel);
}

/**
 * Lines in a file, not elements produced by splitting on "\n". A trailing
 * newline yields a final empty element that is not a line — counting it accepts
 * line N+1 on almost every real file, which is the single most likely
 * hallucination this check exists to catch.
 */
function countLines(content: string): number {
	if (content.length === 0) return 0;
	const parts = content.split("\n");
	if (parts.at(-1) === "") parts.pop();
	return parts.length;
}

function normalizeCwe(cwe: string[] | undefined): string[] {
	if (!cwe) return [];
	// No clear class keeps [] — never invent a classification (plan §6.8).
	return cwe
		.map((c) => String(c).trim().toUpperCase())
		.filter((c) => /^CWE-\d+$/.test(c))
		.slice(0, 5);
}

function requireText(v: unknown, field: string): string {
	if (typeof v !== "string" || v.trim().length === 0) {
		throw new Error(`${field} is required`);
	}
	return v;
}

/**
 * probe has no bash but can launder a payload into candidate.summary, which
 * later phases read (plan §5). Strip the run nonce so repo text cannot forge a
 * trust boundary, and strip control characters so findings cannot rewrite a
 * terminal on the way out.
 */
export function sanitize(ctx: Pick<RunContext, "nonce">, text: string): string {
	return redactSecrets(
		stripControlChars(text.replaceAll(ctx.nonce, "[nonce-stripped]")),
	).slice(0, 20000);
}
