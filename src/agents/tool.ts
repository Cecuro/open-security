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

export interface RunContext {
	scanId: string;
	workerId: string;
	repoRoot: string;
	profile: Profile;
	ledger: Ledger;
	nonce: string;
	verbs?: Verb[];
	depth?: number;
	overflowDir?: string;
	resolvableIds?: string[];
	dispositions?: Disposition[];
}

export type Verb =
	| "work.next"
	| "candidate.create"
	| "candidate.validate"
	| "candidate.assess"
	| "lead.record";

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
			Type.Union([Type.Literal("code_evidence"), Type.Literal("repo_claim")]),
		),
	},
	{ additionalProperties: false },
);

const paramsSchema = (verbs: Verb[]) =>
	Type.Object(
	{
		verb: Type.Union(verbs.map((v) => Type.Literal(v))),

		limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 200 })),
		cursor: Type.Optional(Type.Integer({ minimum: 0 })),

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

		text: Type.Optional(Type.String()),
		status: Type.Optional(
			Type.Union([Type.Literal("open"), Type.Literal("dead_end")]),
		),
	},
	{ additionalProperties: false },
);

const ALL_VERBS: Verb[] = [
	"work.next",
	"candidate.create",
	"candidate.validate",
	"candidate.assess",
	"lead.record",
];

// The tool describes only the verbs this worker may call. A description that
// advertises a verb the worker cannot use is an instruction to make an error.
const VERB_DOC: Record<Verb, string> = {
	"work.next":
		"- work.next({ limit, cursor }) — the files you are accountable for, and the total.",
	"candidate.create":
		"- candidate.create({ title, cwe, locations, summary, evidence, instance }) — a\n" +
		"  suspected flaw. locations must cite real line ranges in files inside the repo.",
	"candidate.validate":
		"- candidate.validate({ id, disposition, rationale }) — is it real? No severity here.",
	"candidate.assess":
		"- candidate.assess({ id, entry_point, path, controls, impact, ... }) — how far it\n" +
		"  reaches, plus the observable inputs severity is computed from. You do not set\n" +
		"  severity.",
	"lead.record":
		"- lead.record({ text, status }) — a hypothesis you chased. Record dead ends too.",
};

export function createOpensecTool(ctx: RunContext) {
	const verbs = ctx.verbs ?? ALL_VERBS;
	const guidelines = [
		...(verbs.includes("work.next")
			? ["Call opensec work.next before reviewing anything — it is the list you are accountable for."]
			: []),
		...(verbs.includes("lead.record")
			? ["Record dead ends with lead.record. Silence is indistinguishable from never having looked."]
			: []),
	];
	return defineTool({
		name: "opensec",
		label: "opensec",
		description: [
			`Record security review work. ${verbs.length === 1 ? "One verb" : `${verbs.length} verbs`}:`,
			"",
			...verbs.map((v) => VERB_DOC[v]),
		].join("\n"),
		parameters: paramsSchema(verbs),
		promptSnippet: "opensec - record worklist progress, candidates, verdicts and leads",
		...(guidelines.length > 0 ? { promptGuidelines: guidelines } : {}),
		// Two calls in one tool batch must not interleave a create and a validate.
		executionMode: "sequential",
		async execute(_id, params) {
			const output = run(ctx, params as Params);
			return { content: [{ type: "text", text: output }], details: undefined };
		},
	});
}

type Params = {
	verb: Verb;
	[k: string]: unknown;
};

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
	const { files, total } = ctx.ledger.listWork(ctx.scanId, limit, cursor);
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

	if (!locations.some((l) => ctx.ledger.fileInScope(ctx.scanId, l.path))) {
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
		// Capped like instance and symbol: a title is one line of a findings table.
		title: sanitize(ctx, title).slice(0, 200),
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

function candidateValidate(ctx: RunContext, p: Params): string {
	const { candidate, id } = requireCandidate(ctx, p);
	const rationale = sanitize(ctx, requireText(p.rationale, "rationale"));

	const disposition = (p.disposition as Disposition | undefined) ?? "needs_follow_up";

	if (ctx.dispositions && !ctx.dispositions.includes(disposition)) {
		throw new Error(
			`${ctx.workerId} may only set disposition: ${ctx.dispositions.join(", ")}. ` +
				`Got '${disposition}'.`,
		);
	}

	if (disposition === "duplicate") {
		// Every failure below throws and records nothing. Writing anything here
		// would give the candidate a validation record it never earned, and the
		// validate pass skips rows that already have one.
		const dup = typeof p.duplicate_of === "string" ? p.duplicate_of : "";
		if (!dup || dup === id) {
			throw new Error(
				`duplicate_of must name another candidate — got '${dup}'. Nothing was recorded.`,
			);
		}
		if (ctx.resolvableIds && !ctx.resolvableIds.includes(dup)) {
			throw new Error(
				`duplicate_of '${dup}' is not in your group. You were asked about: ` +
					`${ctx.resolvableIds.join(", ")}. Nothing was recorded.`,
			);
		}
		const target = ctx.ledger.getCandidate(ctx.scanId, dup);
		if (!target) {
			throw new Error(`no candidate '${dup}' in this scan. Nothing was recorded.`);
		}
		if (target.merged_into) {
			throw new Error(
				`duplicate_of '${dup}' is itself merged into '${target.merged_into}' — point ` +
					`every duplicate at the surviving row. Nothing was recorded.`,
			);
		}
		ctx.ledger.resolveCandidate(ctx.scanId, id, {
			disposition: "duplicate",
			rationale,
			duplicate_of: dup,
			validation: { disposition: "duplicate", rationale, at: now() },
		});
		return JSON.stringify({ id, disposition: "duplicate", duplicate_of: dup });
	}

	const resolution: Resolution = {
		...candidate.resolution,
		disposition,
		rationale,
		validation: { disposition, rationale, at: now() },
	};
	ctx.ledger.resolveCandidate(ctx.scanId, id, resolution);

	return JSON.stringify({
		id,
		disposition,
		next:
			disposition === "confirmed"
				? "a separate attack-path pass will rate this. You do not assess it."
				: undefined,
	});
}

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
		// candidate.resolution exists here — the confirmed-validation check above
		// already threw otherwise.
		const resolution: Resolution = {
			...candidate.resolution,
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
		...candidate.resolution,
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
	const status = (p.status as "open" | "dead_end" | undefined) ?? "open";
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

	const raw = p.suppression as SeverityInputs["suppression"];
	const suppression = raw?.evidence ? { ...raw, evidence: sanitize(ctx, raw.evidence) } : raw;

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

function validateLocation(ctx: RunContext, loc: Location): Location {
	if (typeof loc?.path !== "string" || loc.path.length === 0) {
		throw new Error("location.path is required");
	}
	if (isAbsolute(loc.path)) {
		throw new Error(`location.path must be repo-relative, got '${loc.path}'`);
	}

	const root = realpathSync(ctx.repoRoot);
	const abs = resolve(root, loc.path);

	if (outsideRoot(root, abs)) {
		throw new Error(`location '${loc.path}' resolves outside the repo`);
	}

	let leaf: ReturnType<typeof lstatSync>;
	try {
		leaf = lstatSync(abs);
	} catch {
		throw new Error(`no such file: ${loc.path}`);
	}
	if (leaf.isSymbolicLink()) throw new Error(`location '${loc.path}' is a symlink`);
	if (!leaf.isFile()) throw new Error(`location '${loc.path}' is not a regular file`);

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
		...(loc.symbol ? { symbol: sanitize(ctx, String(loc.symbol)).slice(0, 200) } : {}),
		...(loc.role && (ROLES as readonly string[]).includes(loc.role)
			? { role: loc.role as LocationRole }
			: {}),
	};
}

function outsideRoot(root: string, abs: string): boolean {
	const rel = relative(root, abs);
	return rel.length === 0 || rel.startsWith("..") || isAbsolute(rel);
}

function countLines(content: string): number {
	if (content.length === 0) return 0;
	const parts = content.split("\n");
	if (parts.at(-1) === "") parts.pop();
	return parts.length;
}

function normalizeCwe(cwe: string[] | undefined): string[] {
	if (!cwe) return [];
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

export function sanitize(
	ctx: Pick<RunContext, "nonce">,
	text: string,
	limit = 20000,
): string {
	return redactSecrets(
		stripControlChars(text.replaceAll(ctx.nonce, "[nonce-stripped]")),
	).slice(0, limit);
}
