import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { isAbsolute, relative, resolve } from "node:path";

import type { CandidateActivityWrite, Ledger } from "../db/db.js";
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
	/** The files this worker owns. Undefined means the whole repository. */
	worklist?: readonly string[];
	/** Which pass this worker belongs to. Reads are counted per group. */
	readGroup?: string;
	resolvableIds?: string[];
	dispositions?: Disposition[];
}

export type Verb =
	| "work.next"
	| "work.complete"
	| "candidate.create"
	| "candidate.validate"
	| "candidate.assess";

// The threat model is a map, not a findings list — its prompt says so, so the
// tool must not advertise candidate.create to it. Without this it fell through
// to ALL_VERBS and offered three verbs the phase has no use for.
export const THREAT_MODEL_VERBS: Verb[] = ["work.next"];
export const PROBE_VERBS: Verb[] = ["work.next", "work.complete", "candidate.create"];
export const VALIDATE_VERBS: Verb[] = ["work.next", "candidate.validate"];
export const ASSESS_VERBS: Verb[] = ["work.next", "candidate.assess"];
export const REDUCE_VERBS: Verb[] = ["candidate.validate"];
export const SUBAGENT_VERBS: Verb[] = ["work.next"];

const ROLES = ["entrypoint", "source", "root_control", "sink", "evidence"] as const;

const ALL_VERBS: Verb[] = [
	"work.next",
	"work.complete",
	"candidate.create",
	"candidate.validate",
	"candidate.assess",
];

type Params = {
	verb: Verb;
	[k: string]: unknown;
};

/** Execute one command received from the sandbox CLI bridge. */
export function runOpensec(ctx: RunContext, p: Params): string {
	assertCommandAllowed(ctx, p);
	switch (p.verb) {
		case "work.next":
			return workNext(ctx, p);
		case "work.complete":
			return workComplete(ctx, p);
		case "candidate.create":
			return candidateCreate(ctx, p);
		case "candidate.validate":
			return candidateValidate(ctx, p);
		case "candidate.assess":
			return candidateAssess(ctx, p);
		default:
			throw new Error(`unknown verb: ${String(p.verb)}`);
	}
}

/** Validate every item before atomically recording a candidate-validation batch. */
export function runOpensecBatch(ctx: RunContext, verb: Verb, values: readonly unknown[]): string {
	if (verb !== "candidate.validate") throw new Error(`${verb} does not accept an input array`);
	if (values.length === 0) throw new Error("candidate.validate input array must not be empty");
	if (values.length > 50) throw new Error("candidate.validate accepts at most 50 items per batch");

	const seen = new Set<string>();
	const plans = values.map((value, index) => {
		if (typeof value !== "object" || value === null || Array.isArray(value)) {
			throw new Error(`candidate.validate input[${index}] must be a JSON object`);
		}
		try {
			const p = { ...(value as Record<string, unknown>), verb } as Params;
			assertCommandAllowed(ctx, p);
			const plan = prepareCandidateValidation(ctx, p);
			if (seen.has(plan.id)) throw new Error(`repeats '${plan.id}'`);
			seen.add(plan.id);
			return plan;
		} catch (err) {
			throw new Error(`candidate.validate input[${index}]: ${(err as Error).message}`);
		}
	});

	const merged = new Set(plans.filter((plan) => plan.duplicateOf).map((plan) => plan.id));
	for (const plan of plans) {
		if (plan.duplicateOf && merged.has(plan.duplicateOf)) {
			throw new Error(
				`duplicate_of '${plan.duplicateOf}' is also merged in this batch — point every duplicate at the surviving row`,
			);
		}
	}
	ctx.ledger.addCandidateActivities(plans.map((plan) => plan.activity));
	return JSON.stringify(plans.map((plan) => plan.output));
}

function assertCommandAllowed(ctx: RunContext, p: Params): void {
	validateCommandFields(p);
	const allowed = ctx.verbs ?? ALL_VERBS;
	if (!allowed.includes(p.verb)) {
		throw new Error(
			`'${p.verb}' is not available to ${ctx.workerId}. You may call: ${allowed.join(", ")}. ` +
			`Report what you found in your final message instead — whoever delegated to you records it.`,
		);
	}
}

const FIELDS_BY_VERB: Record<Verb, readonly string[]> = {
	"work.next": ["limit"],
	"work.complete": ["summary"],
	"candidate.create": ["title", "cwe", "locations", "description", "instance"],
	"candidate.validate": ["id", "disposition", "rationale", "duplicate_of"],
	"candidate.assess": [
		"id",
		"entry_point",
		"path",
		"controls",
		"rationale",
		"impact",
		"vector",
		"auth_required",
		"network_reachable",
		"cross_tenant",
		"code_execution_proven",
		"traced_path_no_control",
		"method",
		"suppression",
	],
};

/** The bridge shares this check with the PI tool so misspelled JSON never becomes a silent no-op. */
function validateCommandFields(p: Params): void {
	const fields = FIELDS_BY_VERB[p.verb];
	if (!fields) return;
	const unknown = Object.keys(p).filter((key) => key !== "verb" && !fields.includes(key));
	if (unknown.length > 0) throw new Error(`${p.verb} does not accept: ${unknown.join(", ")}`);
}

const WORK_BATCH_MAX = 50;

function workNext(ctx: RunContext, p: Params): string {
	// Capped: a batch large enough to page the whole repository in three calls is
	// a batch nobody reads. The cap is what makes `remaining` mean anything.
	const asked = (p.limit as number | undefined) ?? 25;
	const limit = Math.min(Math.max(1, asked), WORK_BATCH_MAX);
	const capped = asked > WORK_BATCH_MAX;
	const { files, unread } = ctx.ledger.listWork(ctx.scanId, limit, ctx.worklist, ctx.readGroup);
	// A partially-read file says so, with what is left. pi truncates a read at
	// 50KB, so on a large file the agent has to come back with an offset, and it
	// can only know that if the worklist tells it.
	const lines = files.map((f) =>
		f.bytes_read > 0
			? `${f.path} (${f.bytes_total} bytes, ${f.bytes_read} read — continue with an offset)`
			: `${f.path} (${f.bytes_total} bytes)`,
	);
	return JSON.stringify(
		{
			files: lines,
			returned: files.length,
			remaining: Math.max(0, unread - files.length),
			// A silent cap is the tool lying about what it did. Say it, so an agent
			// that asked for 200 knows why it got 50 and does not read a short batch
			// as a nearly-empty worklist.
			...(capped ? { asked, capped_to: WORK_BATCH_MAX } : {}),
			// "no files but work remaining" is not a state the worklist can be in.
			// Saying so is cheaper than a probe quietly concluding it is done.
			note:
				files.length > 0
					? `these are unread. read them, then call work.next for the next batch` +
						(capped ? ` (batches are capped at ${WORK_BATCH_MAX})` : "")
					: unread === 0
						? "end of worklist"
						: `worklist bug: ${unread} unread but none returned — report this rather than stopping`,
		},
		null,
		1,
	);
}

function workComplete(ctx: RunContext, p: Params): string {
	const summary = sanitize(ctx, requireText(p.summary, "summary")).slice(0, 2000);
	ctx.ledger.completeWorkerWork(ctx.scanId, ctx.worklist ?? [], ctx.readGroup);
	ctx.ledger.recordEvent(
		ctx.scanId,
		"work_complete",
		{ summary, read_group: ctx.readGroup ?? null },
		ctx.workerId,
	);
	return JSON.stringify({ status: "complete", note: "worklist read" });
}

function candidateCreate(ctx: RunContext, p: Params): string {
	const title = requireText(p.title, "title");
	const description = requireText(p.description, "description");
	const rawLocations = p.locations;
	if (!Array.isArray(rawLocations) || rawLocations.length === 0) {
		throw new Error("candidate.create requires at least one location");
	}

	const locations = rawLocations.map((l) => validateLocation(ctx, l as Location));

	// What ties a finding to you has to be the finding, not a mention of it.
	//
	// A probe once cited README.md:30 as `evidence`, with the entrypoint, the
	// broken control and the sink all in files the user had excluded, and filed
	// four findings about code nobody asked it to review. Evidence is supporting
	// material by definition; the finding *is* its entrypoint, control and sink.
	// So when roles are given, one of those has to be in scope. When none are
	// given there is nothing to discriminate on, and any location will do.
	const substantive = locations.filter((l) => l.role !== undefined && l.role !== "evidence");
	const anchors = substantive.length > 0 ? substantive : locations;
	if (!anchors.some((l) => ctx.ledger.fileInScope(ctx.scanId, l.path, ctx.worklist))) {
		throw new Error(
			(substantive.length > 0
				? `no entrypoint, source, root_control or sink is in your worklist — an evidence ` +
					`location does not tie a finding to you. Cite a file from work.next, or include ` +
						`the issue in your completion summary. `
				: `no location is in your worklist — cite at least one file from work.next, or ` +
						`include the issue in your completion summary. `) +
				`Got: ${anchors.map((l) => `${l.path}${l.role ? ` (${l.role})` : ""}`).join(", ")}`,
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
		cweIds: normalizeCwe(p.cwe),
		locations,
		description: sanitize(ctx, description),
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
	const plan = prepareCandidateValidation(ctx, p);
	ctx.ledger.addCandidateActivity(plan.activity);
	return JSON.stringify(plan.output);
}

type CandidateValidationPlan = {
	id: string;
	duplicateOf?: string;
	activity: CandidateActivityWrite;
	output: Record<string, unknown>;
};

function prepareCandidateValidation(ctx: RunContext, p: Params): CandidateValidationPlan {
	const { id } = requireCandidate(ctx, p);
	const rationale = sanitize(ctx, requireText(p.rationale, "rationale"));

	const disposition =
		enumValue<Disposition>(p.disposition, "disposition", [
			"confirmed",
			"not_applicable",
			"duplicate",
			"needs_follow_up",
		]) ?? "needs_follow_up";

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
		if (target.duplicate_of) {
			throw new Error(
				`duplicate_of '${dup}' is itself merged into '${target.duplicate_of}' — point ` +
					`every duplicate at the surviving row. Nothing was recorded.`,
			);
		}
		return {
			id,
			duplicateOf: dup,
			activity: {
				scanId: ctx.scanId,
				candidateId: id,
				workerId: ctx.workerId,
				kind: "duplicate",
				body: rationale,
				status: "duplicate",
				duplicateOf: dup,
				data: { disposition: "duplicate", duplicate_of: dup },
			},
			output: { id, disposition: "duplicate", duplicate_of: dup },
		};
	}

	return {
		id,
		activity: {
			scanId: ctx.scanId,
			candidateId: id,
			workerId: ctx.workerId,
			kind: "validation",
			body: rationale,
			status: disposition,
			data: { disposition },
		},
		output: {
			id,
			disposition,
			next:
				disposition === "confirmed"
					? "a separate assessment pass will rate this. You do not assess it."
					: undefined,
		},
	};
}

function candidateAssess(ctx: RunContext, p: Params): string {
	const { candidate, id } = requireCandidate(ctx, p);

	const validated = candidate.activities.findLast((activity) => activity.kind === "validation")?.data?.disposition;
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
		ctx.ledger.addCandidateActivity({
			scanId: ctx.scanId,
			candidateId: id,
			workerId: ctx.workerId,
			kind: "assessment",
			body: rationale,
			status: "needs_follow_up",
			data: { disposition: "needs_follow_up", reachability },
		});
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

	const computed = computeSeverity(inputs);
	const disposition = computed.reportable ? "confirmed" : "suppressed";
	ctx.ledger.addCandidateActivity({
		scanId: ctx.scanId,
		candidateId: id,
		workerId: ctx.workerId,
		kind: "assessment",
		body: rationale,
		status: disposition,
		data: { disposition, reachability, inputs, computed },
	});

	return JSON.stringify({
		id,
		disposition,
		severity: computed.severity,
		confidence: computed.confidence,
		proof_gap: computed.proof_gap,
		notes,
	});
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
	const list = (v: unknown, name: string): string[] => {
		if (v === undefined) return [];
		if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) {
			throw new Error(`${name} must be an array of strings`);
		}
		return v
			.filter((x): x is string => typeof x === "string" && x.trim().length > 0)
			.map((x) => sanitize(ctx, x).slice(0, 500))
			.slice(0, 40);
	};
	if (p.entry_point !== undefined && typeof p.entry_point !== "string") {
		throw new Error("entry_point must be a string");
	}
	return {
		entry_point:
			typeof p.entry_point === "string" ? sanitize(ctx, p.entry_point).slice(0, 500) : "",
		path: list(p.path, "path"),
		controls: list(p.controls, "controls"),
	};
}

function readSeverityInputs(
	ctx: RunContext,
	p: Params,
	notes: string[],
): SeverityInputs | null {
	const impact = enumValue<Impact>(p.impact, "impact", ["none", "low", "medium", "high"]);
	const vector = enumValue<Vector>(p.vector, "vector", [
		"remote",
		"local_network",
		"localhost",
		"none",
		"unknown",
	]);
	const method = enumValue<Method>(p.method, "method", [
		"reproduced_poc",
		"asan",
		"debugger",
		"code_reading",
		"counterevidence",
	]);
	if (!impact || !method) return null;
	if (!vector) notes.push("no vector given; treated as unknown, which caps likelihood at low");

	const authRequired = enumValue<AuthRequired>(p.auth_required, "auth_required", [
		"none",
		"user",
		"admin",
	]);
	const suppression = readSuppression(ctx, p.suppression);

	return {
		impact,
		vector: vector ?? "unknown",
		auth_required: authRequired ?? "user",
		network_reachable: booleanValue(p.network_reachable, "network_reachable"),
		cross_tenant: booleanValue(p.cross_tenant, "cross_tenant"),
		code_execution_proven: booleanValue(p.code_execution_proven, "code_execution_proven"),
		traced_path_no_control: booleanValue(p.traced_path_no_control, "traced_path_no_control"),
		method,
		suppression,
	};
}

function enumValue<T extends string>(
	value: unknown,
	name: string,
	allowed: readonly T[],
): T | undefined {
	if (value === undefined) return undefined;
	if (typeof value !== "string" || !allowed.includes(value as T)) {
		throw new Error(`${name} must be one of: ${allowed.join(", ")}`);
	}
	return value as T;
}

function booleanValue(value: unknown, name: string): boolean {
	if (value === undefined) return false;
	if (typeof value !== "boolean") throw new Error(`${name} must be a boolean`);
	return value;
}

function readSuppression(ctx: RunContext, value: unknown): SeverityInputs["suppression"] {
	if (value === undefined) return undefined;
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		throw new Error("suppression must be an object");
	}
	const raw = value as Record<string, unknown>;
	const allowed = [
		"self_only",
		"requires_preexisting_privilege",
		"privilege_delta_is_the_bug",
		"precondition_unreachable",
		"evidence",
		"source",
	];
	const unknown = Object.keys(raw).filter((key) => !allowed.includes(key));
	if (unknown.length > 0) throw new Error(`suppression does not accept: ${unknown.join(", ")}`);
	const evidence = raw.evidence;
	if (evidence !== undefined && typeof evidence !== "string") {
		throw new Error("suppression.evidence must be a string");
	}
	return {
		self_only: booleanValue(raw.self_only, "suppression.self_only"),
		requires_preexisting_privilege: booleanValue(
			raw.requires_preexisting_privilege,
			"suppression.requires_preexisting_privilege",
		),
		privilege_delta_is_the_bug: booleanValue(
			raw.privilege_delta_is_the_bug,
			"suppression.privilege_delta_is_the_bug",
		),
		precondition_unreachable: booleanValue(
			raw.precondition_unreachable,
			"suppression.precondition_unreachable",
		),
		...(evidence === undefined ? {} : { evidence: sanitize(ctx, evidence) }),
		source: enumValue(raw.source, "suppression.source", ["code_evidence", "repo_claim"]),
	};
}

function validateLocation(ctx: RunContext, loc: Location): Location {
	if (!loc || typeof loc !== "object" || Array.isArray(loc)) {
		throw new Error("each location must be an object");
	}
	const raw = loc as unknown as Record<string, unknown>;
	const allowed = ["path", "start_line", "end_line", "symbol", "role"];
	const unknown = Object.keys(raw).filter((key) => !allowed.includes(key));
	if (unknown.length > 0) throw new Error(`location does not accept: ${unknown.join(", ")}`);
	if (typeof loc?.path !== "string" || loc.path.length === 0) {
		throw new Error("location.path is required");
	}
	if (typeof loc.start_line !== "number") throw new Error("location.start_line must be an integer");
	if (loc.end_line !== undefined && typeof loc.end_line !== "number") {
		throw new Error("location.end_line must be an integer");
	}
	if (loc.symbol !== undefined && typeof loc.symbol !== "string") {
		throw new Error("location.symbol must be a string");
	}
	if (
		loc.role !== undefined &&
		(typeof loc.role !== "string" || !(ROLES as readonly string[]).includes(loc.role))
	) {
		throw new Error(`location.role must be one of: ${ROLES.join(", ")}`);
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
		...(loc.symbol ? { symbol: sanitize(ctx, loc.symbol).slice(0, 200) } : {}),
		...(loc.role ? { role: loc.role as LocationRole } : {}),
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

function normalizeCwe(cwe: unknown): string[] {
	if (cwe === undefined) return [];
	if (!Array.isArray(cwe) || cwe.some((value) => typeof value !== "string")) {
		throw new Error("cwe must be an array of strings");
	}
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
