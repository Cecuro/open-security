# Security scan: security-tool-implementation-b7e028

| | |
|---|---|
| repository | `/Users/gustavhartz/Projects/open-security/.claude/worktrees/security-tool-implementation-b7e028` |
| revision | `fa353b27e5ee12349c5367157cc5396fbcf43948` |
| profile | **static** — nothing was executed |
| model | `azure-openai-responses/gpt-5.6-luna` |
| prompts | `70f8685e384e1d3c` |
| started | 2026-08-06T17:01:40.564Z |
| tokens | 3,181,046 in / 44,974 out |
| cost | $0.2196 |

## Coverage

- **41 / 41 files touched** (100%)
- **224.6 KB / 224.6 KB read** (100%) — the number to trust
- 21597 files excluded from scope with a recorded reason
- ownership: 5 partition(s), 9/9/9/9/5 files (min 5, max 9)

> Coverage is derived from the read and grep calls that actually happened, not
> from anything the agents claimed. It is a **laziness detector, not proof of
> review**: a file that was read is not thereby a file that was understood.

Extensions in scope: `.js`, `.json`, `.md`, `.mjs`, `.sql`, `.ts`.

## Findings

| # | severity | confidence | finding | location |
|---|---|---|---|---|
| c2 | critical (unproven) | 0.3 | Partitioned discovery workers can overwrite other workers' candidates | `src/agents/tool.ts:232` |
| c1 | low | 0.3 | Repository file tools follow symlinks outside scan root | `src/agents/session.ts:234` |
| c3 | low | 0.3 | Duplicate resolution can hide a finding by targeting an unresolved candidate | `src/agents/tool.ts:255` |

### c2 — Partitioned discovery workers can overwrite other workers' candidates

**critical (unproven)** · confidence 0.3 · CWE-862

> `proof_gap: no_execution` — this severity is asserted from code, not demonstrated.

**Locations**

- `src/agents/tool.ts:232-247` — `candidateResolve`
- `src/agents/tool.ts:284-297` — `candidateCreate`

**What an attacker gets**

A repository-controlled prompt injection can make a discovery probe call candidate.resolve for a guessed candidate ID belonging to another probe, changing its disposition or merging it, because resolution checks only scan-wide existence and does not enforce worker/partition ownership. This can suppress or alter another worker's finding in the final report.

**Evidence**

> `run` grants every phase worker PHASE_VERBS, including candidate.resolve (src/agents/tool.ts:227-245). `candidateResolve` loads only by scan ID and candidate ID (`src/agents/tool.ts:243-244`) and immediately accepts the resolution; unlike candidateCreate's explicit partition-scoped fileInScope check (`src/agents/tool.ts:284-297`), it has no worker or partition authorization. Discovery contexts are partitioned but created with the default phase verbs (`src/sdk/scanner.ts:258-266`), so a malicious repository instruction processed by one probe can target another probe's c1/c2 row.

**Investigation**

Confirmed after tracing the complete cross-partition path. Discovery creates each probe context with its partitionId but leaves verbs at PHASE_VERBS, which includes candidate.resolve (src/sdk/scanner.ts:262-265; src/agents/tool.ts:64-69). A probe can submit a guessed existing ID; candidateResolve only calls getCandidate(scanId, id) and has no worker/partition ownership check (src/agents/tool.ts:306-309), then writes the resolution through resolveCandidate, whose UPDATE is scoped only by scan_id and id (src/agents/tool.ts:366; src/db/db.ts:321-328). For duplicate, the same unscoped lookup permits selecting another candidate, and the DB sets merged_into on the source (src/agents/tool.ts:317-336; src/db/db.ts:324-328). Candidate IDs are predictable count-based c1, c2, etc. (src/db/db.ts:270-276). Creation is partition-checked, but that control does not apply to resolution (src/agents/tool.ts:284-297). Discovery returns all candidates and later report rendering excludes every merged row from live findings (src/sdk/scanner.ts:284-286; src/scan/render.ts:21-27), so a repository prompt injection that induces a probe call can alter or remove another probe's candidate from the live report. The probe prompt's own-worklist instruction is guidance, not an enforcement control. No execution is claimed.

**Severity inputs**

`impact=medium` `vector=remote` `auth_required=none` `network_reachable=true` `cross_tenant=true` `traced_path_no_control=true` `code_execution_proven=false` `method=code_reading`

- likelihood high from vector=remote, auth_required=none
- matrix: impact=medium × likelihood=high → high
- critical (unproven): unauthenticated, network-reachable, cross-tenant, but nothing was executed

### c1 — Repository file tools follow symlinks outside scan root

**low** · confidence 0.3 · CWE-59

**Locations**

- `src/agents/session.ts:234-253` — `confine / withinRepo`
- `src/agents/session.ts:156-160` — `AgentRunner.run`

**What an attacker gets**

A scanned repository can contain a symlinked directory or file pointing outside the repository; the model's read, grep, find, or ls request passes the lexical containment check and the underlying tool follows the link, exposing arbitrary local files to the model/provider.

**Evidence**

> AgentRunner installs all repository file tools through confine at session.ts:156-160. confine only extracts params.path and rejects paths failing withinRepo at session.ts:238-243. withinRepo resolves the user-supplied path lexically and checks only that lexical result is under resolve(root) at session.ts:251-253; it does not lstat/realpath the path or reject symlink components before calling inner at session.ts:244-248. Thus a repository path such as link/secret (where link points outside repo) is lexically in-root but is handed to the dependency tool, whose file operation can follow the symlink. The repository's separate candidate validator explicitly recognizes this distinction and performs realpath containment, but that control is not on these file-tool reads.

**Investigation**

The actual call path completes. AgentRunner registers read, grep, find, and ls through confine at src/agents/session.ts:156-160. confine extracts the model-supplied params.path and calls withinRepo before invoking the underlying tool at lines 238-248. withinRepo uses path.resolve/relative only at lines 251-253; it does not lstat, realpath, or reject symlink components. A repository entry such as link/secret, with link pointing outside the repository, therefore passes lexical containment. The dependency read tool resolves the path relative to the repository root and then calls filesystem access/readFile without canonicalizing the target; intermediate symlinks are followed. The same underlying filesystem behavior applies to the wrapped grep/find/ls operations. Instrumentation occurs after successful execution and only records the lexical requested path, so it does not stop or detect the read. The separate finding-location validator's realpath checks are not on this tool execution path. No caller control establishes that repository trees cannot contain such symlinks.

**Severity inputs**

`impact=medium` `vector=localhost` `auth_required=none` `network_reachable=false` `cross_tenant=true` `traced_path_no_control=true` `code_execution_proven=false` `method=code_reading`

- likelihood low from vector=localhost, auth_required=none
- matrix: impact=medium × likelihood=low → low

### c3 — Duplicate resolution can hide a finding by targeting an unresolved candidate

**low** · confidence 0.3 · CWE-20

**Locations**

- `src/agents/tool.ts:255-279` — `candidateResolve`
- `src/scan/render.ts:24-28` — `renderMarkdown`

**What an attacker gets**

A model-controlled candidate.resolve can mark any existing candidate as a duplicate of an unresolved or non-reportable row. Rendering removes every row with merged_into before producing findings, so the confirmed source can disappear from the report even though its duplicate target is never a surviving finding.

**Evidence**

> For disposition duplicate, `candidateResolve` accepts any existing target that is not itself merged (`src/agents/tool.ts:255-270`); it does not require the target to be confirmed/reportable. It then stores duplicate and sets merged_into (`src/agents/tool.ts:271-278`, with the DB update in src/db/db.ts:324-331). `renderMarkdown` builds `merged` from all candidates with merged_into and filters them out (`src/scan/render.ts:24-28`), so pointing at an unresolved target removes the source from all report sections while the target remains only in follow-up.

**Investigation**

Confirmed by static end-to-end trace, with a qualification to the filing: the source is removed from the principal Findings section and its detailed finding/severity, but it is still listed in the separate Merged as duplicates audit section and retained in findings.json. In candidateResolve, duplicate_of is looked up across all candidates and accepted when the target exists and is not merged; there is no requirement that the target be confirmed or reportable (src/agents/tool.ts:318-340). The dedup caller supplies only confirmed, unmerged rows (src/sdk/scanner.ts:370-378), but the write-side lookup is not restricted to that set, so this caller-side filtering does not stop a model from naming an existing unresolved candidate. The database records merged_into on the source (src/db/db.ts:321-328). Rendering then constructs the merged-ID set and excludes every merged source from live candidates and confirmed findings (src/scan/render.ts:31-41); an unresolved target is categorized in follow-up (src/scan/render.ts:43-46). The only target control rejects missing/self targets or already-merged targets, not unresolved targets (src/agents/tool.ts:320-333). Thus a confirmed source can be omitted from the normal findings report and CLI confirmed count while the unresolved target remains follow-up. The existing mutual-merge protection does not address this target-state mismatch.

**Severity inputs**

`impact=medium` `vector=unknown` `auth_required=none` `network_reachable=false` `cross_tenant=false` `traced_path_no_control=true` `code_execution_proven=false` `method=code_reading`

- likelihood low from vector=unknown, auth_required=none
- matrix: impact=medium × likelihood=low → low

## Suppressed

- **c6** Concurrent agents can collectively bypass the configured spend ceiling — suppressed before the matrix: self_only

## Not applicable

- **c5** Discovery probes can pre-resolve candidates and bypass investigation — The discovery permission issue is real in isolation: discover() gives probes a context with no verbs override (src/sdk/scanner.ts:263-264), createOpensecTool/run defaults that to PHASE_VERBS (src/agents/tool.ts:227-240), and candidateResolve plus Ledger.resolveCandidate do not enforce phase, ownership, or unresolved state (src/agents/tool.ts:306-374; src/db/db.ts:321-328). However, the claimed investigation bypass does not hold on the normal execution path. discover() returns ledger.listCandidates(), including already-resolved rows (src/sdk/scanner.ts:285-286), and Scanner.run() passes that explicit array to investigate() (src/sdk/scanner.ts:443-448). investigate() therefore does not use its unresolved-only fallback; it schedules every returned candidate (src/sdk/scanner.ts:292-310), including a probe-resolved one, and the investigator is instructed to resolve it. Any confirmed/suppressed resolution written through the tool still passes readSeverityInputs and computeSeverity, with non-reportable results downgraded (src/agents/tool.ts:345-363). Directly calling investigate() without arguments can skip pre-resolved rows, but that is a distinct caller/API usage and does not establish the filed discovery-to-normal-run bypass.

## Merged as duplicates

- **c4** Repository symlinks let agent file tools read outside the scan root → merged into **c1**: Both findings describe the same missing symlink-aware repository confinement in the wrapped read/grep/find/ls tools: one patch to make withinRepo resolve and validate the real path (or otherwise enforce realpath containment) fixes the disclosure path described by both rows. c1 retains the more precise primary location in confine and the tool wiring.

## Leads that went nowhere

"No findings" from an agent that never looked is indistinguishable from "no
findings" from an agent that looked hard — unless the dead ends are written
down. These are they.

- Reviewed README.md and package.json for exposed credentials, unsafe install/runtime claims, and dependency configuration; no hardcoded secret, shell/SQL sink, or actionable package-level security flaw found. The documented container profile is explicitly marked not implemented and rejected by Scanner.open.
- Reviewed prompts/agents/skeptic.md and delegation path; delegated tasks are nonce-wrapped and subagents have read-only verbs with no finding-write capability, so no independent authorization bypass was identified.
- Reviewed docs/plan.md and docs/example-report.md for runnable examples or unsafe guidance; plan clearly labels container/MCP/serve features as future milestones, and the example report is static documentation rather than executable behavior.
- Reviewed LICENSE, NOTICE, .gitignore, and .git metadata; these contain licensing, attribution, ignore patterns, or worktree metadata only, with no secrets or executable security behavior.
- Checked the README claim that estimate spends/writes nothing against CLI and Scanner.estimate path; estimate returns before Scanner.open/ledger creation, while inventory is read-only, so no write or model call occurs.
- Checked prompt-pack loading as a potential prompt-injection boundary; --prompts and ~/.opensec/prompts are explicit operator-controlled configuration, and the reviewed skeptic task is wrapped as untrusted evidence, so no attacker-controlled repository path is used for prompt lookup.
- Reviewed session initialization and resource loading: the agent runs in ~/.opensec/agent with in-memory untrusted settings, disabled context files/extensions/skills/templates/themes, and an explicit empty appendSystemPrompt, so repository .pi configuration and APPEND_SYSTEM.md do not enter the agent setup.
- Reviewed subagent delegation: depth, concurrency, per-parent count, shared budget billing, and SUBAGENT_VERBS prevent recursive/fan-out abuse and child finding writes; delegated task text is nonce-wrapped before the child prompt.
- Reviewed prompt assets and copy-assets script: these are static prompt/schema packaging inputs with no shell interpolation or runtime repository path construction; caller-selected prompt trust is explicit configuration rather than an independently exploitable ingress in these files.
- Reviewed severity computation and tool schema: severity inputs are enum-validated before computeSeverity, and static-profile execution claims are downgraded rather than trusted.
- Reviewed text redaction and Markdown-related types/tests; control characters, nonces, and recognized secret formats are sanitized, while the intentionally vulnerable fixture code is test data rather than scanner behavior.
- Reviewed Scanner lifecycle, artifact paths, git invocation, partition tests, and ledger regressions; generated scan IDs and argument-array subprocess calls prevent an obvious path or shell injection in these files.
- Checked SQL construction and dynamic partition clauses in db.ts; all ordinary values are bound and the only SQL fragments come from internal partition scope, so no attacker-controlled SQL injection was found.
- Checked Markdown and terminal output paths; candidate prose is control-stripped and escaped for tables, headings, links/images, and block evidence, so no report rendering injection was found.
- Checked candidate location containment and line validation; absolute paths, lexical escapes, symlink leaves/directories, non-files, and invalid ranges are rejected before ledger insertion.
- Checked prompt loading and inventory subprocess argument construction; prompt names are fixed and rg/git use argument arrays rather than shell interpolation, so no direct path or shell injection was found in these files.
- Reviewed test/pipeline.test.ts, including end-to-end inventory, candidate creation, resolution, and Markdown rendering; it uses temporary fixtures and exercises the production controls without introducing an attacker-controlled sink or authorization bypass.
- Reviewed test/severity.test.ts and the exercised severity implementation; input combinations are bounded by the typed tool schema and the matrix/gates prevent model-supplied severity escalation, with no security flaw in the test code.
- Reviewed test/subagent.test.ts and subagent implementation; tests cover depth, concurrency, budget, verb scoping, and empty results, and the temporary files/ledger do not expose a security issue.
- Reviewed test/tool.test.ts and the exercised tool boundary; path, symlink, line-range, worklist ownership, prose sanitization, and directional degradation cases are covered, with no flaw in this test file.
- Reviewed tsconfig.json; it restricts compilation to src/**/*.ts, excludes tests and build output, and contains no security-relevant compiler configuration weakness.
- Checked subagent budget enforcement: checkBudget runs before each spawn and bill runs after completion, so concurrent calls can observe the same spend; however Scanner documents the ceiling as checked between runs and allowed to overshoot by a run, and this is an operator cost-bound semantics issue rather than access to repository or host assets.
- Reviewed all assigned prompt assets as instructions/data: they contain review workflow and nonce-wrapping guidance, not executable sinks; the prompt-injection boundary remains model-dependent but no separate code-level authorization or filesystem sink was introduced by these files.

---

## How severity was computed

Severity is computed from observable inputs, not chosen by a model. Suppression
is a gate before the matrix, so low impact downgrades but never discards.

| impact | L=high   | L=medium | L=low    |
|--------|----------|----------|----------|
| high   | high     | high     | medium   |
| medium | high     | medium   | low      |
| low    | medium   | low      | low      |
| none   | low      | low      | info     |

Critical is a promotion, not a cell: unauthenticated + network-reachable +
(execution proven | cross-tenant | traced path with no intervening control).

Confidence is bound to method: reproduced PoC 1.0, ASan 0.9, debugger 0.8,
code understanding alone 0.3, counterevidence 0.0.

This scan ran under the **static** profile. Nothing was executed, so no finding
here carries execution proof, and any critical is marked `(unproven)`.

