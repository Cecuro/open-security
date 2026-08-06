# opensec — build plan

## Goal

Point it at a repository, get real security findings with file:line, evidence, and a
severity you can defend — **using any model you want, on your own machine.**

openai/codex-security proved the method works: threat-model first, fan out agents to
find candidates, verify each one, render the report deterministically. But it is
~75k LOC welded to the Codex CLI and desktop app, one model per scan, with some
findings gated behind Trusted Access. We want the same method as a small open CLI on
the [pi](https://pi.dev) harness — Qwen, Kimi, GLM, GPT, Claude, whatever is good
this month, routed per phase — with a local SQLite ledger you own and a UI you can
run yourself.

TypeScript, no Python · SDK is the core · one SQLite DB · Apache-2.0.

Scope of this document: **M0 and M1**.

> **Missing background.** Earlier drafts linked four research documents —
> deferred mechanics, a codex-security teardown, Ozone patterns, and a plan
> review. None of them are in this repository, and the links have been removed
> rather than left dangling. Everything M0 and M1 need is in this file; the
> places that previously deferred detail to "deferred mechanics" now say what is
> actually undecided. M5–M7 will need that thinking redone before they start.

---

## 1. What a scan does

```
opensec scan .

0  inventory     rg --files → filter → import graph
                 partition into size-capped worklists            no LLM
1  threat model  1 agent: entry points, trust boundaries, authn/authz,
                 sensitive assets, external surface              cached per revision
2  discovery     N probes in parallel, each HANDED a worklist,
                 each READING the whole repo → candidates        no bash
3  investigate   1 agent per candidate: build it, run it,
                 try to break it                                 bash, in container
4  report        SQLite → markdown + SARIF + JSON                no LLM
```

`opensec scan . --estimate` says 340 files, ~$1.40, ~12 minutes. You run it. One
agent writes the threat model. Eight probes fan out, each accountable for an explicit
list of files but free to read anything. Each candidate gets an investigate agent
that tries to actually trigger it. What survives gets an impact and a likelihood; the
CLI computes severity.

**The worklist is the load-bearing ergonomic.** codex-security's best mechanic isn't
a clever prompt, it's `list_review_items` — the agent always knows which files it
must account for, pages through them, and reports progress against a fixed
denominator. "Review the repo" produces drift; an assigned list produces completion.

Agents write through **one structured tool**. File lists, partitions, severity
arithmetic and the report are ordinary TypeScript that cannot drift.

---

## 2. Why this instead of codex-security

Same method, and their severity policy, counterevidence checklist and
instance-splitting rules are kept near-verbatim (Apache-2.0, with `NOTICE`).

| | codex-security | opensec |
|---|---|---|
| Agent tool surface | 46 `workbench_cli` subcommands | 5 (4 verbs + delegate) |
| SQLite tables | 19 | 6 |
| Python | 34 scripts, 19k LOC | none |
| Prompt | 4,465 lines | 360 |

Those figures are counted, not recalled — see [comparison](comparison.md), which
also lists what they have and we do not.

- **Any model, per phase**, and nothing gated.
- **Partitioned accountability, not partitioned reading.** Their subagents get
  non-overlapping file partitions, which structurally severs the
  wrapper-in-one-file / missing-check-in-another bug class.
- **Coverage measured from traces**, not agent self-report.
- **Severity computed** from observable inputs, not an enum the model can set to
  `ignore`.
- **The ledger is yours**, and the whole thing is embeddable as an SDK.

Where they're ahead: ~60 bullets of family-specific discovery heuristics we drop are
real signal someone paid for in false positives, their deep mode runs at scale today,
and they have usage data. Our bet — that a shorter general prompt travels better
across models — is unproven until the benchmark, which is designed to falsify it.

---

## 3. Surfaces

The SDK **is** the contract; everything else shapes arguments and formats results.

| Surface | Consumer | Entry |
|---|---|---|
| **SDK** | your scripts, CI glue | `import { Scanner } from "opensec"` |
| **CLI** | humans, CI | `opensec` |
| **MCP** | *your* coding agent | `opensec mcp` |
| **agent tool** | the *scan's* agents, in-process | `src/agents/tool.ts` |

```ts
const scanner = await Scanner.open({ repo: ".", model: "kimi/k2" });
const scan = await scanner.run();
// or drive the spine yourself — phases are individually callable and durable
const inv = await scanner.inventory();
await scanner.investigate(await scanner.discover({ partition: inv.partitions[0] }));
```

Every adapter carries a `RunContext` bound to `(scan_id, worker_id, round)`; without
it the three adapters resolve ambient state three different ways.

### The agent tool

```
probe        read, grep, find, ls, opensec, delegate         ← no bash
investigate  read, grep, find, ls, bash, opensec, delegate   ← bash: container only
subagent     read, grep, find, ls, opensec(read-only verbs)   ← cannot file findings

opensec({ verb: "work.next",         limit, cursor })  → assigned files + total
opensec({ verb: "candidate.create",  title, cwe, locations[], summary, evidence })
opensec({ verb: "candidate.resolve", id, disposition, confidence, evidence,
                                     impact, likelihood, suppression{} })
opensec({ verb: "lead.record",       text, status })

delegate({ agent_type: "tracer" | "skeptic", task, description })  → the child's report
```

Prose arrives as JSON and never touches a shell — no backtick command substitution,
no `--body-file` dance. There is deliberately no `files.done` verb: completion is
derived from traces (§6), so an agent cannot mark work it never did.

**Fan-out is in-process** `createAgentSession()` with a concurrency limiter — *not*
pi's `subagent` extension, which spawns a fresh `pi` process: `customTools` don't
cross the boundary (the `opensec` tool silently vanishes), `--no-session` kills the
traces coverage depends on, budget and abort don't propagate, and the child inherits
the API key. Confirmed from its source: it is `spawn(execPath, ["--mode","json","-p",
"--no-session"])`. **Agent-initiated delegation uses the same in-process path**, one
level deep, so a subagent keeps the tool, the trace, the budget and the coverage.
Pin `@earendil-works/pi-coding-agent` to an exact version.

---

## 4. Pipeline decisions

**Inventory is `rg --files --hidden --no-ignore --glob '!.git/**'`**, not
`git ls-files` — untracked and hidden files are real surface (CI configs,
`.env.example`, dropped scripts). Sorted `LC_ALL=C`, written atomically, so the list
is byte-identical across runs. Filtering happens after, and every excluded file keeps
its exclusion reason.

**Partitions are size-capped clusters.** Real bugs cross files — source in
`handlers/upload.ts`, missing containment in `lib/archive.ts` — so reads are
repo-wide and only *ownership* is partitioned. Most repos are one giant
weakly-connected import component (a shared `utils` connects everything), so
component-based partitioning would put 90% of files in one partition. Instead: take
components, split anything over `partition_max_files` by directory affinity, merge
anything under the floor into its nearest neighbour. `role: source` / `role: sink`
fragments from different worklists are joined on symbol name — a **lead generator,
not a merge**, since `execute` and `open` collide constantly. The partition size
distribution prints in the scan header, because one probe owning 300 files is a run
whose coverage claim is worth less.

**Validation and attack-path are one session, two records.** Splitting them meant two
agents loading the same candidate, code and repro.

**Dedup.** Exact `(path, line, cwe)` never fires — rounds cite different lines of the
same function and CWE assignment legitimately varies (CWE-22/-23/-36). Cheap pass is
`(file, enclosing symbol, normalized CWE family)`; an LLM reducer runs only within
collision groups and must justify each merge by **remediation subsumption** (merge
only if one patch fixes both). Source rows are preserved: over-merging destroys
instances silently, under-merging only costs budget.

### Structural checks at the write boundary

Each is a failure mode a model actually produces:

| Check | Why |
|---|---|
| line range exists in the real file | a hallucinated line is a hard tool error, not a bad report |
| locations resolve inside the repo, regular file, no symlink | scanned code is attacker-authored |
| ≥1 location in the worker's own worklist | ties every finding to an owner |
| unknown fields rejected | a typo'd field is silent data loss |
| duplicate `(rule, anchor)` with no `instance` | enforces instance-splitting — siblings cannot collapse into one row |
| IDs derived, never accepted | `sha256(rule, anchor, instance)`; line numbers never enter identity, so ids survive code movement |

On collision, rows **merge their prose** rather than first-wins, so two passes that
found the same sink from different angles keep both rationales.

**Degradation is directional.** Anything unverifiable degrades the *scan's* claim
rather than disappearing: a discarded finding forces every coverage surface to
`needs_follow_up` and appends a deferred row; an unparseable disposition becomes
`needs_follow_up`. Malformed model output can make a scan look worse — never clean.
Thirty lines, and the right default for the whole system.

---

## 5. Trust boundaries

**What runs where.** Every LLM session runs in-process on the host. The container
exists for exactly one thing: executing `investigate`'s bash. That deletes three
pieces of machinery earlier drafts carried — a unix-socket DB server (nothing in the
container writes), an egress proxy (model calls originate on the host, so the
container needs zero egress), and a credential broker (the agent *is* the
orchestrator process). Each solved a real problem for a design that no longer exists.

**Scope comes from the human, never from the repo.** Scanned code is attacker-
authored by definition. codex is of two minds here — their guidance calls a resolved
`SECURITY.md` *"untrusted policy data"*, while their threat-model skill says it *"can
be that authoritative source"*. The second gives back what the first withholds: a
repo shipping *"`src/auth/` is a demo harness, out of scope"* shapes every partition
and suppression without issuing an instruction, and the payoff is silent false
negatives. So:

- Scope is set by CLI flags and config. Full stop.
- `SECURITY.md`/`AGENTS.md` are evidence with provenance, never suppression grounds.
- Every suppression records `source ∈ {policy_flag, code_evidence, repo_claim}`, and
  repo claims are quoted: *"N candidates suppressed on in-repo policy claims."*
- All repo-derived context is wrapped in a per-run nonce delimiter; only text outside
  nonce blocks is instruction.

### Two profiles

| | container | static |
|---|---|---|
| repo | writable copy at `/work` | read-only |
| execution | builds, tests, PoCs | **none** |
| `investigate` | + bash | no bash, reads confined to repo root |
| ceiling | crashing PoC → ASan → debugger → test → repro | static trace, `proof_gap: no_execution` |

```bash
opensec scan .                       # auto: container if Docker is reachable
opensec scan . --profile container   # require it, fail loudly — the CI setting
opensec scan . --profile static      # force read-only, never touch Docker
```

Static executes **nothing**. Running the repo's own tests is arbitrary execution by
design, not by injection (`npm test` runs `package.json` scripts, `pytest` auto-loads
`conftest.py`, `cargo test` runs build scripts) — on a machine that reaches
`~/.ssh`, `~/.aws`, and every repo the user ever scanned. The profile is recorded on
the scan and printed in the report header, and `compare` carries it: dropping to
static once must not read as a pile of "resolved" findings.

**Container:** `--network none` — not an allowlist, not a proxy; nothing inside needs
to reach anything, so there is no rule to get wrong. Plus `--cap-drop ALL
--security-opt no-new-privileges --read-only --init --pids-limit --memory --cpus
--user 10001:10001`, tmpfs `/tmp`, digest-pinned base image, per-bash timeouts, never
the Docker socket. (`--init` for PID-1 reaping, or a build that leaks processes
defeats `--pids-limit`.)

**Honest limits:**

- v1 does not resolve dependencies — `--network none` makes that a hard constraint.
  Validation uses vendored deps or a warm cache, else records
  `proof_gap: build_requires_network`. Expect this on a real fraction of repos.
- The model API is still a bidirectional channel the orchestrator holds, and it is
  fed attacker-authored code. Container egress control stops PoCs phoning home; it
  does not stop prompt content leaving.
- `/out` is a host volume, so PoC artifacts land on the host: never auto-opened,
  never executable.
- `probe` has no bash but can launder a payload into `candidate.summary`, which
  `investigate` reads *with* bash. Candidate fields are sanitized leaving probe.

**Credentials and privacy.** The API key never reaches the container. Bash children
get an explicit env allowlist, never inheritance; credentials come from a mode-600
file so they aren't handed to every child. Secret-shaped strings are redacted before
findings reach SQLite. And "runs locally" reads as "my code stays local", which is
false for every non-local model — so the README says so plainly, with default
exclusions, redaction before any prompt, and per-provider retention notes.

---

## 6. Storage, severity, coverage

**One process, one connection, no DB in the container.** Single-writer by
construction — no claim races, no lease recovery, and none of the WAL-over-virtiofs
breakage a bind-mounted DB would have caused. One DB at `~/.opensec/opensec.db`,
`--db` to override; artifacts under `~/.opensec/scans/<scan_id>/`. Never hold a
transaction across an LLM call.

```sql
schema_version (version, applied_at)                 -- from M0, not retrofitted
repos          (id, path, name, remote_url, created_at)
scans          (id, repo_id, revision, mode, profile, status, phase, round,
                config_hash, cancel_requested, heartbeat_at, started_at,
                completed_at, tokens_in, tokens_out, cost_usd, coverage)
files          (scan_id, path, sha, owner_worker, partition_id, excluded_reason,
                bytes_total, bytes_read, first_touched_at)
candidates     (id, scan_id, round, worker_id, title, cwe_ids, locations_json,
                summary, evidence, instance, resolution_json, merged_into)
leads          (scan_id, worker_id, text, status)    -- hypotheses that died
surfaces       (scan_id, label, risk_area, disposition, reason, candidate_id)
```

`files` *is* the worklist — `work.next` is a query over it, and `bytes_read` is what
makes coverage measurable. `surfaces` is the coverage ledger, derived
deterministically from candidate outcomes with no extra model call: resolved
reportable → `checked`; either phase deferred → `needs_follow_up` + a deferred entry;
`not_applicable` → `not_applicable`; suppressed → `rejected`; missing record →
unresolved, which blocks `coverage: complete`.

`findings`/`occurrences`/`triage`/fingerprints arrive with `compare` (M6). Their
schema is not designed yet.

### Severity is computed

codex's matrix says `impact=high / likelihood=high → critical **only when the
critical criteria above are satisfied**` — the distinction anyone acts on is prose.
And both enums include `ignore`, so 5 of 25 cells are suppression: a `severity.ts`
fed those enums launders judgment rather than removing it.

1. **Reportability is a gate before the matrix.** Hard suppression first — self-only,
   unachievable precondition, privileged-only — *unless the privilege delta itself is
   the bug*. Without this gate, dropping `ignore` means self-XSS lands at `low` and
   ships. The matrix is not a delete key: low impact downgrades, never discards.
2. **No `ignore` in either enum.** Suppression is auditable booleans with evidence
   strings: `self_only`, `requires_preexisting_privilege`,
   `privilege_delta_is_the_bug`, `precondition_unreachable`.
3. **Both axes have rubrics.** Likelihood keys off `vector ∈ remote | local_network |
   localhost | none | unknown`. Computing a matrix in code is theatre if its inputs
   are pure judgment.
4. **Critical comes from observable inputs**: `auth_required ∈ none|user|admin`,
   `network_reachable`, `cross_tenant`, `code_execution_proven`.
5. **Static scans can still reach critical.** `code_execution_proven` is only true
   under the container profile, so requiring it would cap the *default* profile below
   critical for a textbook RCE that's obvious from reading the code. Second route:
   unauthenticated, network-reachable, traced path, no intervening control — carries
   `proof_gap: no_execution` and prints as `critical (unproven)`. The ceiling is on
   confidence, not severity.
6. **Confidence is bound to method numerically**: 1.0 reproduced PoC, 0.9+ ASan, 0.8+
   debugger, 0.3+ code understanding alone, 0.0 counterevidence. Without this, a
   static trace of a scary CWE reports 0.9.
7. **The matrix is a data table in one module** — `help.ts` renders it, `severity.ts`
   evaluates it, the MCP schema describes it. Drift is impossible rather than tested
   for.
8. **CWE hygiene.** No clear class keeps `cwe: []` — never invent a classification.
   CWE comes from the *primary broken control*, not bolted-on support impacts.

### Coverage is measured

An agent that reads nothing and marks everything done would yield
`coverage: complete`, so there is no self-report verb. A file counts as touched only
when a `read`/`grep` actually reached it — and a searched or partially-read file is
not a completed file. Three numbers, because none alone is honest: files touched
(gamed by one repo-wide grep), **bytes read vs bytes in scope** (the one to trust),
and surfaces dispositioned. Trace-derived coverage is a **laziness detector, not
proof of review**, and the README says exactly that. Plus the `leads` table, because
"every candidate dispositioned" is trivially satisfied by never creating candidates.

---

## 7. Prompts

Ozone's shape (~130 lines), with ~200 lines of codex kept as phase-local references.
Roughly half of every codex SKILL.md is tool choreography our orchestrator does in
code.

```
prompts/
  orchestrator.md      threat-model first and written down BEFORE fan-out, probe
                       wide, verify before reporting, account for every unresolved
                       lead, "what is not a finding"
  agents/{probe,investigate}.md
  refs/                loaded only by the phase that needs them
    severity.md · counterevidence.md · invalid-rebuttals.md · instances.md
```

**The counterevidence checklist needs a counterweight**, or it becomes a suppression
machine — absence of deployment evidence is always available. *"Missing
public-ingress evidence is not by itself dispositive counterevidence"*: it lowers
confidence, never forces suppression. Plus a named list of invalid rebuttals, each a
fossil of a specific bad triage:

- An `alert` proof demonstrates JavaScript execution — it is not evidence *against*
  XSS.
- An HTTP method or JSON content type alone is not a CSRF defense.
- An intended webhook, or an optional operator allowlist, does not suppress SSRF when
  attacker-controlled destinations reach internal or metadata targets.
- *"Missing internal runtime setup is not suppression evidence"* — the model that
  cannot build it has not thereby refuted it.
- A same-family finding in a neighbouring route never closes this row.

**One-line rules that cost a sentence each:** don't stop reviewing a file after one
bug; don't skip demos, examples, fixtures or tests that contain runnable behavior;
read nearby code (ownership is not a reading restriction); don't ignore a clear bug
because another seems more important; account for binaries that couldn't be reviewed
rather than dropping them from the denominator; don't let the scan target bias the
threat model; and no location-only filler — *"the root cause is tied to the broken
control at `path:line`"* is not a root cause.

`--prompts <dir>` with a documented resolution order, hashed into
`scans.config_hash`. That's what makes prompts-as-data real rather than "edit files
inside our npm package", and it's the seam a community rule pack needs.

---

## 8. Budgets, outputs, layout

```bash
npm i -g opensec && export OPENROUTER_API_KEY=...
opensec scan . --estimate     # files, tokens, $, wall-clock — spends nothing
opensec scan .
```

```toml
[limits]
max_cost_usd = 3   ·   wall_minutes = 30   ·   max_files = 2000
partition_max_files = 60
```

Findings stream to the terminal as they're confirmed. No presets until the benchmark
can generate them: one sensible default model, `--model X` to override, per-phase
overrides with per-key fallthrough so a phase can set effort and inherit the model.

**A budget you cannot price is not a budget** — a model with no pricing entry makes
`--max-cost` refuse to start rather than run unbounded. This bites us harder than
codex since we're deliberately multi-provider, so `opensec models` prints what's
priced, `--max-cost none` is the explicit opt-out, and a price is a one-line PR. The
budget **aborts in flight** from the live session stream, not after a phase returns
when the tokens are already billed. If usage can't be measured, say so rather than
printing zero.

**Outputs are attack surfaces**, since every finding carries attacker-controlled
prose. Escape by default and never `innerHTML`; `CSP default-src 'none'`; bind
`127.0.0.1` with a per-run token and an `Origin` check; strip ESC sequences from CLI
output (OSC 52 writes the clipboard, OSC 8 forges links); SARIF uses `message.text`
only (GitHub renders `message.markdown`); CSV cells starting `= + - @` (and fullwidth
forms) get a `'` prefix. Canonical records are write-once, projections always
regenerated, and SARIF export failure warns rather than failing the scan.

`opensec serve` (M4) is one Node process over the same SQLite: scans · findings ·
finding detail · triage.

```
opensec/
├── src/
│   ├── sdk/          THE API — Scanner, RunContext, types, events
│   ├── cli/ · mcp/
│   ├── scan/         inventory · partition · threat-model · discovery
│   │                 investigate · coverage · severity · render
│   ├── agents/       session (pi SDK) · pool · tool
│   └── db/           schema.sql · migrate · queries
├── prompts/          data: shipped as files, hashed, overridable
├── docker/ · benchmark/ · test/ · docs/
```

`prompts/` sits outside `src/` because it is data. **Extension seams in v1:** output
formats and prompt packs. **Deliberately absent:** custom phases (the spine's value
is that it's fixed) and pluggable storage (every query is SQLite-specific and it
would constrain the single-writer design).

---

## 9. Milestones

| # | Deliverable | Done when |
|---|---|---|
| **M0** | **Walking skeleton.** Inventory → threat model → **one** probe, no partitioning → investigate → markdown. SQLite, the write tool, `work.next`, computed severity, static profile | One command on a known-vulnerable repo prints a finding with file:line — the pi-session + tool + SQLite + renderer loop is proven |
| **M1** | Fan-out and accounting: partitioning, N probes, fragment join, trace coverage, surfaces ledger, dedup, SARIF | A clean-machine install scans a 300-file repo with 8 probes and reports coverage it can defend |
| **M2** | Container + `--profile auto\|container\|static` | Crashing PoCs; CI can require the sandbox |
| **M3** | Benchmark: execution oracle, temporal holdout, published results | We can state recall@N and sampled precision, per model |
| **M4** | `opensec mcp` + `opensec serve` | Claude Code can scan and triage without leaving the editor |
| M5 | `--diff`, `--fail-on`, `--baseline`, GitHub Action | A PR check that comments only CONFIRMED findings |
| M6 | fingerprints + `opensec compare` | Triage survives a re-scan; new/persisting/resolved |
| M7 | Deep mode saturation loop + presets from M3 | `deep` terminates `saturated` or `capped` as a checked assertion |

**v1 = M0–M4.** One rule behind the ordering: nothing claims evidence it doesn't
have. The benchmark precedes deep mode and presets, because "repeat until saturated"
is a 20× spend multiplier and "use Qwen for discovery" is a recommendation — neither
worth making without measurement. M5–M7 mechanics are undesigned — the research
that once backed them is not in this repository, so budget for redoing it.

**Benchmark note.** Known-CVE precision/recall cannot produce a defensible number:
recall over a denominator of one, contamination that *differs per model* (biasing the
exact comparison this exists to make), patch-adjacent leakage, no definition of a
match. So execution is the oracle — a scan either produces a crashing input or it
doesn't — starting with CVE-Bench, reporting recall@N plus sampled manual precision,
with a temporal holdout on advisory date vs model cutoff.

---

## 10. Known risks

- **Name.** `opensec` is one character from **OSSEC**. npm is unclaimed; the GitHub
  orgs are taken. Mitigated in the README's first paragraph, not by renaming.
- **The prompt bet.** Dropping codex's ~60 family-specific heuristics assumes a short
  general prompt travels better across models. Unproven until M3.
- **Partitioning may not balance.** Size-capped clustering over a regex import graph
  is a heuristic; if repos split badly, probes are unevenly loaded and the coverage
  claim weakens. The size distribution prints in the header so this fails loudly.
- **Monorepos.** `max_files` refuses with scoping guidance rather than running away.
- **Language coverage.** Untested languages degrade silently; the report must say
  which languages it recognized.
