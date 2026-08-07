# opensec

Point it at a repository, get real security findings with `file:line`, evidence,
and a severity you can defend — using any model you want, on your own machine.

> **Not OSSEC.** `opensec` is one character away from
> [OSSEC](https://www.ossec.net/), the host intrusion detection system. They are
> unrelated projects. If you were looking for HIDS, you want OSSEC.

Status: **M0 — walking skeleton.** One probe, no fan-out, static profile only.
It runs the whole loop end to end and produces a report. It does not yet do
partitioning, parallel probes, fan-out coverage accounting, or containers. See
[docs/plan.md](docs/plan.md) for what M1–M7 add.

## Install

```bash
npm i -g opensec
```

Requires Node 20.11+ and [ripgrep](https://github.com/BurntSushi/ripgrep) on
`PATH`. Credentials come from pi's model runtime — set the environment variables
for whichever provider you use, e.g. `AZURE_OPENAI_API_KEY` and
`AZURE_OPENAI_BASE_URL`, or `OPENROUTER_API_KEY`, or `ANTHROPIC_API_KEY`.

## Use

```bash
opensec scan . --estimate
```

```bash
opensec scan . --model azure-openai-responses/gpt-5.4
```

```bash
opensec help severity
```

Nothing is guessed: without `--model`, opensec refuses to start rather than
picking a model for you. `--estimate` spends nothing, writes nothing, and needs
no model.

As an SDK:

```ts
import { Scanner } from "opensec";

const scanner = await Scanner.open({ repo: ".", model: "azure-openai-responses/gpt-5.4" });
const result = await scanner.run();

// or drive the spine yourself — phases are individually callable
const inv = await scanner.inventory();
const tm = await scanner.threatModel();
await scanner.discover(tm);
await scanner.reduce();
await scanner.validate();
await scanner.assess();
const report = scanner.report();
```

## What it actually does

```
0  inventory     rg --files → filter → worklist                   no LLM
1  threat model  1 agent: entry points, trust boundaries,          cached
                 authn/authz, sensitive assets, external surface
2  discovery     N probes in parallel, each handed a worklist,
                 free to read the whole repo                      no bash
3  reduce        identical findings merge in code, for free;
                 an agent reads only the groups that collide
4  validate      1 agent per candidate: is this real?
5  attack path   1 agent per survivor: how far does it reach?
6  report        SQLite → markdown + JSON                         no LLM
```

Agents write through **one tool with five verbs** — `work.next`,
`candidate.create`, `candidate.validate`, `candidate.assess`, `lead.record`.
File lists, severity arithmetic and the report are ordinary TypeScript that
cannot drift.

**Validation and rating are separate agents, on purpose.** A reader who has
already talked themselves into "this is real" is a poor judge of how far it
actually reaches. Splitting them means most false positives die in a cheap pass
that has no severity fields to reach for, and the agent that builds the attack
path starts cold, without the first one's reasoning. It also makes the
reachability trace checkable: `traced_path_no_control` is one of two routes to
`critical`, and the tool now rejects it when the recorded path is empty or lists
controls.

**Dedup is two layers.** Findings with the same class, files, roles and instance
collapse the moment they are filed, without a model — two probes reaching the
same conclusion produce one row carrying both their evidence. Only groups that
collide but are not identical reach an agent, and the test there is remediation
subsumption: two rows are duplicates only if one patch fixes both. Merged rows
are kept, never deleted. Finding something twice is evidence about the search,
not about the finding, so a merged row is validated like any other.

**The threat model is yours.** It is written to
`~/.opensec/repos/<repo>/threat-model.md` and reused on the next scan of the
same repository, as written. Edit it — you know which entry points are actually
exposed and which "sensitive asset" is test data. `--refresh-threat-model`
regenerates it; nothing else overwrites it.

Any agent can `delegate` a self-contained task to a subagent: a general reviewer
with a fresh context and the same read-only tools. Subagents run **in-process**,
one level deep, sharing the ledger — their reads count toward coverage and their
spend counts against `--max-cost`. They cannot record findings. They report back,
and the agent that delegated stays accountable for what gets filed.

## Three things worth knowing before you trust the output

**"Runs locally" does not mean your code stays local.** The orchestrator, the
ledger and the file handling are all on your machine. But every model call sends
source code to whatever provider you pointed it at, and that is true of every
non-local model. Default exclusions reduce what goes over the wire; they do not
make it zero. Check your provider's retention policy.

**Coverage is a laziness detector, not proof of review.** The report says how
many files were touched and how many bytes were read, derived from the read and
grep calls that actually happened — there is no verb an agent can call to mark
work done. That catches an agent that never looked. It cannot tell you an agent
understood what it read.

**Severity is computed, not chosen.** The model supplies observable inputs —
impact, vector, auth required, network reachable, whether it traced the path,
whether it proved execution — and the CLI computes severity from a data table
you can print with `opensec help severity`. Suppression is a gate before the
matrix, with auditable booleans and evidence, so low impact downgrades a finding
but never silently deletes it. Under the static profile nothing is executed, so
confidence is capped at code-reading (0.3) and any critical prints as
`critical (unproven)`.

## Scope comes from you, never from the repo

Scanned code is attacker-authored by definition. A `SECURITY.md` or `AGENTS.md`
in the repository under review is **evidence with provenance**, never grounds for
suppression and never an instruction — pi's project context loading is switched
off for scan sessions, and all repo-derived text is wrapped in a per-run nonce
delimiter. Suppressions record whether they rest on `policy_flag`,
`code_evidence` or `repo_claim`, and repo claims are quoted in the report.

## Development

```bash
npm install && npm run build && npm test
```

The ledger lives at `~/.opensec/opensec.db`, artifacts under
`~/.opensec/scans/<scan_id>/`. `--db` overrides.

## License

Apache-2.0. The method, the severity policy's structure, the counterevidence
checklist and the instance-splitting rules derive from
[openai/codex-security](https://github.com/openai/codex-security); see
[NOTICE](NOTICE).
