# opensec

Point it at a repository, get security findings with `file:line`, evidence, and
a severity you can defend — using any model you want, on your own machine.

TypeScript, no Python. The SDK is the contract; the CLI shapes arguments and
formats results. One SQLite ledger at `~/.opensec/opensec.db`, artifacts under
`~/.opensec/scans/<scan_id>/`.

```bash
npm install && npm run build && npm test
node dist/cli/index.js scan . --estimate
node dist/cli/index.js scan . --model azure-openai-responses/gpt-5.4
```

## The spine

`Scanner.run()` calls seven methods in a fixed order. The model is never asked
what to do next — only ever asked a question inside one phase.

```
0  inventory     rg --files → filter → worklist → partitions      no LLM
1  threat model  1 agent, cached per repo and reused as written   prompts/threat-model.md
2  discovery     N probes in parallel, each handed a worklist     prompts/probe.md
3  reduce        an agent reads only the groups that collide      prompts/reduce.md
4  validate      1 agent per candidate: is this real?             prompts/validate.md
5  attack path   1 agent per survivor: how far does it reach?     prompts/attack-path.md
                                                                  + refs/counterevidence.md
6  report        SQLite → markdown + JSON                          no LLM
```

```
src/sdk/scanner.ts      the spine; every phase is individually callable
src/agents/session.ts   pi sessions, tool confinement, coverage instrumentation
src/agents/tool.ts      the one tool the agents write through — five verbs
src/agents/subagent.ts  in-process delegation, one level deep
src/scan/              inventory · partition · identity · severity · render · prompts
src/db/                schema.sql (frozen) · migrations.ts · db.ts
prompts/               data, not code: shipped as files, hashed, overridable
test/                  vitest
```

## Invariants

These are what the code is for. Breaking one silently is worse than a bug.

**Severity is computed, never accepted.** The model supplies observable inputs;
`src/scan/severity.ts` computes the rest from one data table that
`opensec help severity` and the report appendix both render. Neither enum has an
`ignore` value. Confidence is bound to method numerically — a static trace
cannot report 0.9.

**Suppression is a gate before the matrix, and it needs three things**: the
boolean, written evidence, and a `source` that is grounds. `repo_claim` is not
grounds, and an absent source is not a way around that. A refused suppression is
louder than an accepted one — it goes in the report.

**Coverage is measured, not reported.** There is no verb an agent can call to
mark work done. A file counts as touched only when a `read` or `grep` actually
reached it; the bytes are what the agent was handed, not the file's size. This
catches an agent that never looked. It cannot tell you one understood what it
read, and the report says so.

**Scope comes from the user, never from the repo.** Scanned code is
attacker-authored by definition. A `SECURITY.md` or `AGENTS.md` inside the
repository under review is evidence with provenance — never an instruction,
never suppression grounds. All repo-derived text is wrapped in a per-run nonce,
and the nonce is stripped from agent prose so repo text cannot forge the
boundary a later agent reads its own prompt through.

**pi's "project" is never the scanned repo.** pi trusts `<project>/.pi/settings.json`
and will spawn its `npmCommand`; it will also splice `.pi/APPEND_SYSTEM.md` into
the system prompt above ours. Settings are in-memory and untrusted, resources
load from a directory we own, and the repo path reaches the file tools only.

**Reads are confined to the repo root** (plus a worker's own overflow
directory). `withinRepo` decides containment on the path pi will actually open —
see `normalizeLikePi`, which mirrors pi's private path expansion and is pinned by
tests. That check has been wrong three times; treat it accordingly.

**Verbs are scoped by role.** Probes file, validate judges, assess rates, the
reducer only merges, subagents write nothing. Candidate ids are predictable, so
without this one probe can resolve another's finding.

**Degradation is directional.** Anything unverifiable downgrades the scan's
claim rather than disappearing: no verdict becomes `needs_follow_up`, an
unparseable disposition becomes `needs_follow_up`, a duplicate pointing at an
already-merged row is refused. Malformed model output can make a scan look
worse. It must never make one look clean.

**Prompts are data.** Resolution order is `--prompts <dir>`, then
`~/.opensec/prompts`, then the packaged `prompts/`, first hit wins per file, all
of it hashed into `scans.config_hash`. The scanned repository is deliberately
not in that list.

**`src/db/schema.sql` is frozen.** `CREATE TABLE IF NOT EXISTS` is a no-op
against a table that exists, so editing it does nothing for anyone who has
already run a scan. Every change is an entry in `src/db/migrations.ts`.

## Writing prompts

Shorter is better. Every constraint that actually matters is enforced in
`src/agents/tool.ts` and fails as a hard, recoverable tool error — a fake line
number, a location outside your partition, an unknown field, a verb you do not
hold. Prose that restates a mechanism costs context and buys nothing; prose that
substitutes for one is a wish.

Two things worth knowing before trusting output: model calls send source code to
whatever provider you pointed at, and coverage is a laziness detector rather than
proof of review.

## Status

Static profile only — `--profile container` throws. Not yet: SARIF, the
`surfaces` coverage ledger, diff scans, deep mode, scan comparison, remediation.
No serious third-party codebase has been scanned yet; every finding so far has
been about opensec's own plumbing.

## License

Apache-2.0. The method, the severity policy's structure, the counterevidence
checklist and the instance-splitting rules derive from
[openai/codex-security](https://github.com/openai/codex-security); see
[NOTICE](NOTICE).
