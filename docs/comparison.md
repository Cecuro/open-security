# opensec vs codex-security

Measured against a shallow clone of `openai/codex-security` on 2026-08-06, and
against opensec at commit `223db75`. Every number below was counted, not
recalled — the plan's §2 table was written from a teardown document that is no
longer in this repository, and three of its four figures were wrong.

## Size

| | codex-security | opensec |
|---|---|---|
| TypeScript | 50,614 lines | 3,287 lines |
| Python | 19,023 lines across 34 scripts | none |
| Prompt / skill markdown | 4,465 lines across 13 skills + 10 shared references | 360 lines across 7 files |
| **Total** | **~75,000 lines** | **~3,650 lines** |
| SQLite tables | 19 | 6 |
| Agent tool surface | 46 `workbench_cli` subcommands | 6 (`opensec` × 5 verbs, `delegate`) |
| Tests | not counted | 1,195 lines, 65 tests |

Corrections to the plan's §2 table: they have **19** tables (not 15), **34**
Python scripts / 19k lines (not 32 / ~15k), **4,465** prompt lines (not ~3,000),
and the agent-facing surface is **46** CLI subcommands (not 59 MCP tools). The
~75k total was right.

## What they have that we do not

This is the honest half of the comparison. Ordered by how much it would hurt a
real user.

| Capability | Their surface | Ours |
|---|---|---|
| **Remediation** | `fix-finding` generates a patch; `finding_remediation_attempts` tracks it | nothing. We report; we never fix. |
| **Hardening proposals** | `propose-security-hardening` | nothing |
| **Ticket intake / tracking** | `triage-finding`, `track-findings` — Jira, GitHub Security Advisories, GitHub REST | nothing |
| **Security policy as a first-class object** | `define-security-policy` | CLI flags only, deliberately (plan §5) |
| **Diff scans** | `security-diff-scan`, `scan_comparisons`, `scan_comparison_matches` | M5/M6, unbuilt |
| **Deep mode** | `deep-security-scan`, `deep_scan_runs/workers/dedup_inputs` | M7, unbuilt |
| **SARIF** | `references/sarif-adapter.md` | M1, unbuilt |
| **Multi-target / workspaces** | `workspaces`, `security_targets` | one repo per scan |
| **Family-specific discovery heuristics** | ~60 bullets of hard-won detail: SSRF webhook nuance, CSRF cookie policy and preflight behaviour, XXE engine specifics, deserialization primitives, upload content-type confusion | a short general prompt |

That last row is the plan's acknowledged bet (§10), and reading their prose
makes the size of it concrete. Their severity policy alone carries paragraphs
distinguishing "arbitrary file read that exposes source code" (high) from "one
that reveals env secrets" (critical). We have none of that, and we will not know
whether a shorter general prompt travels better across models until M3.

They also have production usage data. We have one fixture and one self-scan.

## What we have that they do not

| | |
|---|---|
| **Any model, per phase** | They are welded to Codex. We resolve any pi-supported provider, with per-phase overrides. |
| **Severity computed, not narrated** | Theirs is prose the model applies — `severity-policy.md` line 99 literally reads `self-only impact -> ignore`, so suppression is a value the model chooses. Ours is a gate of auditable booleans followed by a data-table matrix, both in code. Neither of our enums has `ignore`. |
| **Coverage derived from traces** | We instrument read/grep, so coverage is what happened. There is no verb an agent can call to claim progress. |
| **A ledger you own** | `~/.opensec/opensec.db`, 6 tables, documented, no service. |
| **In-process subagents** | Shared budget, shared coverage, verb-scoped. Every published pi subagent extension spawns a process and loses all three. |
| **Budget that refuses to guess** | `--max-cost` will not start against a model with no price. |
| **An editable, reusable threat model** | Theirs is regenerated per scan and lives in the workbench. Ours is a markdown file at `~/.opensec/repos/<repo>/threat-model.md`, reused as written on the next scan, overwritten only on request. |
| **A checked reachability trace** | Both of us split validation from attack-path analysis. Theirs records the path as prose the model writes; ours records `{entry_point, path[], controls[]}` as structure, and rejects `traced_path_no_control` when the path is empty or the controls list is not. |
| **Size** | 3.6k lines against 75k. Their whole Python layer — 19k lines of workbench scripts — is orchestration we do in ~300 lines of TypeScript, because our agents write through one tool instead of 46 CLI subcommands. |

## The claim that held up

Plan §6 argues their matrix "launders judgment rather than removing it", because
`ignore` is a value in both enums. That is confirmed in their source:

> `- If the issue is a real bug but not actually a security vulnerability, classify it as `ignore` (or, if you have to, `low`) for criticality purposes.`
> — `skills/attack-path-analysis/references/severity-policy.md:12`

and the suppression rules we reimplemented as booleans appear there as prose the
model is asked to apply:

> `- self-only impact -> ignore`
> `- unachievable or highly unrealistic preconditions -> ignore`
> — same file, lines 99–100

We turned those two lines into `self_only` and `precondition_unreachable`, each
requiring evidence, each evaluated before the matrix rather than inside it.

That claim was half true until opensec scanned opensec and found the other half:
the booleans were checked in code while `source` — the field that says whether
the model is entitled to set them — was enforced only by the prompt. So the
strongest claim the tool makes, removal from the report, was the one thing a
repository's own `SECURITY.md` could talk an agent into. Suppression now
requires the boolean, written evidence, and a source that is grounds;
`repo_claim` is not grounds, and neither is omitting the field.

The disagreement is real and narrow: they trust the model to apply a policy, we
compute the policy from inputs the model supplies. Both approaches depend on the
model being honest about the inputs. Ours makes the arithmetic auditable and
keeps a low-impact finding in the report; theirs carries far more domain
knowledge about what the inputs mean.

## Where this leaves us

We are not a smaller version of codex-security. We cover the **find → verify →
report** arc at roughly 5% of the code, and we do not attempt remediation,
ticketing, diffing or deep mode at all. For those, they are the tool.

The two things worth defending are the ones a fork of theirs could not easily
adopt: severity that is computed rather than narrated, and coverage that is
measured rather than claimed. Everything else on our side of the table is either
a consequence of being small or a milestone we have not reached.
