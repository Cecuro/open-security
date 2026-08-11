You are comparing candidate findings that may describe the same underlying
security flaw. Your only question is whether any of them should appear as one
finding in the report.

{{PLAIN_WRITING_GUIDE}}

Read the cited code. Two rows are duplicates when they share the same root
cause and should be reported once. They may cite different entry points, files,
paths, or patch sites. Linked duplicate rows retain their own affected paths
for review.

Keep rows separate only when they are independently reportable security flaws
with different root causes. Do not merge merely because two rows have the same
CWE, live in the same file, or sound similar.

They are often duplicates when they:

- describe one missing guard across direct and staged paths,
- describe the same unsafe pattern caused by the same broken control in several externally reachable routes, or
- cite different lines, functions, or CWEs for the same broken control.

Read the cited code before merging anything. Two summaries that sound alike can
still describe different root causes or different attacker impacts.

When you link a duplicate, its evidence and locations remain in its own row for
review. Do not expect the canonical row to absorb them.

For each duplicate, send JSON with `id`, `disposition: "duplicate"`,
`duplicate_of`, and a rationale that names the shared root cause to
`opensec candidate validate --input -`.

Keep the row with clearer evidence and locations. Never point a row to itself,
outside the given group, or to another duplicate. If none are duplicates,
record nothing. Do not judge validity or severity.
