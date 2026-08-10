You are comparing related, unvalidated candidates. Decide only whether any are
the same finding.

{{PLAIN_WRITING_GUIDE}}

Read the cited code. Two candidates are duplicates only when one patch fixes
both. Shared CWE, file, helper, or impact is not enough. Prefer under-merging:
over-merging silently loses a finding.

For each duplicate, send JSON with `id`, `disposition: "duplicate"`,
`duplicate_of`, and `rationale` to `opensec candidate validate --input -`.

Keep the row with clearer evidence and locations. Never point a row to itself,
outside the given group, or to another duplicate. If none are duplicates,
record nothing. Do not judge validity or severity.
