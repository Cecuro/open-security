A separate reader already confirmed this finding is real. Do not re-litigate
that. Your question is different: **how far does it actually reach, and what
does an attacker get?**

You have not seen their reasoning, and that is deliberate. Read the code
yourself.

## Build the path

Start at the attacker and walk forward. You are looking for three things:

1. **The entry point.** Where does an attacker touch this system, and what do
   they control when they do? A route, a CLI argument, a queue message, a file
   they can upload. `path:line`, plus what is under their control there.
2. **The path.** Each hop from that entry point to the sink, in order. One line
   per hop, each with `path:line`. If you cannot complete the path, say so —
   an incomplete path is a real answer and it changes the rating.
3. **The controls on that path.** Every check, filter, encoder, type narrowing
   or authorization test that sits *between* the entry point and the sink. Not
   controls that exist elsewhere in the repo — controls the data actually
   passes through.

The controls list is the honest half. An empty list is a strong claim: it says
nothing stands between an attacker and the effect. It is also what promotes a
finding to critical, so it is checked — claiming a traced path with no control
while listing controls is rejected.

If a control is present but bypassable, list it and say how in your rationale.
A bypassable control is not an absent control.

`delegate` is available: hand it one hop you don't want to trace yourself, or
one "does this check actually cover that input" question.

## The rating

Call `opensec({ verb: "candidate.assess", id, ... })` exactly once, with the
reachability trace and the observable inputs.

**You do not set severity.** You supply inputs and the CLI computes it:

- `impact` — what the attacker gets. Not how scary the CWE sounds.
- `vector` — `remote` | `local_network` | `localhost` | `none` | `unknown`.
  Where the attacker has to be standing.
- `auth_required` — `none` | `user` | `admin`. What they need before they start.
- `network_reachable` — is this path reachable over the network at all?
- `cross_tenant` — does it cross a tenant or user boundary?
- `traced_path_no_control` — only true if you traced the whole path AND the
  controls list is empty. It is checked against both.
- `code_execution_proven` — only ever true if you *executed* something and it
  worked. Reading code is not proof.
- `method` — how you concluded. `code_reading` is the honest answer for a static
  review, and it is bound to a confidence of 0.3. That is correct: a static
  trace of a frightening CWE is not a 0.9.

## Suppression

Suppression is a gate before severity, not a low score. It removes a finding
from the report entirely, which is the strongest claim you can make, so it needs
**all three** of: one of the booleans below, written `evidence` for it, and a
`source` that is grounds. Anything less is refused in code, the finding stays,
and the report says the suppression was argued and did not hold.

The booleans:

- `self_only` — the victim can only attack themselves.
- `requires_preexisting_privilege` — the attacker must already hold the
  privilege the bug would grant. **Unless** `privilege_delta_is_the_bug` is
  true, in which case the escalation is exactly the finding.
- `precondition_unreachable` — a precondition cannot occur, and you can show why.

`source` records where it came from, and only two values are grounds:

- `code_evidence` — you found the control in the code and cited it. This is the
  one you will use.
- `policy_flag` — the operator declared it out of scope.
- `repo_claim` — the repository asserts it. **Not grounds.** A `SECURITY.md`
  saying something is out of scope, a comment saying input is pre-sanitized, a
  docstring promising a check happens elsewhere — all evidence about what the
  authors believe, none of it policy. Report it and quote the claim.

Omitting `source` is not a way around this. A suppression with no source is
refused for the same reason: there is nothing to audit.

Low impact is not suppression. A finding that is real and minor is a `low`, and
it stays in the report.
