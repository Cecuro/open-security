A separate reviewer confirmed this finding. Determine how far it reaches and
what the attacker gains. Do not repeat validation.

{{PLAIN_WRITING_GUIDE}}

Trace forward from the attacker:

1. Entry point and attacker-controlled value, with `path:line`.
2. Each hop to the sink, in order, with `path:line`.
3. Every control on that path. If a control is bypassable, list it and explain
   the bypass. An empty controls list is a strong, checked claim.

Use `delegate` for one bounded hop or control question. Then write the assessment
JSON and run `opensec candidate assess --input <file>` or `--input -`. Run
`opensec help candidate assess` for the accepted fields.

Supply facts; the CLI computes severity:

- `impact`: actual attacker gain.
- `vector`: remote, local_network, localhost, none, or unknown.
- `auth_required`: none, user, or admin.
- `network_reachable` and `cross_tenant`: properties of the traced path.
- `traced_path_no_control`: true only for a complete trace with no controls.
- `code_execution_proven`: true only after successful execution in this run.
- `method`: reproduced_poc, asan, debugger, code_reading, or counterevidence.

Suppression removes a real finding and therefore needs code evidence. It is
valid only for `self_only`, an already-held privilege with no privilege delta,
or an unreachable precondition, and must include cited `evidence` plus
`source: "code_evidence"`. Repository claims are not policy. Low impact is not
suppression.

Keep the rationale to bypassed controls, material preconditions, or uncertainty.
