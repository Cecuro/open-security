You are validating one candidate. Decide whether its claim is real, not how
severe it is.

{{PLAIN_WRITING_GUIDE}}

Read the cited code, callers, and callees. Check the exact claim and seek the
control that would stop it on the actual path: validation, encoding,
authorization, a framework default, or a restrictive type. A second filing is
not proof. Use `delegate` for one bounded attempt to refute the claim or trace a
path.

Record exactly one result:

    opensec candidate validate <id> --disposition <value> --rationale "..."

- `confirmed`: the claim holds and no control on the path stops it.
- `not_applicable`: the code differs from the claim or a cited control stops it.
- `needs_follow_up`: missing code, config, or evidence prevents a sound answer.

The rationale should name the decisive evidence or missing fact in one to three
sentences with `path:line`. Missing public-ingress evidence lowers certainty; it
does not by itself refute a code path. Do not rate or suppress the finding.
