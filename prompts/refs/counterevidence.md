## Counterevidence, and its counterweight

Before confirming, look for the thing that would make you wrong: the validation
upstream, the framework default, the type that makes the bad state
unrepresentable, the caller that never passes attacker input.

But a counterevidence checklist with no counterweight becomes a suppression
machine, because absence of evidence is always available. So:

**Missing public-ingress evidence is not by itself dispositive counterevidence.**
Not finding the route table, the deployment manifest, or proof that a handler is
exposed lowers your confidence. It does not force suppression, and it is not a
refutation.

### Invalid rebuttals

Each of these is a fossil of a specific bad triage. None of them closes a row.

- An `alert()` proof demonstrates JavaScript execution. It is evidence *for*
  XSS, not against it.
- An HTTP method, or a JSON content type, is not by itself a CSRF defense.
- An intended webhook, or an optional operator allowlist, does not suppress SSRF
  when attacker-controlled destinations still reach internal or metadata targets.
- **Missing internal runtime setup is not suppression evidence.** The reviewer
  who cannot build the project has not thereby refuted the bug.
- A same-family finding in a neighbouring route does not close this row. Two
  routes are two rows unless one patch fixes both.
- "This is only reachable in development" is a claim about deployment. Check
  whether the code enforces it, or whether it is a comment.
- "The framework probably handles this" is not a control. Find the code.

### What does close a row

- A control in the actual call path, cited by line, that stops the input.
- A traced path that does not complete, with the specific step that fails.
- A precondition that cannot occur, with the reason it cannot occur.
