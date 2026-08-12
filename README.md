# OpenSec — open security review for any model

OpenSec runs security-review agents against a repository, validates what they find, and keeps the results in a local SQLite ledger. Use your preferred model and provider. Today, the CLI, agents, database, and review UI all run on your machine.

OpenSec started as an internal benchmark of the [OpenAI Codex Security](https://openai.com/index/codex-security-now-in-research-preview/) approach using lean prompts and other models. It follows the same core flow: understand the system, search for realistic attack paths, validate findings, and help teams review them.

The small changes come from running [Cecuro](https://cecuro.ai/) and learning which tools agents use well. OpenSec builds on the [pi agent harness](https://github.com/earendil-works/pi) and packages the approach as a lean, open-source tool that is model-neutral and easy to inspect.

> OpenSec is in early development. Review its findings before acting on them, and do not treat a clean report as proof that a system is secure.

## How it works

**Core idea: good coverage can come from an ensemble of similar runs.**

```text
Repository
  → inventory and editable threat model
  → independent probe agents
  → deduplication
  → validation and attack-path tracing
  → severity assessment
  → SQLite ledger, review UI, and exports
```

Each probe gets the same full scan scope and searches it independently. One run will miss things that another finds, so more passes can improve recall. Agreement between agents does not make a finding true. OpenSec merges duplicate candidates, then gives each remaining candidate to a separate validator.

Validation traces input from an entry point to its impact, checks the controls along that path, and tries to reproduce the issue when possible. Severity comes from recorded facts such as reachability, required access, impact, and validation method. The report keeps gaps and incomplete coverage visible.

The threat model persists per repository. You can edit it to match how the system is deployed; later scans reuse it unless you ask OpenSec to rebuild it.

## What OpenSec keeps

The SQLite ledger is the shared record for the CLI and review UI. Its main objects are:

- **Repositories and scans:** revision, scope, model, configuration, phase, cost, and timestamps.
- **Files and reads:** the exact scan scope and byte-level coverage for each probe pass.
- **Findings:** evidence, source locations, duplicate links, validation, reachability, and severity.
- **Activity:** comments, review decisions, assessments, and scan events.

This makes interrupted scans resumable and keeps team decisions next to the evidence. It also lets you compare past runs and see which parts of a system received real review.

## Install

OpenSec needs Node.js 22.19+, Docker Engine 28+, and macOS or Linux. Use WSL2 on Windows.

```sh
npm install --global @cecuro/open-security
opensec --version
```

OpenSec uses provider keys already in your environment or the credentials stored by `pi`.

```sh
opensec env
opensec models
opensec scan /path/to/repository --model provider/model
opensec review
```

Run `opensec scan . --estimate` to estimate a scan without calling a model. Run `opensec --help` for scan limits, cost controls, diff scans, exports, and CI options.

## Use it with your team

The local review UI turns scan output into shared work. A team can:

- Review runs and filter findings by run, repository, severity, or state.
- Confirm, suppress, follow up, or comment on a finding.
- Inspect the threat model, evidence, source locations, cost, and coverage.
- Export JSON, CSV, SARIF, or a read-only HTML snapshot.
- Resume interrupted scans and set CI severity thresholds.

![Run overview](docs/screenshots/runs.jpg)

![Finding review](docs/screenshots/findings.jpg)

Review data stays in `~/.opensec/opensec.db`. Exports can contain sensitive code-review data, so inspect them before sharing.

OpenSec is local today. If there is enough interest, we plan to release a hosted version for teams. [Let us know](https://github.com/Cecuro/open-security/issues).

## Develop

```sh
git clone https://github.com/Cecuro/open-security.git
cd open-security
npm ci
npm run release:check
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Report security flaws through [SECURITY.md](SECURITY.md), not a public issue.

## License

Apache-2.0. See [LICENSE](LICENSE).

Built by [Cecuro](https://cecuro.ai/).
